"""Match executable code/layout while allowing resource metadata to differ."""
import hashlib
import json
import xml.etree.ElementTree as ET
import pefile


def examine(data):
    if len(data) > 128 * 1024 * 1024:
        raise ValueError('目标文件大小超出此助手的检查范围。')
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as error:
        raise ValueError('目标不是有效的 PE 程序。') from error
    try:
        if pe.FILE_HEADER.Machine != 0x14c or pe.OPTIONAL_HEADER.Magic != 0x10b:
            raise ValueError('目标不是预期的 x86 PE 程序。')
        if not 1 <= len(pe.sections) <= 96:
            raise ValueError('PE 节表数量异常。')
        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(dirs) < 16:
            raise ValueError('PE 数据目录不完整。')
        resource = dirs[2]
        resource_sections = [s for s in pe.sections
                             if s.VirtualAddress <= resource.VirtualAddress
                             and resource.VirtualAddress + resource.Size <= s.VirtualAddress + s.Misc_VirtualSize]
        if not resource.Size or len(resource_sections) != 1 or resource_sections[0].Characteristics & 0x20000000:
            raise ValueError('资源区布局与支持的程序结构不符。')
        resource_section = resource_sections[0]
        sections = []
        end_of_sections = 0
        for section in pe.sections:
            offset, size = section.PointerToRawData, section.SizeOfRawData
            if size and (offset < pe.OPTIONAL_HEADER.SizeOfHeaders or offset + size > len(data)):
                raise ValueError('PE 节数据范围异常。')
            end_of_sections = max(end_of_sections, offset + size)
            record = {'rva': section.VirtualAddress, 'virtual_size': section.Misc_VirtualSize,
                      'characteristics': section.Characteristics}
            if section is resource_section:
                record['resource_metadata'] = True
            else:
                record.update(raw_size=size, sha256=hashlib.sha256(data[offset:offset+size]).hexdigest())
            sections.append(record)
        overlay = data[end_of_sections:]
        security = dirs[4]
        if security.Size:
            start, end = security.VirtualAddress, security.VirtualAddress + security.Size
            if start < end_of_sections or end > len(data):
                raise ValueError('证书表范围异常。')
            overlay = data[end_of_sections:start] + data[end:]
        profile = {'machine': pe.FILE_HEADER.Machine, 'characteristics': pe.FILE_HEADER.Characteristics,
                   'optional': {name: getattr(pe.OPTIONAL_HEADER, name) for name in (
                       'Magic', 'AddressOfEntryPoint', 'ImageBase', 'SectionAlignment', 'FileAlignment',
                       'SizeOfImage', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve',
                       'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags')},
                   'directories': [(index, directory.VirtualAddress, directory.Size)
                                   for index, directory in enumerate(dirs) if index not in (2, 4)],
                   'sections': sections, 'overlay_sha256': hashlib.sha256(overlay).hexdigest()}
        fingerprint = hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        levels = []
        def walk(entry, depth=0):
            if depth > 3:
                raise ValueError('manifest 资源层级异常。')
            if hasattr(entry, 'directory'):
                for child in entry.directory.entries:
                    walk(child, depth+1)
            elif hasattr(entry, 'data'):
                value = entry.data.struct
                if not 0 < value.Size <= 1024 * 1024:
                    raise ValueError('manifest 大小异常。')
                xml = pe.get_data(value.OffsetToData, value.Size)
                try:
                    root = ET.fromstring(xml)
                except ET.ParseError as error:
                    raise ValueError('程序权限声明格式异常。') from error
                for element in root.iter():
                    if element.tag.rsplit('}', 1)[-1] == 'requestedExecutionLevel':
                        level = element.attrib.get('level', '')
                        if level not in ('asInvoker', 'highestAvailable', 'requireAdministrator'):
                            raise ValueError('程序权限声明值异常。')
                        levels.append(level)
        for entry in getattr(getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None), 'entries', []):
            if entry.id == 24:
                walk(entry)
        level = ('requireAdministrator' if 'requireAdministrator' in levels else
                 'highestAvailable' if 'highestAvailable' in levels else 'asInvoker')
        return {'code_layout_sha256': fingerprint, 'execution_level': level, 'profile': profile}
    finally:
        pe.close()
