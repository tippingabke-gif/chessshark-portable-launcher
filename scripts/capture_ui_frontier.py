"""Capture only the form and timer newly reached by the saved UI continuation."""
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import sys
import time

import capture_registration_state as capture


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pid', type=int, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--object-slot', type=lambda x:int(x,0), help='newly observed global pointer slot at historical module base')
    a = p.parse_args()
    assert not a.out.exists()
    k = capture.K
    h = k.OpenProcess(0x1000 | 0x10, False, a.pid)
    if not h:
        raise C.WinError(C.get_last_error())
    reads = []

    def read(addr, size, label):
        assert 0x10000 <= addr < 0x100000000 and 0 < size <= 0x1000
        buf, got = C.create_string_buffer(size), C.c_size_t()
        if not k.ReadProcessMemory(h, C.c_void_p(addr), buf, size, C.byref(got)) or got.value != size:
            raise C.WinError(C.get_last_error())
        raw = buf.raw
        reads.append(dict(label=label, address=hex(addr), size=size, hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest()))
        return raw

    def u32(addr, label):
        return int.from_bytes(read(addr, 4, label), 'little')

    try:
        pathbuf, n = C.create_unicode_buffer(32768), W.DWORD(32768)
        if not k.QueryFullProcessImageNameW(h, 0, pathbuf, C.byref(n)):
            raise C.WinError(C.get_last_error())
        path = Path(pathbuf.value)
        assert path.name.lower() == 'chessshark.exe'
        snap = k.CreateToolhelp32Snapshot(0x8 | 0x10, a.pid)
        assert snap != C.c_void_p(-1).value
        try:
            entry = capture.MODULEENTRY32W()
            entry.dwSize = C.sizeof(entry)
            ok, base = k.Module32FirstW(snap, C.byref(entry)), None
            while ok:
                if Path(entry.szExePath).resolve() == path.resolve():
                    base = entry.modBaseAddr
                    break
                ok = k.Module32NextW(snap, C.byref(entry))
            assert base is not None
        finally:
            k.CloseHandle(snap)
        if a.object_slot is not None:
            obj = u32(base + a.object_slot - 0xc20000, 'new_object_slot')
            vmt = u32(obj, 'new_object_vmt')
            name = u32(vmt - 0x38, 'new_object_name_pointer')
            name_len = read(name, 1, 'new_object_name_length')[0]
            class_name = read(name+1, name_len, 'new_object_name').decode('ascii')
            size = u32(vmt - 0x34, 'new_object_instance_size')
            read(obj, min(size, 0x1000), 'new_object_prefix')
            result = dict(classification='read-only current-process fields for a newly reached object', pid=a.pid,
                          timestamp_ms=int(time.time()*1000), process_path=str(path), base=hex(base),
                          historical_slot=hex(a.object_slot), object=hex(obj), vmt=hex(vmt),
                          object_class=class_name, instance_size=size, reads=reads)
            a.out.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
            print(json.dumps({k:v for k,v in result.items() if k != 'reads'}))
            return
        reg = u32(base + 0x11de424 - 0xc20000, 'registration_slot')
        raw = read(reg, 0x434, 'registration_form')
        timer = int.from_bytes(raw[0x400:0x404], 'little')
        timer_raw = read(timer, 0x54, 'registration_timer')
        vmt = int.from_bytes(timer_raw[:4], 'little')
        name = u32(vmt - 0x38, 'timer_class_name_pointer')
        name_len = read(name, 1, 'timer_class_name_length')[0]
        class_name = read(name + 1, name_len, 'timer_class_name').decode('ascii')
        assert class_name == 'TTimer'
        read(base + 0xfbe1dc - 0xc20000, 15, 'timer_setter_code')
        result = dict(classification='read-only current-process input for newly reached UI fields; separate from historical checkpoint state',
                      pid=a.pid, timestamp_ms=int(time.time()*1000), process_path=str(path), base=hex(base),
                      form=hex(reg), timer=hex(timer), timer_class=class_name,
                      timer_enabled=timer_raw[0x50], timer_hwnd=hex(int.from_bytes(timer_raw[0x44:0x48], 'little')), reads=reads)
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
        print(json.dumps({k:v for k,v in result.items() if k != 'reads'}))
    finally:
        k.CloseHandle(h)


if __name__ == '__main__':
    main()
