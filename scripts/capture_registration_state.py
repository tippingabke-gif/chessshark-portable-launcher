"""Read a running ChessShark instance's newly identified registration fields.

Only PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ is requested. This
script neither starts the target nor installs hooks nor writes its memory.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import time

K = C.WinDLL('kernel32', use_last_error=True)
K.OpenProcess.argtypes = [W.DWORD,W.BOOL,W.DWORD]
K.OpenProcess.restype = W.HANDLE
K.CloseHandle.argtypes = [W.HANDLE]
K.ReadProcessMemory.argtypes = [W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]
K.ReadProcessMemory.restype = W.BOOL
K.QueryFullProcessImageNameW.argtypes = [W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)]
K.QueryFullProcessImageNameW.restype = W.BOOL
K.CreateToolhelp32Snapshot.argtypes = [W.DWORD,W.DWORD]
K.CreateToolhelp32Snapshot.restype = W.HANDLE


class MODULEENTRY32W(C.Structure):
    _fields_ = [('dwSize',W.DWORD),('th32ModuleID',W.DWORD),('th32ProcessID',W.DWORD),
                ('GlblcntUsage',W.DWORD),('ProccntUsage',W.DWORD),('modBaseAddr',C.c_void_p),
                ('modBaseSize',W.DWORD),('hModule',W.HMODULE),('szModule',W.WCHAR*256),
                ('szExePath',W.WCHAR*260)]


K.Module32FirstW.argtypes = [W.HANDLE,C.POINTER(MODULEENTRY32W)]
K.Module32FirstW.restype = W.BOOL
K.Module32NextW.argtypes = [W.HANDLE,C.POINTER(MODULEENTRY32W)]
K.Module32NextW.restype = W.BOOL


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pid',type=int,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    assert not a.out.exists(),'Refusing to overwrite an existing capture'
    h=K.OpenProcess(0x1000|0x10,False,a.pid)
    if not h:raise C.WinError(C.get_last_error())
    reads=[]
    def read(addr,size,label):
        assert 0<size<=0x1000 and 0x10000<=addr<0x100000000
        buf=C.create_string_buffer(size);got=C.c_size_t()
        if not K.ReadProcessMemory(h,C.c_void_p(addr),buf,size,C.byref(got)) or got.value!=size:
            raise OSError(f'{label}: ReadProcessMemory {addr:#x}+{size:#x}, error {C.get_last_error()}')
        raw=buf.raw
        reads.append({'label':label,'address':hex(addr),'size':size,'hex':raw.hex(),
                      'sha256':hashlib.sha256(raw).hexdigest()})
        return raw
    def u32(addr,label):return int.from_bytes(read(addr,4,label),'little')
    try:
        pathbuf=C.create_unicode_buffer(32768);n=W.DWORD(len(pathbuf))
        if not K.QueryFullProcessImageNameW(h,0,pathbuf,C.byref(n)):raise C.WinError(C.get_last_error())
        path=Path(pathbuf.value)
        assert path.name.lower()=='chessshark.exe','Unexpected process image'
        snap=K.CreateToolhelp32Snapshot(0x8|0x10,a.pid)
        if snap==C.c_void_p(-1).value:raise C.WinError(C.get_last_error())
        try:
            entry=MODULEENTRY32W();entry.dwSize=C.sizeof(entry)
            ok=K.Module32FirstW(snap,C.byref(entry));base=size=None
            while ok:
                if Path(entry.szExePath).resolve()==path.resolve():base,size=entry.modBaseAddr,entry.modBaseSize;break
                ok=K.Module32NextW(snap,C.byref(entry))
            assert base is not None,'Main module was not found'
        finally:K.CloseHandle(snap)
        def at(old):return base+(old-0xc20000)
        # Match native dispatcher and its direct branch before following globals.
        prefix=read(at(0xd97b24),13,'registration_dispatch_signature').hex()
        assert prefix=='8b0a81c1fffbffff83f9057743',f'Unrecognized dispatcher: {prefix}'
        regist=u32(at(0x11de424),'registration_object_slot')
        main=u32(at(0x11dd744),'main_form_slot')
        identity=u32(at(0x11dd79c),'comparison_object_slot')
        objects={}
        for label,ptr in [('registration',regist),('main',main),('comparison',identity)]:
            objects[label]={'pointer':hex(ptr)}
            if ptr:
                vmt=u32(ptr,label+'_vmt')
                objects[label]['vmt']=hex(vmt)
                read(vmt-0x58,0x78,label+'_vmt_context')
        if main:read(main,0x1000,'main_object_prefix')
        if identity:read(identity+0xd20,0x40,'comparison_bytes_context')
        if regist:
            read(regist+0x48,8,'registration_windowproc_method')
            read(regist+0x290,4,'registration_hwnd')
            read(regist+0x408,0x2c,'registration_state_408_433')
            consumer=u32(regist+0x40c,'registration_consumer_pointer')
            if consumer:
                prefix=read(consumer,0x100,'registration_consumer_prefix')
                data,length,capacity=[int.from_bytes(prefix[i:i+4],'little') for i in (8,12,16)]
                objects['registration_consumer']={'pointer':hex(consumer),'vector_at_offset8':
                    {'data':hex(data),'length':length,'capacity':capacity}}
                if data and 0<length<=capacity<=0x100000:read(data,min(length,0x1000),'registration_consumer_vector_bytes')
        if identity:read(identity+0xd40,8,'ui_expected_comparison_bytes')
        if main:
            action=u32(main+0x6fc,'actregist_pointer')
            if action:
                objects['actregist']={'pointer':hex(action),'vmt':hex(u32(action,'actregist_vmt'))}
                read(action+0x6c,4,'actregist_caption_pointer')
                read(action+0x90,4,'actregist_image_index')
        read(at(0x11dd150),0x64,'session_and_response_globals')
        result={'classification':'read-only current-process capture; not a status-one execution or unlock',
                'pid':a.pid,'timestamp_ms':int(time.time()*1000),'process_path':str(path),
                'file_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                'base':hex(base),'module_size':size,'objects':objects,'reads':reads}
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({'output':str(a.out.resolve()),'pid':a.pid,'base':hex(base),'read_count':len(reads)}))
    finally:K.CloseHandle(h)


if __name__=='__main__':main()
