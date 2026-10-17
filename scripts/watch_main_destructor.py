"""One-shot observation of TForm1.Destroy through its VMT data slot."""
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import struct
import time
from inspect_live_objects import Target,K
import native_message_probe

K.VirtualProtectEx.argtypes=[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,C.POINTER(W.DWORD)]
K.VirtualProtectEx.restype=W.BOOL
K.FlushInstructionCache.argtypes=[W.HANDLE,C.c_void_p,C.c_size_t]

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--pid',type=int,required=True);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--seconds',type=float,default=120)
    a=ap.parse_args();assert not a.out.exists();t=Target(a.pid,0x1038)
    d=lambda n:struct.pack('<I',n)
    def write(at,data):
        b=C.create_string_buffer(data);got=C.c_size_t()
        if not K.WriteProcessMemory(t.h,C.c_void_p(at),b,len(data),C.byref(got)) or got.value!=len(data):raise C.WinError(C.get_last_error())
    def pointer(at,value):
        prot=W.DWORD()
        if not K.VirtualProtectEx(t.h,C.c_void_p(at),4,0x04,C.byref(prot)):raise C.WinError(C.get_last_error())
        try:write(at,d(value))
        finally:
            unused=W.DWORD();K.VirtualProtectEx(t.h,C.c_void_p(at),4,prot.value,C.byref(unused))
    out={'pid':a.pid,'base':hex(t.base),'kind':'one-shot VMT destructor observer; 2-second logging pause'}
    def save():a.out.write_text(json.dumps(out,indent=2),encoding='utf-8')
    slot=t.at(0x1119a00)-4;original=t.u32(slot);assert original==t.at(0xc83c64)
    region=K.VirtualAllocEx(t.h,None,0x3000,0x3000,0x40)
    if not region:raise C.WinError(C.get_last_error())
    armed=False;hit=False
    try:
        code=(b'\x9c\x60\x89\xe6\xbf'+d(region+0x410)+b'\xb9'+d((36+1024)//4)+b'\xfc\xf3\xa5'+
              b'\xc7\x05'+d(region+0x400)+d(1)+b'\x68'+d(2000)+b'\xb8'+d(t.at(0x10fae4e))+b'\xff\xd0'+
              b'\x61\x9d\xff\x25'+d(region+0x100))
        write(region,code);write(region+0x100,d(original));K.FlushInstructionCache(t.h,C.c_void_p(region),len(code))
        out.update(slot=hex(slot),original=hex(original),region=hex(region),code=code.hex());save()
        pointer(slot,region);armed=True;print('observer armed',flush=True)
        end=time.monotonic()+a.seconds
        while time.monotonic()<end:
            if t.u32(region+0x400):
                hit=True;raw=t.read(region+0x410,36+1024)
                out['capture_hex']=raw.hex()
                words=struct.unpack('<9I',raw[:36]);out['registers']=dict(zip(('edi','esi','ebp','saved_esp','ebx','edx','ecx','eax','eflags'),[hex(x) for x in words]))
                out['return']=hex(int.from_bytes(raw[36:40],'little'))
                sp=words[3]+4
                for size in (8192,4096,2048,1024):
                    try:out['stack']={'address':hex(sp),'hex':t.read(sp,size).hex()};break
                    except OSError:pass
                out['snapshot']=t.snapshot()
                pointer(slot,original);armed=False;out['restored']=True;save()
                print(json.dumps({'hit':True,'return':out['return'],'registers':out['registers']}),flush=True)
                time.sleep(2.2)
                break
            time.sleep(0.02)
        out['hit']=hit;save()
    except Exception as exc:out['error']=repr(exc);save();raise
    finally:
        if armed:
            try:
                if t.u32(slot)==region:pointer(slot,original);out['restored']=True
            except OSError as exc:out['restore_error']=repr(exc)
        # On a hit the code returned after the fixed pause; otherwise no entry occurred.
        if not armed or out.get('restored'):K.VirtualFreeEx(t.h,C.c_void_p(region),0,0x8000)
        save();t.close()

if __name__=='__main__':main()
