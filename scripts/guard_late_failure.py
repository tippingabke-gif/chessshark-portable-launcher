"""Ignore only a null 0x401 failure after the native completion flag is set."""
import argparse,ctypes as C,json,struct,time
from ctypes import wintypes as W
from pathlib import Path
from inspect_live_objects import Target,K
import watch_main_destructor
D=lambda x:struct.pack('<I',x)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--pid',type=int,required=True);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--restore',type=Path)
    ap.add_argument('--before-completion',action='store_true',help='hold the null failure while startup finishes its update callback')
    a=ap.parse_args();assert not a.out.exists();t=Target(a.pid,0x1038)
    slot=t.at(0x11bac74)-0x14
    def write(at,raw):
        buf=C.create_string_buffer(raw);got=C.c_size_t();assert K.WriteProcessMemory(t.h,C.c_void_p(at),buf,len(raw),C.byref(got)) and got.value==len(raw)
    def pointer(value):
        old=W.DWORD();assert K.VirtualProtectEx(t.h,C.c_void_p(slot),4,4,C.byref(old))
        try:write(slot,D(value))
        finally:
            unused=W.DWORD();K.VirtualProtectEx(t.h,C.c_void_p(slot),4,old.value,C.byref(unused))
    try:
        if a.restore:
            prev=json.loads(a.restore.read_text());assert prev['pid']==a.pid and t.u32(slot)==int(prev['region'],16)
            pointer(int(prev['original'],16));out={'pid':a.pid,'restored':True,'source':str(a.restore)}
        else:
            original=t.u32(slot);assert original==t.at(0xd97b24)
            region=K.VirtualAllocEx(t.h,None,0x1000,0x3000,0x40);assert region
            b=bytearray(b'\x9c');jumps=[]
            checks=[b'\x81\x3a'+D(0x401),b'\x83\x7a\x04\x00',b'\x83\x7a\x08\x00']
            if not a.before_completion:checks.append(b'\x80\xb8'+D(0x418)+b'\x01')
            for raw in checks:
                b.extend(raw);jumps.append(len(b)+1);b.extend(b'\x75\x00')
            b.extend(b'\xff\x05'+D(region+0x100)+b'\xc7\x42\x0c'+D(0)+b'\x9d\xc3')
            dest=len(b)
            for at in jumps:b[at]=dest-(at+1)
            b.extend(b'\x9d\xff\x25'+D(region+0x104))
            write(region,bytes(b));write(region+0x104,D(original));K.FlushInstructionCache(t.h,C.c_void_p(region),len(b));pointer(region)
            out={'pid':a.pid,'slot':hex(slot),'original':hex(original),'region':hex(region),'counter':hex(region+0x100),'code':b.hex(),
                 'condition':'message==0x401 && wparam==0 && lparam==0'+('' if a.before_completion else ' && registration.completion==1'),
                 'lifetime':'current process only; restore VMT slot using --restore, or close the process'}
        a.out.write_text(json.dumps(out,indent=2),encoding='utf-8');print(json.dumps(out))
    finally:t.close()

if __name__=='__main__':main()
