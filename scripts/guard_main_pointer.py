"""One-shot process-local repair of the newly observed startup pointer write."""
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import struct
import sys

from keystone import Ks,KS_ARCH_X86,KS_MODE_32
from inspect_live_objects import Target
import watch_main_destructor
import run_external_hwtrace as hw
K=hw.K


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid',type=int,required=True)
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--read',type=Path)
    a=ap.parse_args()
    assert not a.out.exists()
    t=Target(a.pid,0x143a)
    try:
        if a.read:
            previous=json.loads(a.read.read_text(encoding='utf-8'))
            assert previous['pid']==a.pid
            log=int(previous['log'],16)
            words=struct.unpack('<6I',t.read(log,24))
            out={'pid':a.pid,'source':str(a.read),'hits':words[0],'repairs':words[1],
                 'before':hex(words[2]),'after':hex(words[3]),'eip':hex(words[4]),
                 'global_main':hex(t.u32(int(previous['slot'],16))),'repair_eip':hex(words[5])}
        else:
            app=t.u32(t.at(0x11e55d8))
            actual=t.u32(app+0x58)
            slot=t.at(0x11dd744)
            assert actual==t.u32(slot) and t.u32(actual)==t.at(0x1119a00)
            if t.identity['profile_id']=='v253':
                assert t.read(t.at(0x1732d49)-2,2)==bytes.fromhex('890a')
            code=K.VirtualAllocEx(t.h,None,0x2000,0x3000,0x40)
            assert code
            log=code+0x1000
            asm=Ks(KS_ARCH_X86,KS_MODE_32)
            source=f'''
                pushad
                mov eax, dword ptr [esp+36]
                mov edx, dword ptr [eax]
                cmp dword ptr [edx], 0x80000004
                jne ignore
                mov edx, dword ptr [eax+4]
                test dword ptr [edx+0x14], 1
                jz ignore
                inc dword ptr [{log}]
                mov eax, dword ptr [{slot}]
                mov dword ptr [{log+8}], eax
                mov eax, dword ptr [edx+0xb8]
                mov dword ptr [{log+16}], eax
                cmp eax, {t.at(0x1732d49)}
                jne handled
                cmp dword ptr [edx+0xa8], {slot}
                jne handled
                cmp dword ptr [{slot}], {actual-0x64}
                jne handled
                mov eax, dword ptr [edx+0xb8]
                mov dword ptr [{log+20}], eax
                mov dword ptr [{slot}], {actual}
                mov dword ptr [edx+0xac], {actual}
                mov dword ptr [{log+12}], {actual}
                inc dword ptr [{log+4}]
                and dword ptr [edx+0x18], 0xfff0fffc
            handled:
                mov dword ptr [edx+0x14], 0
                mov dword ptr [esp+28], 0xffffffff
                popad
                ret 4
            ignore:
                mov dword ptr [esp+28], 0
                popad
                ret 4
            '''
            body=bytes(asm.asm(source,addr=code)[0])
            assert hw.remote_write(t.h,code,body)
            stub=hw.build_register_stub(code,code,hw.resolve_x86_export(a.pid,'AddVectoredExceptionHandler'))
            assert hw.remote_write(t.h,code+0x800,stub)
            thread=K.CreateRemoteThread(t.h,None,0,C.c_void_p(code+0x800),None,0,None)
            assert thread and K.WaitForSingleObject(thread,5000)==0
            veh=W.DWORD()
            K.GetExitCodeThread(thread,C.byref(veh));K.CloseHandle(thread)
            assert veh.value
            out={'pid':a.pid,'base':hex(t.base),'slot':hex(slot),'actual_main':hex(actual),
                 'expected_bad_value':hex(actual-0x64),'expected_eip':hex(t.at(0x1732d49)),
                 'handler':hex(code),'veh':hex(veh.value),'log':hex(log),'threads':[],
                 'condition':'Exact profile EIP, EDX == main global, written value == actual_main - 0x64',
                 'lifetime':'one matching repair clears this breakpoint; handler allocation lasts until process exit'}
            a.out.write_text(json.dumps(out,indent=2),encoding='utf-8')
            for tid in hw.gui_threads(a.pid):
                thread=hw.open_thread(tid)
                assert thread and K.SuspendThread(thread)!=0xffffffff
                try:
                    context=hw.WOW64_CONTEXT();context.ContextFlags=hw.WOW64_CONTEXT_DEBUG_REGISTERS
                    assert K.Wow64GetThreadContext(thread,C.byref(context)) and context.Dr7&0xff==0
                    context.Dr0=slot;context.Dr1=0;context.Dr2=0;context.Dr3=0
                    context.Dr6=0;context.Dr7=0xd0001
                    assert K.Wow64SetThreadContext(thread,C.byref(context))
                    out['threads'].append(tid)
                finally:
                    K.ResumeThread(thread);K.CloseHandle(thread)
            assert out['threads']
            out['installed']=True
        a.out.write_text(json.dumps(out,indent=2),encoding='utf-8')
        print(json.dumps(out))
    finally:t.close()


if __name__=='__main__':main()
