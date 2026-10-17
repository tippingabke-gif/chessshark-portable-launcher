"""A bounded native message experiment without patching application code entries."""
from portable_support import selected_process
from version_profiles import relocate
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

import capture_ui_frontier as cap
K=cap.capture.K
K.WriteProcessMemory.argtypes=[W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]
K.WriteProcessMemory.restype=W.BOOL
K.VirtualAllocEx.argtypes=[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,W.DWORD]
K.VirtualAllocEx.restype=C.c_void_p
K.VirtualFreeEx.argtypes=[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD]
K.VirtualFreeEx.restype=W.BOOL
K.CreateRemoteThread.argtypes=[W.HANDLE,C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)]
K.CreateRemoteThread.restype=W.HANDLE
K.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD]
K.GetExitCodeThread.argtypes=[W.HANDLE,C.POINTER(W.DWORD)]
U=C.WinDLL('user32',use_last_error=True)
U.PostMessageW.argtypes=[W.HWND,W.UINT,W.WPARAM,W.LPARAM]
U.PostMessageW.restype=W.BOOL


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pid',type=int,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--inject',action='store_true')
    p.add_argument('--bind-request',action='store_true',help='temporarily match recovered request-id gate to the supplied message')
    a=p.parse_args();assert not a.out.exists()
    h=K.OpenProcess(0x1000|0x10|(0x2|0x28 if a.inject else 0),False,a.pid)
    if not h:raise C.WinError(C.get_last_error())
    out={'pid':a.pid,'experiment':'native allocator and recovered 0x402 message; no application code hooks','samples':[]}
    def save():a.out.write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
    def read(at,size):
        buf=C.create_string_buffer(size);got=C.c_size_t()
        if not K.ReadProcessMemory(h,C.c_void_p(at),buf,size,C.byref(got)) or got.value!=size:raise C.WinError(C.get_last_error())
        return buf.raw
    def u32(at):return int.from_bytes(read(at,4),'little')
    def write(at,data):
        buf=C.create_string_buffer(data);got=C.c_size_t()
        if not K.WriteProcessMemory(h,C.c_void_p(at),buf,len(data),C.byref(got)) or got.value!=len(data):raise C.WinError(C.get_last_error())
    from portable_support import ProfileBackup, LEGACY_PROFILE
    profile=ProfileBackup(LEGACY_PROFILE,a.out)
    out['profile_backup']=profile.info
    region=None;gate_backup=None;gate_at=None
    try:
        pathbuf=C.create_unicode_buffer(32768);n=W.DWORD(32768)
        if not K.QueryFullProcessImageNameW(h,0,pathbuf,C.byref(n)):raise C.WinError(C.get_last_error())
        path=Path(pathbuf.value)
        identity=selected_process(path)
        snap=K.CreateToolhelp32Snapshot(0x18,a.pid)
        try:
            ent=cap.capture.MODULEENTRY32W();ent.dwSize=C.sizeof(ent)
            ok=K.Module32FirstW(snap,C.byref(ent));base=None
            while ok:
                if Path(ent.szExePath).resolve()==path.resolve():base=ent.modBaseAddr;break
                ok=K.Module32NextW(snap,C.byref(ent))
            assert base
        finally:K.CloseHandle(snap)
        at=lambda v:relocate(base,v,identity['profile_id'])
        reg,main,compare,login,app=[u32(at(v)) for v in (0x11de424,0x11dd744,0x11dd79c,0x11de3dc,0x11e55d8)]
        assert all((reg,main,compare,login,app))
        assert read(at(0xd97b24),13).hex()=='8b0a81c1fffbffff83f9057743'
        def snapshot():
            consumer=u32(reg+0x40c)
            return {'time_ms':int(time.time()*1000),'reg_state':read(reg+0x408,0x2c).hex(),
                    'main_visible':read(main+0x69,1)[0],'login_visible':read(login+0x69,1)[0],
                    'reg_visible':read(reg+0x69,1)[0],'timer_enabled':read(u32(reg+0x400)+0x50,1)[0],
                    'login_formstate':read(login+0x3e0,1).hex(),'login_modalresult':u32(login+0x2fc),
                    'application_mainform':hex(u32(app+0x58)),'comparison':read(compare+0xd38,16).hex(),
                    'actregist':hex(u32(main+0x6fc)),'consumer':read(consumer,0x54).hex() if consumer else None}
        out.update(process_path=str(path),base=hex(base),objects={k:hex(v) for k,v in [('registration',reg),('main',main),('comparison',compare),('login',login)]},before=snapshot())
        save()
        if a.inject:
            assert u32(main)==at(0x1119a00),'main TForm1 is no longer live'
            assert u32(main+0x6fc)!=0
            expected=read(compare+0xd40,8)
            payload=b'\x76'*64+bytes(v^0x23 for v in expected)
            region=K.VirtualAllocEx(h,None,0x1000,0x3000,0x40)
            if not region:raise C.WinError(C.get_last_error())
            d=lambda v:struct.pack('<I',v)
            # stdcall thread entry: preserve nonvolatile registers, use EAX-size GetMem,
            # copy payload, publish vector pointer, return success and pop thread arg.
            code=(b'\x53\x56\x57'+b'\xb8'+d(72)+b'\xb9'+d(at(0xdaeadc))+b'\xff\xd1\x89\xc3'+
                  b'\xb8'+d(12)+b'\xb9'+d(at(0xdaeadc))+b'\xff\xd1\x89\xc7'+
                  b'\x89\x1f\xc7\x47\x04'+d(72)+b'\xc7\x47\x08'+d(72)+
                  b'\x89\x3d'+d(region+0x100)+b'\x89\xdf\xbe'+d(region+0x200)+b'\xb9'+d(72)+
                  b'\xfc\xf3\xa4\xb8'+d(1)+b'\x5f\x5e\x5b\xc2\x04\x00')
            write(region,code);write(region+0x200,payload)
            out['remote_stage']={'address':hex(region),'code_hex':code.hex(),'payload_hex':payload.hex()};save()
            tid=W.DWORD();thread=K.CreateRemoteThread(h,None,0,C.c_void_p(region),None,0,C.byref(tid))
            if not thread:raise C.WinError(C.get_last_error())
            try:
                wait=K.WaitForSingleObject(thread,10000)
                out['allocator_thread_wait']=wait;save()
                if wait!=0:raise RuntimeError('native allocator thread did not return within 10 seconds')
                exitcode=W.DWORD();K.GetExitCodeThread(thread,C.byref(exitcode));out['allocator_thread_exit']=exitcode.value
            finally:K.CloseHandle(thread)
            vector=u32(region+0x100);assert vector and u32(vector+4)==72
            out['vector']=hex(vector);out['storage']=hex(u32(vector))
            assert read(u32(vector),72)==payload
            hwnd=u32(reg+0x290)
            if a.bind_request:
                gate_at=reg+0x41c;gate_backup=read(gate_at,4)
                out['request_binding']={'address':hex(gate_at),'original':gate_backup.hex(),'new':'0292e860',
                                        'formula':'(0x42776 * 0x1754 + 0x54a) & 0xffffffff'}
                write(gate_at,d(0x60e89202));save()
            ok=U.PostMessageW(hwnd,0x402,0x42776,vector)
            out['postmessage']={'hwnd':hex(hwnd),'result':bool(ok),'error':C.get_last_error() if not ok else 0};save()
            if not ok:raise C.WinError(C.get_last_error())
            print(json.dumps(out['postmessage']),flush=True)
        for delay in (0.2,1,3,5):
            time.sleep(delay);out['samples'].append(snapshot());save()
        if a.inject:
            out['vector_after']=read(vector,12).hex()
            out['storage_after']=read(int(out['storage'],16),72).hex()
        print(json.dumps(out['samples'][-1]),flush=True)
    except Exception as exc:
        out['error']=repr(exc);save();raise
    finally:
        if gate_backup is not None:
            try:
                observed=read(gate_at,4)
                out['request_binding']['observed_after']=observed.hex()
                if observed==struct.pack('<I',0x60e89202):
                    write(gate_at,gate_backup);out['request_binding']['restored']=True
            except OSError as exc:out['request_binding']['cleanup_error']=repr(exc)
        try:out['profile_backup']=profile.finish()
        except OSError as exc:out['profile_cleanup_error']=repr(exc)
        if region and out.get('allocator_thread_wait')==0:K.VirtualFreeEx(h,C.c_void_p(region),0,0x8000)
        save();K.CloseHandle(h)


if __name__=='__main__':main()
