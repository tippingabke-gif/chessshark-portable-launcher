"""Read window thunks and known Delphi object slots without instrumentation."""
from portable_support import selected_process
from version_profiles import relocate
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import sys
import time
import win32gui
import win32process
import capture_ui_frontier as cap

K=cap.capture.K
U=C.WinDLL('user32',use_last_error=True)
U.GetWindowLongPtrW.argtypes=[W.HWND,C.c_int]
U.GetWindowLongPtrW.restype=C.c_size_t

class Target:
    def __init__(self,pid,access=0x1010):
        self.pid=pid
        self.h=K.OpenProcess(access,False,pid)
        if not self.h:raise C.WinError(C.get_last_error())
        buf=C.create_unicode_buffer(32768);n=W.DWORD(len(buf))
        if not K.QueryFullProcessImageNameW(self.h,0,buf,C.byref(n)):raise C.WinError(C.get_last_error())
        self.path=Path(buf.value)
        self.identity=selected_process(self.path)
        snap=K.CreateToolhelp32Snapshot(0x18,pid)
        try:
            ent=cap.capture.MODULEENTRY32W();ent.dwSize=C.sizeof(ent)
            ok=K.Module32FirstW(snap,C.byref(ent));self.base=None
            while ok:
                if Path(ent.szExePath).resolve()==self.path.resolve():self.base=ent.modBaseAddr;self.size=ent.modBaseSize;break
                ok=K.Module32NextW(snap,C.byref(ent))
            assert self.base
        finally:K.CloseHandle(snap)
    def close(self):K.CloseHandle(self.h)
    def at(self,old):return relocate(self.base,old,self.identity['profile_id'])
    def read(self,at,size):
        assert 0x10000<=at<0x100000000 and 0<size<=0x1000000
        buf=C.create_string_buffer(size);got=C.c_size_t()
        if not K.ReadProcessMemory(self.h,C.c_void_p(at),buf,size,C.byref(got)) or got.value!=size:raise C.WinError(C.get_last_error())
        return buf.raw
    def u32(self,at):return int.from_bytes(self.read(at,4),'little')
    def obj(self,at):
        row={'pointer':hex(at)}
        try:
            vmt=self.u32(at);row['vmt']=hex(vmt)
            row['prefix']=self.read(at,0x80).hex()
            name=self.u32(vmt-0x38);length=self.read(name,1)[0]
            row['class']=self.read(name+1,length).decode('ascii')
            size=self.u32(vmt-0x34);row['size']=size
            if 0<size<0x10000:
                row['data']=self.read(at,size).hex()
        except Exception as e:row['error']=repr(e)
        return row
    def snapshot(self):
        result={'pid':self.pid,'base':hex(self.base),'time_ms':int(time.time()*1000),'objects':{},'windows':[]}
        for label,slot in [('registration',0x11de424),('main',0x11dd744),('comparison',0x11dd79c),('login',0x11de3dc),('application',0x11e55d8)]:
            result['objects'][label]=self.obj(self.u32(self.at(slot)))
        def enum(hwnd,_):
            tid,pid=win32process.GetWindowThreadProcessId(hwnd)
            if pid!=self.pid:return
            row={'hwnd':hex(hwnd),'tid':tid,'class':win32gui.GetClassName(hwnd),'title':win32gui.GetWindowText(hwnd),
                 'visible':bool(win32gui.IsWindowVisible(hwnd)),'enabled':bool(win32gui.IsWindowEnabled(hwnd))}
            try:
                proc=U.GetWindowLongPtrW(hwnd,-4);row['wndproc']=hex(proc)
                if proc:
                    raw=self.read(proc,16);row['thunk']=raw.hex()
                    if raw[0]==0xe8:
                        row['method']=hex(int.from_bytes(raw[5:9],'little'))
                        row['self']=self.obj(int.from_bytes(raw[9:13],'little'))
                props=[]
                win32gui.EnumPropsEx(hwnd,lambda h,key,value,extra: props.append({'key':key,'value':hex(value)}) or True,None)
                row['props']=props
            except Exception as e:row['error']=repr(e)
            result['windows'].append(row)
        win32gui.EnumWindows(enum,None)
        return result

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--pid',type=int,required=True);ap.add_argument('--out',type=Path,required=True)
    a=ap.parse_args();assert not a.out.exists();t=Target(a.pid)
    try:
        result=t.snapshot();a.out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        for row in result['objects'].values():row.pop('data',None);row.pop('prefix',None)
        for row in result['windows']:
            if 'self' in row:row['self'].pop('data',None);row['self'].pop('prefix',None)
        print(json.dumps(result,ensure_ascii=True,indent=2))
    finally:t.close()
