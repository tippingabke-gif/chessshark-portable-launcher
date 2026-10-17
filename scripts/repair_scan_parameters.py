"""Restore two evidenced recognition constants in the current target instance.

Only the first eight bytes of TFormRegist.+0x40C are changed. The parallel
recognizer supplies constant 100.0 at historical 0xCE6438 and doubles its
sampling radius at 0xCE5D04/06. Nothing is written to a user scheme or EXE.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import struct
import sys
import time

from inspect_live_objects import Target, K

K.WriteProcessMemory.argtypes=[W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]
K.WriteProcessMemory.restype=W.BOOL
EXPECTED=struct.pack('<II',100,2)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid',type=int,required=True)
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--restore',type=Path)
    a=ap.parse_args()
    assert not a.out.exists()
    t=Target(a.pid,0x1038)
    try:
        reg=t.u32(t.at(0x11de424));connect=t.u32(t.at(0x11dd7dc))
        assert t.obj(reg)['class']=='TFormRegist'
        assert t.read(connect+0x594,1)==b'\0', 'Stop the scan and dismiss its error first'
        table=t.u32(reg+0x40c)
        assert struct.unpack('<f',t.read(t.at(0xce6438),4))[0]==100.0
        assert t.read(t.at(0xce5d04),4)==bytes.fromhex('03c903c0')
        assert t.read(t.at(0xce696d),8)==bytes.fromhex('db07d8bea4050000')
        before=t.read(table,8)
        if a.restore:
            prior=json.loads(a.restore.read_text(encoding='utf-8'))
            assert prior['pid']==a.pid and prior['base']==hex(t.base)
            assert prior['registration']==hex(reg) and prior['table']==hex(table)
            assert before.hex()==prior['after_hex']
            after=bytes.fromhex(prior['before_hex'])
        else:
            assert before in (bytes(8),EXPECTED), 'Unexpected existing values; inspect before changing'
            after=EXPECTED
        result={'pid':a.pid,'base':hex(t.base),'path':str(t.path),
                'time':time.strftime('%Y-%m-%d %H:%M:%S'),'registration':hex(reg),
                'table':hex(table),'before_hex':before.hex(),'after_hex':after.hex(),
                'before_values':list(struct.unpack('<II',before)),
                'after_values':list(struct.unpack('<II',after)),
                'scope':'Two runtime arithmetic parameters only; scheme files and executable unchanged',
                'verification':'Readback only; functional scan validation is a separate step',
                'restore_from':str(a.restore) if a.restore else None,'applied':False}
        a.out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        got=C.c_size_t();buffer=C.create_string_buffer(after)
        assert K.WriteProcessMemory(t.h,C.c_void_p(table),buffer,8,C.byref(got)) and got.value==8
        assert t.read(table,8)==after
        result['applied']=True
        a.out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps(result,ensure_ascii=True))
    finally:t.close()


if __name__=='__main__':main()
