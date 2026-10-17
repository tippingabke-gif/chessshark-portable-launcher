"""Change one newly located startup flag, retaining its original bytes."""
import argparse
import ctypes as C
import json
from pathlib import Path
import struct
import sys
from inspect_live_objects import Target,K
import native_message_probe

ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--pid',type=int,required=True)
ap.add_argument('--out',type=Path,required=True)
ap.add_argument('--value',type=int,default=1)
ap.add_argument('--restore',type=Path)
a=ap.parse_args()
assert not a.out.exists()
t=Target(a.pid,0x1038)
try:
    main=t.u32(t.at(0x11dd744))
    assert t.u32(main)==t.at(0x1119a00)
    at=main+0xb48
    old=t.read(at,4)
    data=struct.pack('<I',a.value)
    if a.restore:
        previous=json.loads(a.restore.read_text(encoding='utf-8'))
        assert previous['pid']==a.pid and previous['address']==hex(at)
        assert old.hex()==previous['new']
        data=bytes.fromhex(previous['original'])
    out={'pid':a.pid,'base':hex(t.base),'main':hex(main),'address':hex(at),'original':old.hex(),'new':data.hex(),
         'reason':'startup continuation reads main+0xB48 before selecting cleanup; new process-local hypothesis',
         'rollback':'use --restore with this record, or exit the process'}
    a.out.write_text(json.dumps(out,indent=2),encoding='utf-8')
    buf=C.create_string_buffer(data);count=C.c_size_t()
    assert K.WriteProcessMemory(t.h,C.c_void_p(at),buf,4,C.byref(count)) and count.value==4
    out['observed']=t.read(at,4).hex()
    a.out.write_text(json.dumps(out,indent=2),encoding='utf-8')
    print(json.dumps(out))
finally:t.close()
