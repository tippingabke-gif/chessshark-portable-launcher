"""Compose the established startup chain and repair scan constants before use.

Default: back up configuration and write a concrete launch plan. --start starts
one new instance only if no process with the exact target path is running.
Existing ChessShark processes are never closed by this script.
"""
import argparse
import os
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import psutil

ROOT=Path(os.environ['CHESSSHARK_WORKSPACE'])
PRIOR=Path(__file__).resolve().parent
UI=PRIOR/'chessshark_ui_helper_nofallback.py'
TARGET=Path(os.environ['CHESSSHARK_TARGET'])
from portable_support import validate_target
from inspect_live_objects import Target


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--start',action='store_true')
    a=ap.parse_args()
    identity=validate_target(TARGET)
    stamp=datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    run=ROOT/'work'/('clean_scan_launch_'+stamp);run.mkdir(parents=True)
    backup=run/'configuration_before';backup.mkdir()
    state={'target':str(TARGET),'run_directory':str(run),'started':False,'configuration_backup':{},'steps':[],'target_identity':identity}
    def save():
        (run/'result.json').write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding='utf-8')
    for name in ['Config.ini','Connect.dat','ConnectUser.dat','Layout.xml']:
        src=TARGET.parent/name
        if not src.is_file():
            state.setdefault('configuration_absent',[]).append(name)
            continue
        shutil.copy2(src,backup/name)
        state['configuration_backup'][name]=hashlib.sha256(src.read_bytes()).hexdigest()
    scripts=[PRIOR/'guard_late_failure.py',UI,PRIOR/'set_startup_gate.py',
             PRIOR/'guard_main_pointer.py',PRIOR/'native_message_probe.py',PRIOR/'repair_scan_parameters.py']
    assert TARGET.is_file() and all(p.is_file() for p in scripts)
    state['steps']=[str(s) for s in scripts]
    state['runtime_repair']={'table':'TFormRegist.+0x40C','first_dword':100,'second_dword':2,
                             'timing':'After native initialization, before allowing the first scan'}
    state['instruction']='Wait for READY before any connection or engine operation.'
    save()
    print(json.dumps({'prepared':True,'plan':str(run/'result.json'),'backup':str(backup)}),flush=True)
    if not a.start:return
    existing=[]
    for p in psutil.process_iter(['pid','name','exe']):
        if p.info['name'] and p.info['name'].lower()=='chessshark.exe':
            if p.info['exe'] and Path(p.info['exe']).resolve()==TARGET.resolve():existing.append(p.pid)
    if existing:
        state['blocked_by_existing_pids']=existing;save()
        raise RuntimeError('Existing target preserved. Close its window before --start: '+str(existing))
    process=subprocess.Popen([str(TARGET)],cwd=TARGET.parent)
    state.update(pid=process.pid,process_create_time=psutil.Process(process.pid).create_time(),started=True);save()
    print('STARTING '+str(process.pid)+'; wait for READY.',flush=True)
    try:
        deadline=time.monotonic()+30
        while True:
            if process.poll() is not None:raise RuntimeError('Target exited during startup')
            ready=False
            try:
                t=Target(process.pid)
                try:
                    ready=(t.u32(t.at(0x11bac74)-0x14)==t.at(0xd97b24)
                           and t.u32(t.at(0x11dd744))!=0)
                finally:t.close()
            except (OSError,AssertionError):pass
            if ready:break
            if time.monotonic()>deadline:raise RuntimeError('Native startup readiness timeout')
            time.sleep(.1)
        def step(label,script,*args,timeout=25):
            command=([sys.executable,'--worker',script.name] if getattr(sys,'frozen',False) else [sys.executable,os.environ['CHESSSHARK_ENTRY'],'--worker',script.name])+['--pid',str(process.pid),*map(str,args)]
            with (run/(label+'.console.txt')).open('w',encoding='utf-8') as log:
                completed=subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,
                                         timeout=timeout,creationflags=subprocess.CREATE_NO_WINDOW)
            state.setdefault('completed_steps',[]).append({'name':label,'exit_code':completed.returncode});save()
            if completed.returncode:raise RuntimeError(label+' failed; target preserved, see '+str(run))
            print(label+' complete',flush=True)
        step('failure_guard',scripts[0],'--out',run/'failure_guard.json','--before-completion')
        step('agreement_and_update',UI,'--target-exe',TARGET,'--seconds','4','--poll-ms','100',
             '--log',run/'ui.jsonl','--accept-agreement','--update-action','defer',
             '--registration-action','none','--login-action','probe','--messagebox-action','none')
        step('startup_gate',scripts[2],'--out',run/'startup_gate.json')
        step('main_pointer_guard',scripts[3],'--out',run/'main_pointer_guard.json')
        step('native_completion',scripts[4],'--out',run/'native_completion.json','--inject','--bind-request')
        step('scan_parameters',scripts[5],'--out',run/'scan_parameters.json')
        t=Target(process.pid)
        try:
            reg=t.u32(t.at(0x11de424));main=t.u32(t.at(0x11dd744));con=t.u32(t.at(0x11dd7dc))
            assert t.read(t.u32(reg+0x40c),8).hex()=='6400000002000000'
            assert t.read(main+0x69,1)==b'\x01'
            assert t.read(con+0x594,1)==b'\0'
            state['ready']={'main':hex(main),'parameters':[100,2],'scan_active':False}
        finally:t.close()
        save();print('READY '+str(process.pid)+'; evidence '+str(run),flush=True)
        return state
    except Exception as error:
        state['error']=repr(error);save();raise


if __name__=='__main__':main()
