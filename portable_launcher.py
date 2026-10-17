"""Self-contained, exact-build ChessShark portable startup assistant."""
import argparse
from contextlib import redirect_stdout
import ctypes
import hashlib
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import time
from release_presentation import public_result, public_error
import psutil
import win32gui
import win32con

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent
ASSETS = Path(getattr(sys, '_MEIPASS', BASE/'bundle'))
SCRIPTS = ASSETS/'scripts'
sys.path.insert(0, str(SCRIPTS))
from portable_support import (dump_json, validate_target, find_target, data_root,
                              target_key, TargetLock, ensure_platform,
                              requires_elevation, relaunch_elevated)
APP_DIR = Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else BASE
WORKERS = {'guard_late_failure.py', 'chessshark_ui_helper_nofallback.py', 'set_startup_gate.py',
           'guard_main_pointer.py', 'native_message_probe.py', 'repair_scan_parameters.py'}
LOG_ROOT = None
OUT_PATH = None
PUBLIC_REPORT = None


def verify_bundle():
    manifest = json.loads((ASSETS/'bundle_manifest.json').read_text(encoding='utf-8'))
    for name, digest in manifest['files'].items():
        if hashlib.sha256((SCRIPTS/name).read_bytes()).hexdigest() != digest:
            raise RuntimeError('内嵌文件校验失败：' + name)
    return manifest


def worker_command(name, *args):
    command = ([sys.executable, '--worker', name] if getattr(sys, 'frozen', False)
               else [sys.executable, str(Path(__file__).resolve()), '--worker', name])
    return command + list(args)


def existing_processes(target):
    result = []
    for process in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if (process.info['name'] or '').lower() == 'chessshark.exe':
                path = process.info['exe']
                if path and Path(path).resolve() == target.resolve():
                    result.append(process)
                elif not path:
                    raise RuntimeError('现有 ChessShark 进程的路径不可读。请以与它相同的权限运行助手。')
        except psutil.NoSuchProcess:
            continue
    return result


def reuse(target, root, supplied_record=None):
    processes = existing_processes(target)
    if not processes:
        return None
    if len(processes) != 1:
        raise RuntimeError('此目录已有多个软件实例，均已保留。请保存棋局并整理窗口后再运行。')
    process = processes[0]
    records = list((root/'work').glob('clean_scan_launch_*/result.json'))
    if supplied_record:
        records.insert(0, supplied_record)
    trusted = None
    trusted_state = None
    expected_steps = ['failure_guard', 'agreement_and_update', 'startup_gate',
                      'main_pointer_guard', 'native_completion', 'scan_parameters']
    for record in records:
        try:
            prior = json.loads(record.read_text(encoding='utf-8-sig'))
            completed = prior.get('completed_steps', [])
            complete_chain = (len(completed) == 6 and
                              [step.get('name') for step in completed] == expected_steps and
                              all(step.get('exit_code') == 0 for step in completed))
            if (complete_chain and prior.get('pid') == process.pid and prior.get('ready')
                    and prior.get('process_create_time') == process.create_time()
                    and Path(prior['target']).resolve() == target.resolve()):
                trusted = record
                trusted_state = prior
                break
        except (OSError, ValueError, KeyError):
            continue
    if trusted is None:
        raise RuntimeError('已有窗口缺少本助手的完整启动记录，已原样保留。请保存棋局并自行关闭该窗口，再运行助手。')
    from inspect_live_objects import Target
    t = Target(process.pid)
    try:
        main_obj = t.u32(t.at(0x11dd744))
        reg = t.u32(t.at(0x11de424))
        if t.obj(main_obj)['class'] != 'TForm1' or t.obj(reg)['class'] != 'TFormRegist':
            raise RuntimeError('现有窗口状态与记录不符，已保留。')
        params = struct.unpack('<II', t.read(t.u32(reg+0x40c), 8))
        if params != (100, 2):
            raise RuntimeError('现有窗口的参数与完成记录不符，已保留。')
        hwnd = t.u32(main_obj+0x290)
        if win32gui.IsWindow(hwnd):
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE if win32gui.IsIconic(hwnd) else win32con.SW_SHOW)
        if supplied_record and trusted == supplied_record:
            imported = root/'work'/('clean_scan_launch_import_' + str(process.pid))/'result.json'
            dump_json(imported, trusted_state)
            trusted = imported
        return {'status': 'reused_existing_ready_process', 'pid': process.pid, 'parameters': list(params),
                'ready_record': str(trusted), 'no_new_target_started': True, 'no_memory_writes': True}
    finally:
        t.close()


def main():
    global LOG_ROOT, OUT_PATH, PUBLIC_REPORT
    if len(sys.argv) > 2 and sys.argv[1] == '--worker':
        name = sys.argv[2]
        if name not in WORKERS:
            raise ValueError('Unknown worker')
        verify_bundle()
        sys.argv = [str(SCRIPTS/name), *sys.argv[3:]]
        runpy.run_path(str(SCRIPTS/name), run_name='__main__')
        return
    ap = argparse.ArgumentParser(description='ChessShark 便携启动修复；Windows x64 / 已验证构建')
    ap.add_argument('target_path', nargs='?', type=Path, help='可将 ChessShark.exe 拖到助手上')
    ap.add_argument('--target', type=Path)
    ap.add_argument('--select', action='store_true', help='重新选择软件位置')
    ap.add_argument('--elevated-retry', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--diagnose', action='store_true', help='只检查内嵌运行时和工作入口')
    ap.add_argument('--check', action='store_true', help='只检查所选文件，不启动或修改软件')
    ap.add_argument('--data-dir', type=Path, help='指定日志、备份与助手设置目录')
    ap.add_argument('--ready-record', type=Path, help='导入同一现存实例的既有完成记录')
    ap.add_argument('--out', type=Path, help='保存本机诊断记录（含当前软件路径）')
    ap.add_argument('--export-report', type=Path, help='导出可分享的简要状态，不包含路径或原始日志')
    ap.add_argument('--no-dialog', action='store_true', help='错误写到日志和控制台，不显示消息框')
    args = ap.parse_args()
    OUT_PATH = args.out
    PUBLIC_REPORT = args.export_report
    platform_info = ensure_platform()
    manifest = verify_bundle()
    if args.diagnose:
        from keystone import Ks, KS_ARCH_X86, KS_MODE_32
        if Ks(KS_ARCH_X86, KS_MODE_32).asm('nop')[0] != [0x90]:
            raise RuntimeError('Keystone self-check failed')
        checks = []
        env = os.environ.copy()
        env['PYTHONUTF8'] = '1'
        for name in sorted(WORKERS):
            result = subprocess.run(worker_command(name, '--help'), stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=40, env=env,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            checks.append({'worker': name, 'exit_code': result.returncode,
                           'output': result.stdout.decode('utf-8', errors='replace')})
            if result.returncode:
                raise RuntimeError(str(checks[-1]))
        result = {'diagnostic': 'passed', 'bundled_files': len(manifest['files']),
                  'standalone_runtime': bool(getattr(sys, 'frozen', False)), 'worker_checks': checks,
                  'target_was_modified': False, 'external_python_required': False, 'platform': platform_info}
    else:
        LOG_ROOT = data_root(APP_DIR, args.data_dir)
        settings_file = LOG_ROOT/'settings.json'
        try:
            settings = json.loads(settings_file.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            settings = {}
        explicit = args.target or args.target_path
        if args.no_dialog and not explicit and not args.diagnose:
            raise ValueError('--no-dialog 运行时请用 --target 指定目标。')
        selected = find_target(explicit, APP_DIR, settings.get('target'), args.select)
        if selected is None:
            print('已取消选择，软件未启动。')
            return
        identity = validate_target(selected)
        target = Path(identity['path'])
        if args.check:
            result = {'status': 'compatible', 'target': identity, 'target_was_modified': False,
                      'new_target_started': False}
        else:
            if requires_elevation(identity):
                if args.elevated_retry:
                    raise RuntimeError('管理员启动仍未获得相应权限，请检查 Windows 提示。')
                command = ([sys.executable] if getattr(sys, 'frozen', False)
                           else [sys.executable, str(Path(__file__).resolve())])
                command += ['--target', str(target), '--data-dir', str(LOG_ROOT), '--elevated-retry']
                if args.out:
                    command += ['--out', str(args.out.resolve())]
                if args.ready_record:
                    command += ['--ready-record', str(args.ready_record.resolve())]
                if args.export_report:
                    command += ['--export-report', str(args.export_report.resolve())]
                if args.no_dialog:
                    command += ['--no-dialog']
                print('原版软件要求管理员权限，等待 Windows 权限确认…', flush=True)
                raise SystemExit(relaunch_elevated(command, target.parent))
            dump_json(settings_file, {'target': str(target)})
            root = LOG_ROOT/'targets'/target_key(target)
            (root/'work').mkdir(parents=True, exist_ok=True)
            os.environ['CHESSSHARK_WORKSPACE'] = str(root)
            os.environ['CHESSSHARK_TARGET'] = str(target)
            os.environ['CHESSSHARK_ENTRY'] = str(Path(__file__).resolve())
            os.environ['PYTHONUTF8'] = '1'
            with TargetLock(target):
                result = reuse(target, root, args.ready_record)
                if result is None:
                    print('正在启动，请等待出现 READY 后再选择引擎或开始连线。', flush=True)
                    from launch_chessshark_with_scan_fix import main as launch
                    prior_argv = sys.argv
                    try:
                        sys.argv = ['launch_chessshark_with_scan_fix.py', '--start']
                        with (root/'launch.console.txt').open('w', encoding='utf-8') as local_log:
                            with redirect_stdout(local_log):
                                result = launch()
                    finally:
                        sys.argv = prior_argv
                dump_json(root/'last_run.json', result)
            print('已就绪。', flush=True)
    if args.out:
        dump_json(args.out, result)
    public = public_result(result)
    if PUBLIC_REPORT:
        dump_json(PUBLIC_REPORT, public)
    print(json.dumps(public, ensure_ascii=True))


if __name__ == '__main__':
    if getattr(sys, 'frozen', False) and '--worker' not in sys.argv:
        ctypes.windll.kernel32.SetConsoleTitleW('ChessShark 便携启动助手')
    try:
        main()
    except Exception as error:
        record = {'status': 'failed', 'error': str(error), 'time': time.strftime('%Y-%m-%d %H:%M:%S')}
        log = None
        if '--worker' not in sys.argv:
            try:
                if OUT_PATH:
                    dump_json(OUT_PATH, record)
                if LOG_ROOT:
                    log = LOG_ROOT/'last_error.json'
                    dump_json(log, record)
            except OSError:
                pass
            if not any(flag in sys.argv for flag in ('--diagnose', '--check', '--no-dialog')):
                public = public_error(error)
                ctypes.windll.user32.MessageBoxW(None, public['message'] + '\n错误代码：' + public['code'],
                                                'ChessShark 便携启动助手', 0x10)
        if '--worker' in sys.argv:
            print(json.dumps(record, ensure_ascii=True), file=sys.stderr)
        else:
            public = public_error(error)
            if PUBLIC_REPORT:
                try:
                    dump_json(PUBLIC_REPORT, public)
                except OSError:
                    pass
            print(json.dumps(public, ensure_ascii=True), file=sys.stderr)
        sys.exit(1)
