"""Portable paths, exact-build validation, and bounded profile preservation."""
import ctypes
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
from pe_compatibility import examine

SUPPORTED_SHA256 = '7bd71207219c8548ba1e60d09cdfb127bdddd67d3d38ee76cd0f98171202a34e'
ORIGINAL_SHA256 = 'eecbfa6ff3e6d1ab7dc28cb6c5c2c975f259f42ca3ca3414f438e359ca1f1d89'
SUPPORTED_BUILDS = {SUPPORTED_SHA256: 'asInvoker', ORIGINAL_SHA256: 'requireAdministrator',
                    'a400839f77cb4d90f4251f7e4072af36b3a787882be074d971fd3106f98b2838': 'requireAdministrator',
                    '8f41218ea962cdf678230a4a80ffcc405696fb63c7b6b1720d7744503bd0d468': 'asInvoker'}
KNOWN_PROFILE_IDS = {digest: ('v248' if digest in (SUPPORTED_SHA256, ORIGINAL_SHA256) else 'v253')
                     for digest in SUPPORTED_BUILDS}
COMPATIBLE_LAYOUT_SHA256 = 'ee454c6d13c541f077d6fd6d864ac53e15124c0d5820fa6a02d881971a287540'
V253_LAYOUT_SHA256 = 'f9d3fbe693df8f6b762118528e477755c0e1bd0a1a42420639f1013f23608864'
LAYOUT_PROFILES = {COMPATIBLE_LAYOUT_SHA256: 'v248', V253_LAYOUT_SHA256: 'v253'}
# An observed side effect of this exact build, not a required installation path.
LEGACY_PROFILE = Path('D:/qq游戏/MiniGames/QQChess/config.ini')
CONFIG_FILES = ('Config.ini', 'Connect.dat', 'ConnectUser.dat', 'Layout.xml')


def dump_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    temporary.replace(path)


def validate_target(path):
    path = Path(path).expanduser().resolve(strict=True)
    if path.name.lower() != 'chessshark.exe' or not path.is_file():
        raise ValueError('请选择完整软件目录中的 ChessShark.exe。')
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest in SUPPORTED_BUILDS:
        level = SUPPORTED_BUILDS[digest]
        match = 'known_file'
        profile_id = KNOWN_PROFILE_IDS[digest]
        layout_sha256 = COMPATIBLE_LAYOUT_SHA256 if profile_id == 'v248' else V253_LAYOUT_SHA256
    else:
        try:
            candidate = examine(data)
        except (ValueError, IndexError, AttributeError) as error:
            raise ValueError('软件构建不匹配：' + str(error)) from error
        if candidate['code_layout_sha256'] not in LAYOUT_PROFILES:
            raise ValueError('软件代码或关键布局不匹配，尚未启动或修改。版本文字、图标和权限声明已允许变化。实际 SHA-256：' + digest)
        level = candidate['execution_level']
        match = 'compatible_code_layout'
        layout_sha256 = candidate['code_layout_sha256']
        profile_id = LAYOUT_PROFILES[layout_sha256]
    return {'path': str(path), 'sha256': digest, 'bytes': len(data), 'architecture': 'x86',
            'version': 'compatible code/layout; version label is not used',
            'execution_level': level, 'match_method': match,
            'code_layout_sha256': layout_sha256, 'profile_id': profile_id}



def selected_process(path):
    selected = os.environ.get('CHESSSHARK_TARGET')
    if not selected or Path(path).resolve() != Path(selected).resolve():
        raise ValueError('目标进程与本次选择的软件路径不符。')
    return validate_target(path)


def choose_file():
    class OPENFILENAMEW(ctypes.Structure):
        _fields_ = [('lStructSize', W.DWORD), ('hwndOwner', W.HWND), ('hInstance', W.HINSTANCE),
                    ('lpstrFilter', W.LPCWSTR), ('lpstrCustomFilter', W.LPWSTR), ('nMaxCustFilter', W.DWORD),
                    ('nFilterIndex', W.DWORD), ('lpstrFile', W.LPWSTR), ('nMaxFile', W.DWORD),
                    ('lpstrFileTitle', W.LPWSTR), ('nMaxFileTitle', W.DWORD), ('lpstrInitialDir', W.LPCWSTR),
                    ('lpstrTitle', W.LPCWSTR), ('Flags', W.DWORD), ('nFileOffset', W.WORD),
                    ('nFileExtension', W.WORD), ('lpstrDefExt', W.LPCWSTR), ('lCustData', W.LPARAM),
                    ('lpfnHook', ctypes.c_void_p), ('lpTemplateName', W.LPCWSTR), ('pvReserved', ctypes.c_void_p),
                    ('dwReserved', W.DWORD), ('FlagsEx', W.DWORD)]
    buffer = ctypes.create_unicode_buffer(32768)
    dialog = OPENFILENAMEW()
    dialog.lStructSize = ctypes.sizeof(dialog)
    dialog.lpstrFilter = 'ChessShark.exe\0ChessShark.exe\0程序 (*.exe)\0*.exe\0\0'
    dialog.lpstrFile = ctypes.cast(buffer, W.LPWSTR)
    dialog.nMaxFile = len(buffer)
    dialog.lpstrTitle = '选择鲨鱼象棋 ChessShark.exe（保留完整软件目录）'
    dialog.Flags = 0x1000 | 0x800 | 0x80000 | 0x8  # must exist, explorer, no cwd change
    library = ctypes.WinDLL('comdlg32', use_last_error=True)
    library.GetOpenFileNameW.argtypes = [ctypes.POINTER(OPENFILENAMEW)]
    library.GetOpenFileNameW.restype = W.BOOL
    if library.GetOpenFileNameW(ctypes.byref(dialog)):
        return Path(buffer.value)
    error = library.CommDlgExtendedError()
    if error:
        raise OSError('选择文件窗口失败：' + hex(error))
    return None


def find_target(explicit, app_dir, saved, force_select=False):
    if explicit:
        return Path(explicit)
    if force_select:
        return choose_file()
    for candidate in (app_dir/'ChessShark.exe', app_dir/'ChessShark'/'ChessShark.exe'):
        if candidate.is_file():
            return candidate
    if saved and Path(saved).is_file():
        return Path(saved)
    return choose_file()


def data_root(app_dir, override=None):
    if override:
        candidates = [Path(override)]
    else:
        candidates = [app_dir/'ChessShark助手数据']
        local = os.environ.get('LOCALAPPDATA')
        if local:
            candidates.append(Path(local)/'ChessSharkPortableLauncher')
    last = None
    for path in candidates:
        try:
            path.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryFile(dir=path):
                pass
            return path.resolve()
        except OSError as error:
            last = error
    raise OSError('日志目录不可写。请用 --data-dir 指定可写目录。') from last


def target_key(target):
    return hashlib.sha256(os.path.normcase(str(Path(target).resolve())).encode('utf-8')).hexdigest()[:24]


class TargetLock:
    """One startup per selected path, including independent launcher copies."""
    def __init__(self, path):
        self.path = path
        self.handle = None

    def __enter__(self):
        k = ctypes.WinDLL('kernel32', use_last_error=True)
        k.CreateMutexW.argtypes = [ctypes.c_void_p, W.BOOL, W.LPCWSTR]
        k.CreateMutexW.restype = W.HANDLE
        self.handle = k.CreateMutexW(None, False, 'Local\\ChessSharkPortable_' + target_key(self.path))
        error = ctypes.get_last_error()
        if not self.handle:
            raise ctypes.WinError(error)
        if error == 183:
            self.__exit__(None, None, None)
            raise RuntimeError('此软件的启动助手正在运行，请等待它完成。')
        return self

    def __exit__(self, *args):
        if self.handle:
            k = ctypes.WinDLL('kernel32', use_last_error=True)
            k.CloseHandle.argtypes = [W.HANDLE]
            k.CloseHandle(self.handle)
            self.handle = None


class ProfileBackup:
    """Skip absent profiles; restore only the two evidenced profile keys."""
    def __init__(self, path, report_path):
        self.path, self.report_path = Path(path), Path(report_path)
        self.original = self.path.read_bytes() if self.path.is_file() else None
        self.info = {'path': str(self.path), 'existed': self.original is not None}
        if self.original is not None:
            self.report_path.with_suffix('.qq_config.original.bin').write_bytes(self.original)
            self.info['original_sha256'] = hashlib.sha256(self.original).hexdigest()

    def finish(self):
        current = self.path.read_bytes() if self.path.is_file() else None
        if current == self.original:
            self.info['changed'] = False
            return self.info
        self.info['changed'] = True
        if current is not None:
            self.report_path.with_suffix('.qq_config.after.bin').write_bytes(current)
        if self.original is None or current is None:
            self.info['restored'] = False
            self.info['reason'] = 'Profile newly appeared or disappeared; retained for inspection.'
            return self.info
        def clean(blob):
            # Preserve byte-level evidence and tolerate non-Chinese Windows encodings.
            return [line for line in blob.splitlines()
                    if not line.lstrip().lower().startswith((b'version=', b'versionb='))]
        if clean(self.original) == clean(current):
            # A second read avoids overwriting a concurrent edit observed after comparison.
            if self.path.read_bytes() == current:
                self.path.write_bytes(self.original)
                self.info['restored'] = True
            else:
                self.info.update(restored=False, reason='Concurrent profile edit; retained.')
        else:
            self.info.update(restored=False, reason='Unrelated profile changes; retained.')
        return self.info


def ensure_platform():
    # Environment variables can be stripped by a launcher; ask Windows directly.
    if os.name != 'nt' or struct.calcsize('P') != 8:
        raise RuntimeError('此版本需要 Windows 10/11 x64。')
    class SYSTEM_INFO(ctypes.Structure):
        _fields_ = [('architecture', W.WORD), ('reserved', W.WORD), ('page_size', W.DWORD),
                    ('minimum_address', ctypes.c_void_p), ('maximum_address', ctypes.c_void_p),
                    ('active_mask', ctypes.c_size_t), ('processors', W.DWORD), ('processor_type', W.DWORD),
                    ('allocation_granularity', W.DWORD), ('level', W.WORD), ('revision', W.WORD)]
    info = SYSTEM_INFO()
    kernel = ctypes.WinDLL('kernel32')
    kernel.GetNativeSystemInfo.argtypes = [ctypes.POINTER(SYSTEM_INFO)]
    kernel.GetNativeSystemInfo(ctypes.byref(info))
    import sys
    if info.architecture != 9 or sys.getwindowsversion().major < 10:
        raise RuntimeError('此版本需要 Windows 10/11 x64。')
    return {'native_architecture': 'AMD64', 'windows_build': sys.getwindowsversion().build}


def is_administrator():
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    shell.IsUserAnAdmin.argtypes = []
    shell.IsUserAnAdmin.restype = W.BOOL
    return bool(shell.IsUserAnAdmin())


def requires_elevation(identity):
    return identity.get('execution_level') in ('requireAdministrator', 'highestAvailable') and not is_administrator()


def relaunch_elevated(command, cwd):
    """Use the ordinary Windows UAC dialog; wait for the child launcher exit."""
    import subprocess
    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [('cbSize', W.DWORD), ('fMask', W.ULONG), ('hwnd', W.HWND),
                    ('lpVerb', W.LPCWSTR), ('lpFile', W.LPCWSTR), ('lpParameters', W.LPCWSTR),
                    ('lpDirectory', W.LPCWSTR), ('nShow', ctypes.c_int), ('hInstApp', W.HINSTANCE),
                    ('lpIDList', ctypes.c_void_p), ('lpClass', W.LPCWSTR), ('hkeyClass', W.HKEY),
                    ('dwHotKey', W.DWORD), ('hIcon', W.HANDLE), ('hProcess', W.HANDLE)]
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    shell.ShellExecuteExW.restype = W.BOOL
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40 | 0x100  # NOCLOSEPROCESS | NOASYNC
    info.lpVerb = 'runas'
    info.lpFile = str(command[0])
    info.lpParameters = subprocess.list2cmdline([str(arg) for arg in command[1:]])
    info.lpDirectory = str(cwd)
    info.nShow = 1
    if not shell.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.get_last_error()
        if error == 1223:
            raise RuntimeError('已取消 Windows 管理员权限确认，软件尚未启动。')
        raise ctypes.WinError(error)
    if not info.hProcess:
        raise RuntimeError('管理员启动未返回进程句柄，请查看 Windows 权限提示。')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
    kernel.WaitForSingleObject.restype = W.DWORD
    kernel.GetExitCodeProcess.argtypes = [W.HANDLE, ctypes.POINTER(W.DWORD)]
    kernel.GetExitCodeProcess.restype = W.BOOL
    kernel.CloseHandle.argtypes = [W.HANDLE]
    try:
        if kernel.WaitForSingleObject(info.hProcess, 0xffffffff) != 0:
            raise ctypes.WinError(ctypes.get_last_error())
        exit_code = W.DWORD()
        if not kernel.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return exit_code.value
    finally:
        kernel.CloseHandle(info.hProcess)
