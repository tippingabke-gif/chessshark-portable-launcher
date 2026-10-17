# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import keystone

root = Path(SPECPATH)
scripts = root / 'bundle' / 'scripts'
keystone_dll = Path(keystone.__file__).resolve().parent / 'keystone.dll'
if not keystone_dll.is_file():
    raise RuntimeError('Windows x64 Keystone DLL is required; install requirements-build.txt')

a = Analysis(
    [str(root / 'portable_launcher.py')],
    pathex=[str(root), str(scripts)],
    binaries=[(str(keystone_dll), 'keystone')],
    datas=[(str(path), 'scripts') for path in sorted(scripts.glob('*.py'))]
          + [(str(root / 'bundle' / 'bundle_manifest.json'), '.')],
    hiddenimports=['keystone', 'win32gui', 'win32process', 'win32api', 'win32con',
                   'win32clipboard', 'inspect_live_objects', 'capture_ui_frontier',
                   'capture_registration_state', 'native_message_probe', 'watch_main_destructor',
                   'run_external_hwtrace', 'launch_chessshark_with_scan_fix', 'portable_support',
                   'pe_compatibility', 'pefile', 'version_profiles', 'release_presentation'],
    hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False, optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name='ChessShark_便携启动修复',
          version=str(root / 'release_version.txt'),
          debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
          runtime_tmpdir=None, console=True, disable_windowed_traceback=False,
          argv_emulation=False, target_arch=None, codesign_identity=None, entitlements_file=None)
