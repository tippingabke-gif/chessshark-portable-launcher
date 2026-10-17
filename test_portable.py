"""Tests for new portability behavior; no target process starts or memory writes."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from version_profiles import relocate
from unittest.mock import patch, MagicMock
from portable_support import (ProfileBackup, find_target, data_root, validate_target,
                              TargetLock, selected_process, ensure_platform, requires_elevation, relaunch_elevated)


class PortableTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='棋盘 便携测试 ')
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_architecture_without_processor_environment(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(ensure_platform()['native_architecture'], 'AMD64')

    def test_original_build_requests_admin_only_when_needed(self):
        with patch('portable_support.is_administrator', return_value=False):
            self.assertTrue(requires_elevation({'execution_level': 'requireAdministrator'}))
            self.assertFalse(requires_elevation({'execution_level': 'asInvoker'}))
        with patch('portable_support.is_administrator', return_value=True):
            self.assertFalse(requires_elevation({'execution_level': 'requireAdministrator'}))

    def test_uac_cancel_does_not_retry(self):
        shell = MagicMock()
        shell.ShellExecuteExW.return_value = False
        with patch('portable_support.ctypes.WinDLL', return_value=shell), patch('portable_support.ctypes.get_last_error', return_value=1223):
            with self.assertRaisesRegex(RuntimeError, '已取消'):
                relaunch_elevated(['assistant.exe', '--target', 'X:/中文 空格/ChessShark.exe'], self.root)
        shell.ShellExecuteExW.assert_called_once()

    def test_uac_child_exit_and_quoted_path_are_preserved(self):
        shell, kernel = MagicMock(), MagicMock()
        observed = {}
        def launch(pointer):
            observed['parameters'] = pointer._obj.lpParameters
            observed['verb'] = pointer._obj.lpVerb
            pointer._obj.hProcess = 123
            return True
        def exit_code(handle, pointer):
            pointer._obj.value = 17
            return True
        shell.ShellExecuteExW.side_effect = launch
        kernel.WaitForSingleObject.return_value = 0
        kernel.GetExitCodeProcess.side_effect = exit_code
        with patch('portable_support.ctypes.WinDLL', side_effect=lambda name, **kw: shell if name == 'shell32' else kernel):
            self.assertEqual(relaunch_elevated(['assistant.exe', '--target', 'X:/中文 空格/ChessShark.exe'], self.root), 17)
        self.assertEqual(observed['verb'], 'runas')
        self.assertIn('"X:/中文 空格/ChessShark.exe"', observed['parameters'])
        kernel.CloseHandle.assert_called_once_with(123)

    def test_version_profiles_keep_separate_offsets_under_aslr(self):
        for base in (0x400000, 0x490000, 0xd00000):
            self.assertEqual(relocate(base, 0x11dd744, 'v248'), base+0x5bd744)
            self.assertEqual(relocate(base, 0x11dd744, 'v253'), base+0x5c8920)
            self.assertEqual(relocate(base, 0x1732d49, 'v253'), base+0x748c1b)

    def test_unmapped_new_version_address_stops(self):
        with self.assertRaisesRegex(ValueError, '尚未迁移'):
            relocate(0x490000, 0xc83c64, 'v253')

    def test_same_directory_wins_over_stale_saved_path(self):
        exe = self.root/'ChessShark.exe'
        exe.write_bytes(b'x')
        with patch('portable_support.choose_file', side_effect=AssertionError('unexpected dialog')):
            self.assertEqual(find_target(None, self.root, 'X:/absent/ChessShark.exe'), exe)

    def test_explicit_target_and_manual_selection(self):
        explicit = self.root/'elsewhere/ChessShark.exe'
        self.assertEqual(find_target(explicit, self.root, None), explicit)
        with patch('portable_support.choose_file', return_value=explicit):
            self.assertEqual(find_target(None, self.root, None, True), explicit)

    def test_readonly_app_location_falls_back(self):
        # A file occupying the preferred directory reproduces an unwritable location.
        (self.root/'ChessShark助手数据').write_text('occupied')
        with patch.dict(os.environ, {'LOCALAPPDATA': str(self.root/'用户数据')}):
            self.assertEqual(data_root(self.root), (self.root/'用户数据/ChessSharkPortableLauncher').resolve())

    def test_missing_optional_profile_is_not_created(self):
        path = self.root/'nonexistent/config.ini'
        record = ProfileBackup(path, self.root/'native.json')
        self.assertFalse(record.finish()['changed'])
        self.assertFalse(path.exists())

    def test_profile_only_known_changes_are_restored(self):
        path = self.root/'config.ini'
        original = b'[game]\r\nVersion=old\r\ncustom=keep\r\n'
        path.write_bytes(original)
        record = ProfileBackup(path, self.root/'native.json')
        path.write_bytes(b'[game]\r\nVersion=new\r\ncustom=keep\r\nVersionB=2\r\n')
        self.assertTrue(record.finish()['restored'])
        self.assertEqual(path.read_bytes(), original)

    def test_unrelated_profile_edits_preserved(self):
        path = self.root/'config.ini'
        path.write_bytes(b'[game]\r\nVersion=old\r\ncustom=keep\r\n')
        record = ProfileBackup(path, self.root/'native.json')
        modified = b'[game]\r\nVersion=new\r\ncustom=changed\r\n'
        path.write_bytes(modified)
        self.assertFalse(record.finish()['restored'])
        self.assertEqual(path.read_bytes(), modified)

    def test_new_profile_is_preserved_and_logged(self):
        path = self.root/'config.ini'
        record = ProfileBackup(path, self.root/'native.json')
        path.write_bytes(b'new')
        self.assertFalse(record.finish()['restored'])
        self.assertEqual(path.read_bytes(), b'new')

    def test_wrong_build_rejected_before_pe_parse(self):
        path = self.root/'ChessShark.exe'
        path.write_bytes(b'wrong version')
        with self.assertRaisesRegex(ValueError, '构建不匹配'):
            validate_target(path)
        self.assertEqual(path.read_bytes(), b'wrong version')

    def test_process_selection_scoped_to_exact_path(self):
        with patch.dict(os.environ, {'CHESSSHARK_TARGET': str(self.root/'selected/ChessShark.exe')}):
            with self.assertRaisesRegex(ValueError, '路径不符'):
                selected_process(self.root/'other/ChessShark.exe')

    def test_startup_mutex_excludes_second_launcher(self):
        with TargetLock(self.root/'ChessShark.exe'):
            with self.assertRaisesRegex(RuntimeError, '正在运行'):
                with TargetLock(self.root/'ChessShark.exe'):
                    self.fail('Second launcher entered')
        with TargetLock(self.root/'ChessShark.exe'):
            pass


if __name__ == '__main__':
    unittest.main(verbosity=2)
