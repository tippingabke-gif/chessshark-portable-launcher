"""Privacy boundary checks with mocked startup; no target process access."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import portable_launcher as launcher
from release_presentation import public_error, public_result

SECRET = r'C:\Users\private_builder\Documents\contact_123456789\ChessShark.exe'

class PresentationTests(unittest.TestCase):
    def test_result_uses_allowlist(self):
        record={'status':'compatible','target':{'path':SECRET,'profile_id':'v253','version':SECRET},'error':SECRET,'run_directory':SECRET}
        self.assertEqual(public_result(record),{'status':'compatible','version':'V2.5.3'})

    def test_unrecognized_status_does_not_echo(self):
        self.assertEqual(public_result({'status':SECRET,'target':{'profile_id':SECRET}}),{'status':'completed'})

    def test_diagnostic_omits_worker_text(self):
        self.assertEqual(public_result({'diagnostic':'passed','worker_checks':[{'output':SECRET}]}),{'status':'diagnostic_passed','worker_checks':1})

    def test_error_does_not_echo_exception(self):
        for error in [RuntimeError(SECRET),FileNotFoundError(2,'missing',SECRET),PermissionError(13,'denied',SECRET)]:
            output=json.dumps(public_error(error))
            self.assertNotIn('private_builder',output)
            self.assertNotIn('123456789',output)

    def test_known_error_keeps_fixed_action(self):
        record=public_error(RuntimeError('已有窗口缺少本助手的完整启动记录 '+SECRET))
        self.assertEqual(record['code'],'E_EXISTING')
        self.assertNotIn('private_builder',json.dumps(record))

    def test_worker_failure_has_neutral_stage(self):
        record=public_error(RuntimeError('scan_parameters failed; '+SECRET))
        self.assertIn('识别参数',record['message'])
        self.assertNotIn('private_builder',json.dumps(record))

    def test_startup_output_and_shareable_report_exclude_private_record(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            target=root/'ChessShark.exe'
            shared=root/'share.json'
            private=root/'private.json'
            identity={'path':str(target),'profile_id':'v253'}
            result={'target':str(target),'target_identity':identity,'run_directory':SECRET,'ready':{'parameters':[100,2]},'pid':1234}
            def run():
                print('STARTING '+SECRET)
                print(json.dumps(result))
                return result
            stdout=io.StringIO()
            from contextlib import nullcontext
            with patch.object(sys,'argv',['launcher','--target',str(target),'--no-dialog','--export-report',str(shared),'--out',str(private)]), \
                 patch.object(launcher,'ensure_platform',return_value={}), \
                 patch.object(launcher,'verify_bundle',return_value={}), \
                 patch.object(launcher,'data_root',return_value=root), \
                 patch.object(launcher,'find_target',return_value=target), \
                 patch.object(launcher,'validate_target',return_value=identity), \
                 patch.object(launcher,'requires_elevation',return_value=False), \
                 patch.object(launcher,'TargetLock',return_value=nullcontext()), \
                 patch.object(launcher,'reuse',return_value=None), \
                 patch.dict(sys.modules,{'launch_chessshark_with_scan_fix':type('FakeModule',(),{'main':staticmethod(run)})()}), \
                 contextlib.redirect_stdout(stdout):
                launcher.main()
            self.assertNotIn('private_builder',stdout.getvalue())
            self.assertNotIn(str(root),stdout.getvalue())
            self.assertNotIn('private_builder',shared.read_text(encoding='utf-8'))
            self.assertEqual(json.loads(shared.read_text(encoding='utf-8'))['status'],'ready')
            self.assertEqual(json.loads(private.read_text(encoding='utf-8'))['run_directory'],SECRET)
            log=next((root/'targets').glob('*/launch.console.txt'))
            self.assertIn('private_builder',log.read_text(encoding='utf-8'))

if __name__=='__main__':
    unittest.main(verbosity=2)
