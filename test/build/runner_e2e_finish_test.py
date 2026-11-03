#!/usr/bin/env python3
"""Check privileged report/cleanup boundaries using temporary paths and mocked TC."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / 'builder' / 'runner' / 'runner-e2e-finish.py'
spec = importlib.util.spec_from_file_location('e2e_finish', SOURCE)
finish = importlib.util.module_from_spec(spec)
spec.loader.exec_module(finish)


class FinishTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = self.root / 'state'
        self.logs = self.root / 'logs'
        self.bundle = self.root / 'bundle'
        self.run_id = '20261102T000000Z-123'
        self.report = self.logs / self.run_id
        self.job = self.base / 'job-state'
        for path in (self.base, self.report, self.bundle / 'artifact',
                     self.bundle / 'source/test/e2e', self.job / 'artifacts/helpers'):
            path.mkdir(parents=True, exist_ok=True)
        (self.base / 'current').write_text(self.run_id)
        (self.bundle / 'SOURCE_COMMIT').write_text('9d3cce87\n')
        (self.bundle / 'artifact/ecapture').write_bytes(b'test-artifact')
        (self.bundle / 'source/test/e2e/platform.sh').write_text('# test source')
        (self.report / 'stdout.log').write_text(
            '[PASS] linux/tls/text\n[FAIL] linux/gotls/pcapng-with-dsb\n'
            'CLIENT_RANDOM synthetic-secret-that-must-stay-private\n')
        (self.job / 'artifacts/helpers/binary').touch()
        (self.job / 'artifacts/capture.log').write_text('synthetic private capture')
        for target, value in [('BASE', self.base), ('LOGS', self.logs), ('BUNDLE', self.bundle)]:
            patcher = mock.patch.object(finish, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for target, options in [
            ('os.geteuid', {'return_value': 0}), ('os.chown', {}),
            ('grp.getgrnam', {'return_value': type('Group', (), {'gr_gid': os.getgid()})()}),
            ('subprocess.run', {}), ('subprocess.check_output', {'return_value': b'[]'}),
        ]:
            patcher = mock.patch(target, **options)
            patched = patcher.start()
            self.addCleanup(patcher.stop)
            if target == 'subprocess.run':
                self.tc = patched

    def test_report_redacts_payloads_and_archives_without_helpers(self):
        finish.main()
        text = (self.logs / 'latest-summary.json').read_text()
        summary = json.loads(text)
        self.assertEqual((summary['passed'], summary['failed']), (1, 1))
        self.assertNotIn('synthetic-secret', text)
        self.assertIn('test/e2e/platform.sh', summary['harness_sha256'])
        self.assertEqual((self.logs / 'latest-summary.json').stat().st_mode & 0o777, 0o640)
        self.assertFalse(self.job.exists())
        self.assertFalse((self.base / 'current').exists())
        self.assertTrue((self.bundle / 'artifact/ecapture').exists())
        self.tc.assert_not_called()
        with tarfile.open(self.report / 'artifacts.tar.gz') as archive:
            self.assertIn('artifacts/capture.log', archive.getnames())
            self.assertFalse(any('helpers' in name for name in archive.getnames()))

    def test_only_owned_tc_state_is_removed(self):
        (self.base / 'owns-loopback-clsact').touch()
        finish.main()
        self.assertEqual(self.tc.call_args.args[0], ['/usr/sbin/tc', 'qdisc', 'del', 'dev', 'lo', 'clsact'])
        self.assertFalse((self.base / 'owns-loopback-clsact').exists())

    def test_failed_tc_cleanup_retains_recovery_state(self):
        (self.base / 'owns-loopback-clsact').touch()
        with mock.patch('subprocess.check_output', return_value=b'[{"kind":"clsact"}]'):
            with self.assertRaises(RuntimeError):
                finish.main()
        self.assertTrue(self.job.exists())
        self.assertTrue((self.base / 'current').exists())

    def test_invalid_control_path_does_not_delete_files(self):
        (self.base / 'current').write_text('../outside')
        with self.assertRaises(RuntimeError):
            finish.main()
        self.assertTrue(self.job.exists())
        self.tc.assert_not_called()

    def test_interrupted_run_is_distinguished_from_success(self):
        with mock.patch.dict(os.environ, {'SERVICE_RESULT': 'signal', 'EXIT_STATUS': 'TERM'}):
            finish.main()
        summary = json.loads((self.logs / 'latest-summary.json').read_text())
        self.assertEqual(summary['service_result'], 'signal')
        self.assertEqual(summary['exit_status'], 'TERM')
        self.assertFalse(summary['completed'])

    def test_stop_is_not_reported_as_complete_even_if_service_result_is_success(self):
        with mock.patch.dict(os.environ, {'SERVICE_RESULT': 'success', 'EXIT_STATUS': 'TERM'}):
            finish.main()
        summary = json.loads((self.logs / 'latest-summary.json').read_text())
        self.assertFalse(summary['completed'])


if __name__ == '__main__':
    if sys.platform != 'linux':
        sys.exit('E2E service regression checks require Linux.')
    unittest.main()
