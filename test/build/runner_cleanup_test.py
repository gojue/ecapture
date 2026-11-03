#!/usr/bin/env python3
"""Linux regression checks for the dedicated runner's destructive cleanup."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / 'builder' / 'runner' / 'runner-job-cleanup.py'
spec = importlib.util.spec_from_file_location('runner_cleanup', SOURCE)
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


class CleanupTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.work = self.base / '_work'
        self.workspace = self.work / 'ecapture' / 'ecapture'
        self.job = self.base / 'job-state'
        self.control = self.base / '.job-cleanup.json'
        self.env_file = self.work / '_temp' / '_runner_file_commands' / 'set_env_test'
        self.workspace.mkdir(parents=True)
        self.env_file.parent.mkdir(parents=True)
        self.env_file.touch()
        for key, value in dict(BASE=self.base, WORK=self.work, WORKSPACE=self.workspace,
                               JOB=self.job, CONTROL=self.control).items():
            patcher = mock.patch.object(cleanup, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(cleanup.pwd, 'getpwuid',
                                    return_value=SimpleNamespace(pw_name='ecapture-runner'))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.dict(os.environ, {
            'RUNNER_TRACKING_ID': 'cleanup-regression-' + str(os.getpid()),
            'GITHUB_WORKSPACE': str(self.workspace), 'GITHUB_ENV': str(self.env_file),
        })
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_symlinks_never_delete_external_files(self):
        outside = self.base / 'preserve'
        outside.mkdir()
        marker = outside / 'identity'
        marker.write_text('keep')
        (self.workspace / 'link').symlink_to(outside, target_is_directory=True)
        readonly = self.workspace / 'readonly-module'
        readonly.mkdir()
        (readonly / 'source').write_text('remove')
        readonly.chmod(0o500)
        cleanup.empty_directory(self.workspace)
        self.assertEqual(marker.read_text(), 'keep')
        self.assertEqual(list(self.workspace.iterdir()), [])
        self.workspace.rmdir()
        self.workspace.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            cleanup.empty_directory(self.workspace)
        self.assertEqual(marker.read_text(), 'keep')

    def test_job_lifecycle_preserves_live_actions_and_runner_state(self):
        preserved = self.base / 'validation' / 'source'
        preserved.parent.mkdir()
        preserved.write_text('keep')
        actions = self.work / '_actions'
        actions.mkdir()
        (actions / 'downloaded-action').write_text('keep until job ends')
        (self.workspace / 'previous-checkout').write_text('remove')
        cleanup.main('start')
        self.assertEqual(list(self.workspace.iterdir()), [])
        self.assertTrue((actions / 'downloaded-action').exists())
        self.assertIn('HOME=' + str(self.job / 'home'), self.env_file.read_text())
        self.assertTrue(self.control.exists())
        (self.job / 'home' / 'leftover').write_text('remove')
        (self.workspace / 'output').write_text('remove')
        cleanup.main('end')
        for path in (self.workspace, self.job, actions):
            self.assertEqual(list(path.iterdir()), [])
        self.assertFalse(self.control.exists())
        self.assertTrue(self.env_file.exists(), 'live file commands must survive the end hook')
        self.assertEqual(preserved.read_text(), 'keep')
        cleanup.main('startup')
        self.assertEqual(list((self.work / '_temp').iterdir()), [])
        self.assertEqual(preserved.read_text(), 'keep')

    def test_invalid_start_context_leaves_files_untouched(self):
        marker = self.workspace / 'keep'
        marker.touch()
        with mock.patch.dict(os.environ, {'GITHUB_WORKSPACE': '/unexpected'}):
            with self.assertRaises(RuntimeError):
                cleanup.main('start')
        with mock.patch.dict(os.environ, {'RUNNER_TRACKING_ID': ''}):
            with self.assertRaises(RuntimeError):
                cleanup.main('start')
        self.assertTrue(marker.exists())

    def spawn_process(self, token):
        env = dict(os.environ, RUNNER_TRACKING_ID=token)
        process = subprocess.Popen([
            sys.executable, '-c',
            'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
            'print("ready",flush=True); time.sleep(60)',
        ], env=env, stdout=subprocess.PIPE, text=True)
        self.assertEqual(process.stdout.readline().strip(), 'ready')
        def stop():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdout.close()
        self.addCleanup(stop)
        return process

    def test_end_kills_job_process_but_preserves_other_process(self):
        tracked = self.spawn_process(os.environ['RUNNER_TRACKING_ID'])
        unrelated = self.spawn_process('unrelated-' + str(os.getpid()))
        cleanup.main('end')
        self.assertEqual(tracked.wait(timeout=5), -9)
        self.assertIsNone(unrelated.poll())

    def test_start_recovers_interrupted_job(self):
        previous = self.spawn_process('interrupted-' + str(os.getpid()))
        self.control.write_text(json.dumps({'tracking_id': 'interrupted-' + str(os.getpid())}))
        self.job.mkdir()
        (self.job / 'previous-job').touch()
        (self.workspace / 'previous-output').touch()
        cleanup.main('start')
        self.assertEqual(previous.wait(timeout=5), -9)
        self.assertFalse((self.job / 'previous-job').exists())
        self.assertEqual(list(self.workspace.iterdir()), [])


if __name__ == '__main__':
    if sys.platform != 'linux':
        sys.exit('Runner cleanup tests require Linux and pidfd support.')
    unittest.main()
