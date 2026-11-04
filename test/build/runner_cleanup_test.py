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

    def test_e2e_cleanup_reaps_only_capture_processes_and_owned_tc(self):
        e2e = self.base / 'privileged-e2e'
        (e2e / 'job-state').mkdir(parents=True)
        (e2e / 'job-state/cache').touch()
        (e2e / 'owns-loopback-clsact').touch()
        tracked = self.spawn_process('ecapture-root-e2e')
        unrelated = self.spawn_process('unrelated-' + str(os.getpid()))
        with mock.patch.object(cleanup, 'E2E', e2e), mock.patch('os.geteuid', return_value=0), \
             mock.patch('subprocess.run') as tc, mock.patch('subprocess.check_output', return_value=b'[]'):
            cleanup.main('e2e')
            cleanup.main('e2e')  # EXIT trap and always() cleanup are idempotent.
        self.assertEqual(tracked.wait(timeout=5), -9)
        self.assertIsNone(unrelated.poll())
        self.assertEqual(list((e2e / 'job-state').iterdir()), [])
        self.assertFalse((e2e / 'owns-loopback-clsact').exists())
        tc.assert_called_once()

    def test_e2e_cleanup_preserves_unowned_tc_and_failed_cleanup_state(self):
        e2e = self.base / 'privileged-e2e'
        with mock.patch.object(cleanup, 'E2E', e2e), mock.patch('os.geteuid', return_value=0), \
             mock.patch.object(cleanup, 'terminate_tracked'), mock.patch('subprocess.run') as tc:
            cleanup.main('e2e')
            tc.assert_not_called()
            (e2e / 'owns-loopback-clsact').touch()
            with mock.patch('subprocess.check_output', return_value=b'[{"kind":"clsact"}]'):
                with self.assertRaises(RuntimeError):
                    cleanup.main('e2e')
            self.assertTrue((e2e / 'owns-loopback-clsact').exists())
        with mock.patch('os.geteuid', return_value=1000):
            with self.assertRaises(RuntimeError):
                cleanup.main('e2e')

    def test_start_hook_admits_only_trusted_e2e_jobs(self):
        event = self.base / 'event.json'
        pr = {'head': {'repo': {'full_name': 'gojue/ecapture'}},
              'base': {'repo': {'full_name': 'gojue/ecapture'}, 'ref': 'master'}}
        # Stop admitted jobs at the first sudo call, before touching host state.
        sudo = self.base / 'sudo'
        sudo.write_text('#!/bin/sh\nexit 77\n')
        sudo.chmod(0o700)
        environment = dict(os.environ, PATH=f'{self.base}:/usr/bin:/bin',
                           GITHUB_REPOSITORY='gojue/ecapture',
                           GITHUB_EVENT_NAME='pull_request', GITHUB_REF='refs/pull/42/merge',
                           GITHUB_WORKFLOW_REF='gojue/ecapture/.github/workflows/e2e.yml@refs/pull/42/merge',
                           GITHUB_JOB='loong64-e2e', GITHUB_EVENT_PATH=str(event))
        command = ['bash', str(SOURCE.with_name('runner-job-started.sh'))]
        for repository, code in [('gojue/ecapture', 77), ('outsider/ecapture', 1)]:
            pr['head']['repo']['full_name'] = repository
            event.write_text(json.dumps({'action': 'opened', 'number': 42, 'pull_request': pr}))
            self.assertEqual(subprocess.run(command, env=environment, capture_output=True).returncode, code)
        environment.update(GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/master',
                           GITHUB_WORKFLOW_REF='gojue/ecapture/.github/workflows/self-hosted-loong64.yml@refs/heads/master',
                           GITHUB_JOB='tls-unit')
        self.assertEqual(subprocess.run(command, env=environment, capture_output=True).returncode, 1)


if __name__ == '__main__':
    if sys.platform != 'linux':
        sys.exit('Runner cleanup tests require Linux and pidfd support.')
    unittest.main()
