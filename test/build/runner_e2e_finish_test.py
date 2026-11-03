#!/usr/bin/env python3
"""Check privileged report/cleanup boundaries using temporary paths and mocked TC."""
import importlib.util
import copy
import hashlib
import itertools
import json
import os
from pathlib import Path
import sys
import subprocess
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / 'builder' / 'runner' / 'runner-e2e-finish.py'
spec = importlib.util.spec_from_file_location('e2e_finish', SOURCE)
finish = importlib.util.module_from_spec(spec)
spec.loader.exec_module(finish)
spec = importlib.util.spec_from_file_location('e2e_prepare',
                                            SOURCE.with_name('runner-e2e-prepare.py'))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


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

    def test_ci_uses_this_snapshot_identity_and_removes_it(self):
        (self.job / 'ci-requested').touch()
        shutil.copytree(self.bundle, self.job / 'bundle')
        (self.job / 'bundle/SOURCE_COMMIT').write_text('a' * 40)
        (self.job / 'ci.json').write_text(json.dumps(
            {'ci_run_id': '123', 'ci_run_attempt': '2', 'ci_job_id': 456}))
        (self.report / 'stdout.log').write_text(
            '[PASS] linux/tls/text\n[PASS] linux/gotls/text\n'
            '[PASS] All Linux E2E suites passed\n')
        with mock.patch.dict(os.environ, {'SERVICE_RESULT': 'success', 'EXIT_STATUS': '0'}):
            finish.main()
        summary = json.loads((self.logs / 'latest-summary.json').read_text())
        self.assertTrue(summary['completed'])
        self.assertEqual(summary['source_commit'], 'a' * 40)
        self.assertEqual(summary['modules'], ['tls', 'gotls'])
        self.assertEqual(summary['ci_run_attempt'], '2')
        self.assertEqual(summary['ci_job_id'], 456)
        self.assertFalse(self.job.exists())
        self.assertTrue(self.bundle.exists())

    def test_preparation_failure_never_reports_previous_bundle_identity(self):
        (self.job / 'ci-requested').touch()
        finish.main()
        summary = json.loads((self.logs / 'latest-summary.json').read_text())
        self.assertIsNone(summary['source_commit'])
        self.assertIsNone(summary['binary_sha256'])
        self.assertFalse(summary['completed'])
        self.assertFalse(self.job.exists())


class AdmissionTest(unittest.TestCase):
    def setUp(self):
        self.request = {'run_id': '123', 'run_attempt': '2', 'sha': 'a' * 40,
                        'binary_sha256': 'b' * 64, 'pull_request': '42'}
        self.run = {'repository': {'full_name': prepare.REPOSITORY},
                    'path': prepare.WORKFLOW, 'status': 'in_progress', 'run_attempt': 2,
                    'event': 'pull_request', 'head_branch': 'feat/example', 'head_sha': 'c' * 40}
        self.pr = {'state': 'open', 'head': {'repo': {'full_name': prepare.REPOSITORY},
                                           'ref': 'feat/example', 'sha': 'c' * 40},
                   'base': {'repo': {'full_name': prepare.REPOSITORY}, 'ref': 'master'},
                   'merge_commit_sha': 'a' * 40}
        self.jobs = {'jobs': [{'name': prepare.JOB_NAME, 'status': 'in_progress',
                               'runner_id': 22, 'id': 456}]}

    def authorize(self):
        with mock.patch.object(prepare, 'github', side_effect=[self.run, self.jobs, self.pr]):
            return prepare.authorize(self.request, 'synthetic-token', 22)

    def test_same_repo_pr_uses_merge_commit_not_head_commit(self):
        identity = self.authorize()
        self.assertEqual(identity['source_ref'], 'refs/pull/42/merge')
        self.assertEqual(identity['source_commit'], 'a' * 40)
        self.assertEqual(identity['ci_job_id'], 456)

    def test_push_and_dispatch_accept_only_protected_branch_names(self):
        self.request['pull_request'] = '0'
        for event in ('push', 'workflow_dispatch'):
            for branch in prepare.BRANCHES:
                self.run.update(event=event, head_branch=branch, head_sha='a' * 40)
                self.assertEqual(self.authorize()['source_ref'], 'a' * 40)
            self.run['head_branch'] = 'feat/example'
            with self.assertRaises(RuntimeError):
                self.authorize()

    def test_rejects_fork_stale_attempt_wrong_runner_and_sha(self):
        mutations = [
            ('pr', ('head', 'repo', 'full_name'), 'outsider/ecapture'),
            ('pr', ('base', 'ref'), 'untrusted'),
            ('pr', ('state',), 'closed'),
            ('pr', ('head', 'sha'), 'd' * 40),
            ('pr', ('merge_commit_sha',), 'd' * 40),
            ('run', ('run_attempt',), 1),
            ('run', ('status',), 'completed'),
            ('run', ('event',), 'pull_request_target'),
            ('run', ('path',), '.github/workflows/other.yml'),
            ('run', ('repository', 'full_name'), 'outsider/ecapture'),
            ('jobs', ('jobs', 0, 'runner_id'), 23),
            ('jobs', ('jobs', 0, 'status'), 'completed'),
            ('jobs', ('jobs', 0, 'name'), 'untrusted'),
            ('request', ('sha',), '../outside'),
        ]
        for name, keys, value in mutations:
            with self.subTest(name=name, keys=keys):
                original = copy.deepcopy(getattr(self, name))
                current = getattr(self, name)
                for key in keys[:-1]:
                    current = current[key]
                current[keys[-1]] = value
                with self.assertRaises(RuntimeError):
                    self.authorize()
                setattr(self, name, original)

    def test_input_rejects_symlinks_hardlinks_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'request.json'
            path.write_bytes(b'{}')
            user = type('User', (), {'pw_uid': os.getuid()})()
            with mock.patch.object(prepare, 'INPUT', root), mock.patch('pwd.getpwnam', return_value=user):
                self.assertEqual(prepare.read_input('request.json', 2), b'{}')
                with self.assertRaises(RuntimeError):
                    prepare.read_input('request.json', 1)
                os.link(path, root / 'hardlink')
                with self.assertRaises(RuntimeError):
                    prepare.read_input('request.json', 2)
                (root / 'hardlink').unlink()
                (root / 'link').symlink_to(path)
                with self.assertRaises(OSError):
                    prepare.read_input('link', 2)
            (root / 'parent-link').symlink_to(root, target_is_directory=True)
            with mock.patch.object(prepare, 'INPUT', root / 'parent-link'):
                with self.assertRaises(OSError):
                    prepare.read_input('request.json', 2)

    def test_start_hook_rejects_fork_before_any_job_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event = root / 'event.json'
            event.write_text(json.dumps({'action': 'opened', 'number': 42, 'pull_request': self.pr}))
            # Stop admitted jobs at the first sudo call, before touching host state.
            sudo = root / 'sudo'
            sudo.write_text('#!/bin/sh\nexit 77\n')
            sudo.chmod(0o700)
            environment = dict(os.environ, PATH=f'{root}:/usr/bin:/bin',
                               GITHUB_REPOSITORY=prepare.REPOSITORY,
                               GITHUB_EVENT_NAME='pull_request', GITHUB_REF='refs/pull/42/merge',
                               GITHUB_WORKFLOW_REF=f'{prepare.REPOSITORY}/{prepare.WORKFLOW}@refs/pull/42/merge',
                               GITHUB_JOB='loong64-e2e', GITHUB_EVENT_PATH=str(event))
            command = ['bash', str(SOURCE.with_name('runner-job-started.sh'))]
            self.assertEqual(subprocess.run(command, env=environment, capture_output=True).returncode, 77)
            self.pr['head']['repo']['full_name'] = 'outsider/ecapture'
            event.write_text(json.dumps({'action': 'opened', 'number': 42, 'pull_request': self.pr}))
            self.assertEqual(subprocess.run(command, env=environment, capture_output=True).returncode, 1)


class SnapshotTest(unittest.TestCase):
    def test_snapshot_binds_source_and_binary_without_forwarding_token(self):
        for encoding, failure in itertools.product(
                ('utf-8', 'utf-8-sig'), ('none', 'changed-ref', 'changed-binary')):
            with self.subTest(encoding=encoding, failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                registration = root / 'registration.json'
                registration.write_text('{"agentId":22}', encoding=encoding)
                binary = b'synthetic-test-binary'
                identity = {'source_ref': 'refs/pull/42/merge', 'source_commit': 'a' * 40,
                            'binary_sha256': hashlib.sha256(binary).hexdigest(),
                            'ci_run_id': '123', 'ci_run_attempt': '2'}
                inputs = {'request.json': b'{}', 'github-token': b'synthetic-secret',
                          'ecapture': binary if failure != 'changed-binary' else b'changed'}
                revision = 'b' * 40 if failure == 'changed-ref' else 'a' * 40
                with mock.patch.object(prepare, 'JOB', root / 'job'), \
                     mock.patch.object(prepare, 'REGISTRATION', registration), \
                     mock.patch.object(prepare, 'read_input', side_effect=lambda name, limit: inputs[name]), \
                     mock.patch.object(prepare, 'authorize', return_value=identity), \
                     mock.patch('os.geteuid', return_value=0), \
                     mock.patch('subprocess.check_output', side_effect=[b'', b'', revision.encode(), b'']) as git:
                    if failure == 'none':
                        prepare.prepare()
                        self.assertEqual((root / 'job/bundle/artifact/ecapture').read_bytes(), binary)
                        self.assertEqual(json.loads((root / 'job/ci.json').read_text()), identity)
                    else:
                        with self.assertRaises(RuntimeError):
                            prepare.prepare()
                        self.assertFalse((root / 'job/ci.json').exists())
                    for call in git.call_args_list:
                        self.assertNotIn('synthetic-secret', str(call))
                        self.assertNotIn('GITHUB_TOKEN', call.kwargs['env'])


if __name__ == '__main__':
    if sys.platform != 'linux':
        sys.exit('E2E service regression checks require Linux.')
    unittest.main()
