#!/usr/bin/env python3
"""Resolve a live, trusted Actions job to a private root-owned E2E snapshot."""

import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import urllib.request

INPUT = Path('/var/lib/ecapture-runner/job-state/e2e-input')
JOB = Path('/var/lib/ecapture-e2e/job-state')
REGISTRATION = Path('/opt/ecapture-actions-runner/.runner')
REPOSITORY = 'gojue/ecapture'
WORKFLOW = '.github/workflows/e2e.yml'
JOB_NAME = 'E2E Tests (OpenSSL/GoTLS) / Debian LoongArch64'
BRANCHES = ('master', 'v2', 'v1')


def read_input(name, limit):
    """Reject substituted parent directories, symlinks and non-regular inputs."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in INPUT.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(source, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != pwd.getpwnam('ecapture-runner').pw_uid
                    or info.st_size > limit):
                raise RuntimeError('Invalid CI input file')
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise RuntimeError('CI input exceeds size limit')
            return data
    finally:
        os.close(fd)


def github(path, token):
    request = urllib.request.Request(
        f'https://api.github.com/repos/{REPOSITORY}/{path}',
        headers={'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28',
                 'Authorization': f'Bearer {token}',
                 'User-Agent': 'ecapture-loong64-e2e'})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def authorize(request, token, runner_id):
    for name, pattern in (('run_id', r'[1-9][0-9]*'), ('run_attempt', r'[1-9][0-9]*'),
                          ('sha', r'[0-9a-f]{40}'), ('binary_sha256', r'[0-9a-f]{64}'),
                          ('pull_request', r'0|[1-9][0-9]*')):
        if not re.fullmatch(pattern, str(request.get(name, ''))):
            raise RuntimeError(f'Invalid CI request field: {name}')
    run_id, attempt = str(request['run_id']), str(request['run_attempt'])
    run = github(f'actions/runs/{run_id}', token)
    if (run['repository']['full_name'] != REPOSITORY
            or run['path'] != WORKFLOW or run['status'] != 'in_progress'
            or str(run['run_attempt']) != attempt):
        raise RuntimeError('Request does not identify a live E2E workflow attempt')
    # The request is writable by the service account. The GitHub API, not its
    # claimed event or SHA, establishes which job is actually on this runner.
    jobs = github(f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100', token)
    active = [job for job in jobs['jobs'] if job['name'] == JOB_NAME
              and job['status'] == 'in_progress' and job['runner_id'] == runner_id]
    if len(active) != 1:
        raise RuntimeError('No unique active LoongArch E2E job on this runner')
    if run['event'] == 'pull_request':
        number = str(request['pull_request'])
        if number == '0':
            raise RuntimeError('Missing pull request number')
        pr = github(f'pulls/{number}', token)
        if (pr['state'] != 'open' or pr['head']['repo']['full_name'] != REPOSITORY
                or pr['base']['repo']['full_name'] != REPOSITORY
                or pr['base']['ref'] not in BRANCHES
                or pr['head']['sha'] != run['head_sha']
                or pr['head']['ref'] != run['head_branch']
                or pr['merge_commit_sha'] != request['sha']):
            raise RuntimeError('Fork, stale or mismatched pull request')
        ref = f'refs/pull/{number}/merge'
    elif run['event'] in ('push', 'workflow_dispatch'):
        if (run['head_branch'] not in BRANCHES or run['head_sha'] != request['sha']
                or str(request['pull_request']) != '0'):
            raise RuntimeError('Untrusted branch or mismatched commit')
        ref = request['sha']
    else:
        raise RuntimeError('Untrusted workflow event')
    return {'ci_run_id': run_id, 'ci_run_attempt': attempt,
            'ci_job_id': active[0]['id'], 'event': run['event'],
            'source_commit': request['sha'], 'binary_sha256': request['binary_sha256'],
            'source_ref': ref, 'modules': ['tls', 'gotls']}


def prepare():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('CI preparation requires Linux root')
    request = json.loads(read_input('request.json', 8192))
    token = read_input('github-token', 4096).decode().strip()
    # The runner's .NET writer may prefix its registration JSON with a UTF-8 BOM.
    runner_id = json.loads(REGISTRATION.read_text(encoding='utf-8-sig'))['agentId']
    identity = authorize(request, token, runner_id)
    bundle = JOB / 'bundle'
    source = bundle / 'source'
    source.mkdir(parents=True, mode=0o700)
    # Fetch the authorized source from the fixed upstream. Never execute scripts
    # from the runner-writable checkout, or pass the API token to child processes.
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(JOB / 'home'),
                   'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                   'GIT_TERMINAL_PROMPT': '0'}

    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args],
                                       env=environment, timeout=180).decode().strip()

    git('init', '--quiet')
    git('fetch', '--quiet', '--no-tags', '--depth=1',
        f'https://github.com/{REPOSITORY}.git', identity['source_ref'])
    if git('rev-parse', 'FETCH_HEAD') != identity['source_commit']:
        raise RuntimeError('Fetched source no longer matches the requested commit')
    git('checkout', '--quiet', '--detach', 'FETCH_HEAD')
    binary = read_input('ecapture', 128 * 1024 * 1024)
    if hashlib.sha256(binary).hexdigest() != identity['binary_sha256']:
        raise RuntimeError('Staged binary changed after the build audit')
    (bundle / 'artifact').mkdir()
    (bundle / 'artifact/ecapture').write_bytes(binary)
    (bundle / 'artifact/ecapture').chmod(0o700)
    (bundle / 'SOURCE_COMMIT').write_text(identity['source_commit'] + '\n')
    (JOB / 'ci.json').write_text(json.dumps(identity) + '\n')


if __name__ == '__main__':
    try:
        prepare()
    except Exception as error:
        # Do not include request contents, HTTP headers, or the ephemeral token.
        print(f'CI snapshot preparation failed: {type(error).__name__}', file=sys.stderr)
        sys.exit(1)
