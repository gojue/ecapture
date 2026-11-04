#!/usr/bin/env python3
"""Clean one dedicated, sequential eCapture runner without touching its identity."""

import fcntl
import json
import os
from pathlib import Path
import pwd
import select
import signal
import stat
import subprocess
import sys

BASE = Path('/var/lib/ecapture-runner')
WORK = BASE / '_work'
WORKSPACE = WORK / 'ecapture' / 'ecapture'
JOB = BASE / 'job-state'
CONTROL = BASE / '.job-cleanup.json'
E2E = Path('/var/lib/ecapture-e2e')


def open_directory(path):
    """Open each component without following a substituted symlink."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def empty_fd(fd):
    # Go's module cache contains read-only directories owned by the runner.
    mode = stat.S_IMODE(os.fstat(fd).st_mode)
    os.fchmod(fd, mode | stat.S_IRWXU)
    with os.scandir(fd) as entries:
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
                try:
                    if os.fstat(child).st_dev != os.fstat(fd).st_dev:
                        raise RuntimeError('Refusing to clean a nested filesystem')
                    empty_fd(child)
                finally:
                    os.close(child)
                os.rmdir(entry.name, dir_fd=fd)
            else:
                os.unlink(entry.name, dir_fd=fd)


def empty_directory(path):
    try:
        fd = open_directory(path)
    except FileNotFoundError:
        return
    try:
        empty_fd(fd)
    finally:
        os.close(fd)


def ancestors():
    excluded = set()
    pid = os.getpid()
    while pid > 0 and pid not in excluded:
        excluded.add(pid)
        try:
            # The command name may contain spaces or closing parentheses.
            fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
            pid = int(fields[1])
        except (FileNotFoundError, ProcessLookupError):
            break
    return excluded


def terminate_tracked(tokens):
    """Terminate only this user's job-tagged children, never the hook or runner."""
    markers = {b'RUNNER_TRACKING_ID=' + token.encode() for token in tokens if token}
    if not markers:
        return
    excluded = ancestors()
    for attempt in range(4):
        handles = []
        try:
            for process in Path('/proc').iterdir():
                if not process.name.isdecimal() or int(process.name) in excluded:
                    continue
                handle = None
                try:
                    if process.stat().st_uid != os.getuid():
                        continue
                    handle = os.pidfd_open(int(process.name))
                    environment = (process / 'environ').read_bytes().split(b'\0')
                    if not markers.intersection(environment):
                        os.close(handle)
                        continue
                    handles.append(handle)
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    if handle is not None:
                        os.close(handle)
            if not handles:
                return
            if attempt == 3:
                raise RuntimeError('Job processes remain after bounded cleanup')
            for handle in handles:
                try:
                    signal.pidfd_send_signal(handle, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            exited, _, _ = select.select(handles, [], [], 2)
            pending = set(handles) - set(exited)
            for handle in pending:
                try:
                    signal.pidfd_send_signal(handle, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if pending:
                select.select(list(pending), [], [], 2)
        finally:
            for handle in handles:
                os.close(handle)


def previous_token():
    try:
        fd = os.open(CONTROL, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return ''
    with os.fdopen(fd) as file:
        value = json.load(file).get('tracking_id', '')
    if not isinstance(value, str):
        raise RuntimeError('Invalid cleanup state')
    return value


def cleanup_e2e():
    """The only root cleanup entry point: fixed E2E processes, TC and caches."""
    if os.geteuid() != 0:
        raise RuntimeError('E2E cleanup requires root')
    E2E.mkdir(mode=0o700, exist_ok=True)
    # The shell EXIT trap and the always() step may arrive together.
    with (E2E / 'cleanup.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        terminate_tracked({'ecapture-root-e2e'})
        owned = E2E / 'owns-loopback-clsact'
        if owned.exists():
            subprocess.run(['/usr/sbin/tc', 'qdisc', 'del', 'dev', 'lo', 'clsact'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            qdiscs = json.loads(subprocess.check_output(
                ['/usr/sbin/tc', '-j', 'qdisc', 'show', 'dev', 'lo']))
            if any(q['kind'] == 'clsact' for q in qdiscs):
                raise RuntimeError('Failed to remove test-owned loopback TC qdisc')
            owned.unlink()
        empty_directory(E2E / 'job-state')
    print('Privileged E2E processes, caches and owned TC state cleaned.')


def main(phase):
    if sys.platform == 'linux' and phase == 'e2e':
        cleanup_e2e()
        return
    if sys.platform != 'linux' or pwd.getpwuid(os.getuid()).pw_name != 'ecapture-runner':
        raise RuntimeError('Run on Linux as the ecapture-runner service account')
    if phase not in ('start', 'end', 'startup'):
        raise RuntimeError('Expected start, end, or startup')
    token = os.environ.get('RUNNER_TRACKING_ID', '')
    if phase == 'start':
        if os.environ.get('GITHUB_WORKSPACE') != str(WORKSPACE) or not token:
            raise RuntimeError('Unexpected workspace or missing job tracking ID')
        env_file = Path(os.environ['GITHUB_ENV'])
        if env_file.parent != WORK / '_temp' / '_runner_file_commands':
            raise RuntimeError('Unexpected GitHub environment file location')
    terminate_tracked({previous_token(), token})
    empty_directory(WORKSPACE)
    empty_directory(JOB)
    # Actions are downloaded before the start hook; preserve the new download.
    if phase != 'start':
        empty_directory(WORK / '_actions')
        empty_directory(WORK / '_tool')
    # Live hooks still need runner-owned file-command and summary files. The
    # runner itself cleans these after the job; startup handles crash leftovers.
    if phase == 'startup':
        empty_directory(WORK / '_temp')
    CONTROL.unlink(missing_ok=True)
    if phase == 'start':
        JOB.mkdir(mode=0o700, exist_ok=True)
        for name in ('home', 'tmp', 'cache', 'go', 'config'):
            (JOB / name).mkdir(mode=0o700)
        values = {
            'HOME': JOB / 'home', 'TMPDIR': JOB / 'tmp',
            'TMP': JOB / 'tmp', 'TEMP': JOB / 'tmp',
            'XDG_CACHE_HOME': JOB / 'cache', 'XDG_CONFIG_HOME': JOB / 'config',
            'GOCACHE': JOB / 'cache' / 'go-build', 'GOPATH': JOB / 'go',
            'GOMODCACHE': JOB / 'go' / 'pkg' / 'mod',
            'GIT_CONFIG_GLOBAL': JOB / 'home' / '.gitconfig',
            'GOPROXY': 'https://goproxy.cn,https://proxy.golang.org,direct',
        }
        with os.fdopen(os.open(CONTROL, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as file:
            json.dump({'tracking_id': token}, file)
        parent = open_directory(env_file.parent)
        try:
            fd = os.open(env_file.name, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, dir_fd=parent)
            with os.fdopen(fd, 'w') as file:
                for key, value in values.items():
                    file.write(f'{key}={value}\n')
        finally:
            os.close(parent)
    print(f'Runner job cleanup ({phase}) completed.')


if __name__ == '__main__':
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else '')
    except Exception as error:
        print(f'::error::Runner cleanup failed: {type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)
