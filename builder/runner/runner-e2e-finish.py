#!/usr/bin/env python3
"""Finish the fixed root E2E service after systemd has reaped its process group."""
import datetime
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

BASE = Path('/var/lib/ecapture-e2e')
LOGS = Path('/var/log/ecapture-e2e')
BUNDLE = Path('/opt/ecapture-e2e')


def main():
    if os.geteuid() != 0:
        raise RuntimeError('E2E cleanup requires root')
    current = BASE / 'current'
    if not current.exists():
        return
    run_id = current.read_text().strip()
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9]+', run_id):
        raise RuntimeError('Invalid root-owned E2E state')
    report = LOGS / run_id
    job = BASE / 'job-state'
    if (BASE / 'owns-loopback-clsact').exists():
        subprocess.run(['/usr/sbin/tc', 'qdisc', 'del', 'dev', 'lo', 'clsact'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        qdiscs = json.loads(subprocess.check_output(['/usr/sbin/tc', '-j', 'qdisc', 'show', 'dev', 'lo']))
        if any(q['kind'] == 'clsact' for q in qdiscs):
            raise RuntimeError('Failed to remove test-owned loopback TC qdisc')
        (BASE / 'owns-loopback-clsact').unlink()
    output = report / 'stdout.log'
    text = output.read_text(errors='replace') if output.exists() else ''
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    # Only publish fixed case identifiers/statuses, never capture payloads or keys.
    cases = [{'name': name, 'status': status.lower()} for status, name in
             re.findall(r'^\[(PASS|FAIL)\] (linux/(?:tls|gotls|gnutls)/[a-z0-9-]+)$', text, re.M)]
    summary = {
        'run_id': run_id,
        'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'service_result': os.environ.get('SERVICE_RESULT', 'unknown'),
        'exit_status': os.environ.get('EXIT_STATUS', 'unknown'),
        'source_commit': (BUNDLE / 'SOURCE_COMMIT').read_text().strip(),
        'binary_sha256': hashlib.sha256((BUNDLE / 'artifact/ecapture').read_bytes()).hexdigest(),
        'harness_sha256': {
            str(path.relative_to(BUNDLE / 'source')): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((BUNDLE / 'source/test/e2e').rglob('*')) if path.is_file()
        },
        'passed': sum(case['status'] == 'pass' for case in cases),
        'failed': sum(case['status'] == 'fail' for case in cases),
        'cases': cases,
    }
    summary['completed'] = (
        summary['service_result'] == 'success' and summary['exit_status'] == '0'
        and summary['failed'] == 0
        and all(any(case['name'].startswith(f'linux/{module}/') for case in cases)
                for module in ('tls', 'gotls', 'gnutls'))
        and text.rstrip().endswith('[PASS] All Linux E2E suites passed')
    )
    if (job / 'artifacts').exists():
        with tarfile.open(report / 'artifacts.tar.gz', 'w:gz') as archive:
            archive.add(job / 'artifacts', arcname='artifacts',
                        filter=lambda info: None if 'helpers' in Path(info.name).parts else info)
    if job.exists():
        shutil.rmtree(job)
    summary['job_state_cleaned'] = True
    summary['loopback_tc_cleaned'] = True
    serialized = json.dumps(summary, indent=2) + '\n'
    (report / 'summary.json').write_text(serialized)
    # The private per-run directory retains raw evidence; the runner sees only
    # the sanitized summary in the root-owned, group-readable log parent.
    temporary = LOGS / '.latest-summary.tmp'
    temporary.write_text(serialized)
    os.chown(temporary, 0, grp.getgrnam('ecapture-runner').gr_gid)
    temporary.chmod(0o640)
    temporary.replace(LOGS / 'latest-summary.json')
    current.unlink()
    print(f'E2E summary: {summary["passed"]} passed, {summary["failed"]} failed; task state cleaned.')


if __name__ == '__main__':
    main()
