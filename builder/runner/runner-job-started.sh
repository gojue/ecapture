#!/usr/bin/env bash
# Install outside the checkout as a root-owned file. See docs/loong64-support.md#dedicated-runner.
set -euo pipefail

deny() {
    echo '::error::This runner only accepts approved Loong64 jobs from trusted repository refs.' >&2
    exit 1
}

[[ "${GITHUB_REPOSITORY:-}" == gojue/ecapture ]] || deny
case "${GITHUB_WORKFLOW_REF:-}" in
    "gojue/ecapture/.github/workflows/self-hosted-loong64.yml@${GITHUB_REF:-}")
        [[ "${GITHUB_JOB:-}" == tls-unit ]] || deny
        [[ "${GITHUB_EVENT_NAME:-}" != pull_request ]] || deny
        ;;
    "gojue/ecapture/.github/workflows/e2e.yml@${GITHUB_REF:-}")
        [[ "${GITHUB_JOB:-}" == loong64-e2e ]] || deny
        ;;
    *) deny ;;
esac
case "${GITHUB_EVENT_NAME:-}" in
    push|workflow_dispatch)
        case "${GITHUB_REF:-}" in
            refs/heads/master|refs/heads/v2|refs/heads/v1) ;;
            *) deny ;;
        esac
        ;;
    pull_request)
        # Reject forks before checkout or build. The root E2E service independently
        # verifies the live run/job/PR through GitHub before executing its snapshot.
        /usr/bin/python3 -I - <<'PY' || deny
import json, os
with open(os.environ['GITHUB_EVENT_PATH']) as file:
    event = json.load(file)
pr = event['pull_request']
if not (event['action'] in ('opened', 'synchronize', 'reopened')
        and pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == 'gojue/ecapture'
        and pr['base']['ref'] in ('master', 'v2', 'v1')
        and os.environ['GITHUB_REF'] == f"refs/pull/{event['number']}/merge"):
    raise SystemExit('Untrusted pull request')
PY
        ;;
    *) deny ;;
esac

sudo -n /usr/bin/systemctl stop ecapture-e2e.service
timeout 120s /usr/bin/python3 /etc/ecapture-runner/job-cleanup.py start
echo 'Trusted native Loong64 workflow accepted.'
