#!/usr/bin/env bash
# Install outside the checkout as a root-owned file. See docs/loong64-support.md#dedicated-runner.
set -euo pipefail

deny() {
    echo '::error::This runner only accepts the approved native Loong64 workflow on trusted branches.' >&2
    exit 1
}

[[ "${GITHUB_REPOSITORY:-}" == gojue/ecapture ]] || deny
case "${GITHUB_EVENT_NAME:-}" in
    push|workflow_dispatch) ;;
    *) deny ;;
esac
case "${GITHUB_REF:-}" in
    refs/heads/master|refs/heads/v2|refs/heads/v1) ;;
    *) deny ;;
esac
[[ "${GITHUB_WORKFLOW_REF:-}" == "gojue/ecapture/.github/workflows/self-hosted-loong64.yml@${GITHUB_REF}" ]] || deny

sudo -n /usr/bin/systemctl stop ecapture-e2e.service
timeout 120s /usr/bin/python3 /etc/ecapture-runner/job-cleanup.py start
echo 'Trusted native Loong64 workflow accepted.'
