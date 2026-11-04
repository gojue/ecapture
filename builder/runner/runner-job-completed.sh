#!/usr/bin/env bash
# Install outside the checkout as a root-owned file.
set -euo pipefail

sudo -n /usr/bin/python3 -I /etc/ecapture-runner/job-cleanup.py e2e
timeout 120s /usr/bin/python3 /etc/ecapture-runner/job-cleanup.py end
