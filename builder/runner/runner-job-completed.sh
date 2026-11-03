#!/usr/bin/env bash
# Install outside the checkout as a root-owned file.
set -euo pipefail

sudo -n /usr/bin/systemctl stop ecapture-e2e.service
timeout 120s /usr/bin/python3 /etc/ecapture-runner/job-cleanup.py end
