#!/usr/bin/env bash
# Install root-owned at /usr/local/libexec/ecapture-e2e-job.
set -euo pipefail
[[ "$EUID" == 0 ]] || { echo 'E2E service requires root' >&2; exit 1; }
[[ "$(uname -s)/$(uname -m)" == Linux/loongarch64 ]] || {
    echo 'This E2E service requires Linux/loongarch64' >&2; exit 1;
}
kernel="$(uname -r | cut -d- -f1)"
[[ "$(printf '%s\n' 6.6 "$kernel" | sort -V | head -n1)" == 6.6 ]] || {
    echo 'This E2E service requires kernel >= 6.6' >&2; exit 1;
}
umask 0077
base=/var/lib/ecapture-e2e
logs=/var/log/ecapture-e2e
job="$base/job-state"
mkdir -p "$base"
if [[ -f "$base/current" ]]; then
    SERVICE_RESULT=interrupted /usr/bin/python3 /usr/local/libexec/ecapture-e2e-finish.py
fi
# Do not alter loopback TC state that predates this dedicated test run.
/usr/sbin/tc -j qdisc show dev lo | /usr/bin/python3 -c '
import json,sys
if any(q["kind"] in ("clsact", "ingress") for q in json.load(sys.stdin)):
    sys.exit("Loopback already has a TC ingress/clsact qdisc; refusing to replace it")
'
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$logs/$run_id" "$job/home" "$job/tmp" "$job/cache" "$job/go" "$job/artifacts"
printf '%s\n' "$run_id" > "$base/current"
exec > "$logs/$run_id/stdout.log" 2>&1
bundle=/opt/ecapture-e2e
modules='tls gotls gnutls'
stress=0
if [[ -e /var/lib/ecapture-runner/job-state/e2e-input/request.json ]]; then
    touch "$job/ci-requested"
    /usr/bin/python3 /usr/local/libexec/ecapture-e2e-prepare.py
    bundle="$job/bundle"
    modules='tls gotls'
    stress=1
fi
touch "$base/owns-loopback-clsact"
export HOME="$job/home" TMPDIR="$job/tmp" TMP="$job/tmp" TEMP="$job/tmp"
export GOCACHE="$job/cache" GOPATH="$job/go" GOMODCACHE="$job/go/pkg/mod"
export GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct GOTOOLCHAIN=local
export ECAPTURE_BINARY="$bundle/artifact/ecapture"
export E2E_ARTIFACT_ROOT="$job/artifacts" E2E_KEEP_ARTIFACTS=1
export E2E_MODULES="$modules" E2E_MODES='text keylog pcapng' E2E_STRESS="$stress"
cd "$bundle/source"
exec /usr/bin/timeout --signal=TERM --kill-after=30s 25m /bin/bash test/e2e/run_e2e.sh
