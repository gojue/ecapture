#!/bin/bash
# Install root-owned at /usr/local/libexec/ecapture-e2e-job.
set -euo pipefail
[[ "$EUID" == 0 && "$#" == 0 ]] || { echo 'Run as root without arguments' >&2; exit 1; }
export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[[ "$(uname -s)/$(uname -m)" == Linux/loongarch64 ]] || {
    echo 'This E2E job requires Linux/loongarch64' >&2; exit 1;
}
kernel="$(uname -r | cut -d- -f1)"
[[ "$(printf '%s\n' 6.6 "$kernel" | sort -V | head -n1)" == 6.6 ]] || {
    echo 'This E2E job requires kernel >= 6.6' >&2; exit 1;
}
umask 0077
base=/var/lib/ecapture-e2e
job="$base/job-state"
mkdir -p "$base"
exec 9>"$base/run.lock"
flock -n 9 || { echo 'An E2E run is already active' >&2; exit 1; }
cleanup() { /usr/bin/python3 -I /etc/ecapture-runner/job-cleanup.py e2e; }
cleanup
finish() {
    local status=$?
    trap - EXIT
    cleanup || status=1
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT TERM
# Do not alter loopback TC state that predates this dedicated test run.
/usr/sbin/tc -j qdisc show dev lo | /usr/bin/python3 -I -c '
import json,sys
if any(q["kind"] in ("clsact", "ingress") for q in json.load(sys.stdin)):
    sys.exit("Loopback already has a TC ingress/clsact qdisc; refusing to replace it")
'
touch "$base/owns-loopback-clsact"
mkdir -p "$job/home" "$job/tmp" "$job/cache" "$job/go"
artifacts="$(mktemp -d /var/log/ecapture-e2e/run.XXXXXXXX)"
cd /var/lib/ecapture-runner/_work/ecapture/ecapture
# Only trusted repository refs enter this dedicated runner. Execute the checked
# out revision as hosted jobs do; do not forward tokens or caller settings.
# Background + wait lets Bash run its cancellation trap immediately.
/usr/bin/setpriv --no-new-privs /usr/bin/env -i \
    PATH="$PATH" HOME="$job/home" TMPDIR="$job/tmp" TMP="$job/tmp" TEMP="$job/tmp" \
    GOCACHE="$job/cache" GOPATH="$job/go" GOMODCACHE="$job/go/pkg/mod" \
    GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct GOTOOLCHAIN=local \
    RUNNER_TRACKING_ID=ecapture-root-e2e ECAPTURE_BINARY="$PWD/bin/ecapture" \
    E2E_ARTIFACT_ROOT="$artifacts" E2E_KEEP_ARTIFACTS=1 \
    E2E_MODULES='tls gotls' E2E_MODES='text keylog pcapng' E2E_STRESS=1 \
    /usr/bin/timeout --signal=TERM --kill-after=30s 25m \
    /bin/bash test/e2e/run_e2e.sh 9>&- &
wait "$!"
