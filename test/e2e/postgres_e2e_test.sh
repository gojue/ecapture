#!/usr/bin/env bash
# Strict, read-only PostgreSQL integration against an existing local database.

set -euo pipefail

E2E_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/e2e/linux/common_config_test.sh
source "$E2E_SCRIPT_DIR/linux/common_config_test.sh"

PSQL_PID=""
SQL_FD_OPEN=0
POSTGRES_BACKEND_PID=""

stop_postgres_client() {
    local attempt status=0
    if ((SQL_FD_OPEN)); then
        printf '\\q\n' >&3 || true
        exec 3>&-
        SQL_FD_OPEN=0
    fi
    [[ -n "$PSQL_PID" ]] || return 0
    for ((attempt = 0; attempt < 50; attempt++)); do
        kill -0 "$PSQL_PID" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$PSQL_PID" 2>/dev/null; then
        log_error "psql did not exit after closing its session"
        kill -TERM "$PSQL_PID" 2>/dev/null || true
        status=1
    fi
    wait "$PSQL_PID" 2>/dev/null || status=1
    PSQL_PID=""
    return "$status"
}

cleanup_postgres() {
    local status="$1"
    stop_postgres_client || status=1
    common_config_cleanup "$status"
}
trap 'status=$?; cleanup_postgres "$status"; exit $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

case_postgres_query() {
    prepare_common_case postgres || return 1
    local os_user="${E2E_POSTGRES_OS_USER:-postgres}"
    local database="${E2E_POSTGRES_DATABASE:-postgres}" backend_binary attempt
    # The backend PID is meaningful only for a local Unix-socket connection.
    if [[ -n "${PGSERVICE:-}" ]]; then
        log_error "PostgreSQL E2E does not accept PGSERVICE; use an explicit local Unix socket"
        return 1
    fi
    if [[ -n "${PGHOSTADDR:-}" || ( -n "${PGHOST:-}" && "${PGHOST}" != /* ) || "${PGHOST:-}" == *,* ]]; then
        log_error "PostgreSQL E2E requires a local Unix socket (PGHOST unset or one absolute socket directory)"
        return 1
    fi
    if [[ "$database" == *'='* || "$database" == *'://'* ]]; then
        log_error "E2E_POSTGRES_DATABASE must be a database name, not a connection string"
        return 1
    fi
    id "$os_user" >/dev/null 2>&1 || { log_error "PostgreSQL OS user does not exist: $os_user"; return 1; }
    mkfifo "$CASE_DIR/queries" || return 1
    # Keep one session open so discovery and the captured query use the same backend.
    exec 3<>"$CASE_DIR/queries"
    SQL_FD_OPEN=1
    timeout --signal=TERM --kill-after=2s 60s runuser -u "$os_user" -- env PGCONNECT_TIMEOUT=5 \
        psql -X -qAt -w --set=ON_ERROR_STOP=1 --dbname "$database" \
        <"$CASE_DIR/queries" >"$CASE_DIR/workload.log" 2>"$CASE_DIR/psql.stderr.log" 3>&- &
    PSQL_PID=$!
    printf 'SELECT pg_backend_pid();\n' >&3
    for ((attempt = 0; attempt < 100; attempt++)); do
        POSTGRES_BACKEND_PID="$(sed -n '1p' "$CASE_DIR/workload.log")"
        [[ "$POSTGRES_BACKEND_PID" =~ ^[1-9][0-9]*$ ]] && break
        if ! kill -0 "$PSQL_PID" 2>/dev/null; then
            log_error "psql could not establish the local database session; see $CASE_DIR/psql.stderr.log"
            return 1
        fi
        sleep 0.1
    done
    [[ "$POSTGRES_BACKEND_PID" =~ ^[1-9][0-9]*$ ]] || { log_error "No PostgreSQL backend PID received"; return 1; }
    backend_binary="$(readlink -f "/proc/$POSTGRES_BACKEND_PID/exe")" || return 1
    [[ -x "$backend_binary" ]] || { log_error "Local PostgreSQL backend binary is unavailable"; return 1; }
    start_common_capture postgres postgres --postgres "$backend_binary" --pid "$POSTGRES_BACKEND_PID" || return 1
    # No DDL/DML, temporary tables, or database cleanup: only a literal SELECT.
    printf "SELECT '%s';\n" "$CASE_TOKEN" >&3
    wait_for_file_contains "$CASE_DIR/workload.log" "$CASE_TOKEN" "successful PostgreSQL SELECT" || return 1
    stop_postgres_client || return 1
    sleep 1
    stop_common_capture || return 1
    assert_common_case postgres || return 1
    assert_file_contains "$EVENT_FILE" "PID=$POSTGRES_BACKEND_PID " "actual PostgreSQL backend PID"
}

main() {
    setup_common_config_suite || return 1
    # Older kernels cannot apply the PID filter that isolates our own backend.
    version_at_least "$(uname -r)" 5.2 || {
        log_error "PostgreSQL E2E requires kernel 5.2+ for backend PID isolation"
        return 1
    }
    require_command psql || return 1
    require_command runuser || return 1
    require_command readlink || return 1
    run_case "linux/postgres/read-only-query-eventaddr-isolation" case_postgres_query
    print_summary "Linux PostgreSQL E2E"
}

main "$@"
