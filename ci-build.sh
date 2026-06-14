#!/usr/bin/env bash
# CI / local test runner for rspamd-dcc-razor-pyzor.
#
# Stages (each skipped with a notice if its tool is absent, so this runs in a
# minimal env; CI installs the tools so nothing is skipped there):
#   lint   — shellcheck (shell) + ruff (python) + luacheck (lua) + py_compile
#   unit   — pytest tests/ (backends mocked; no DCC/Razor/Pyzor needed)
#   docker — build the image, run it, smoke-test the HTTP API, clean up
#            (needs docker + the eilandert/debian-base image + deb.myguard.nl).
#            Enabled when docker is present; force-skip with DRP_CI_DOCKER=0.
#
# Usage:  ./ci-build.sh [lint|unit|docker|all]   (default: all)
set -euo pipefail
cd "$(dirname "$0")"

want="${1:-all}"
rc=0
note() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
skip() { printf '   (skip: %s)\n' "$*"; }

run_lint() {
    note "lint"
    if command -v shellcheck >/dev/null; then
        # SC1091: drp.env is sourced at runtime; not available to follow here.
        shellcheck -s sh -e SC1091 healthcheck.sh \
            root/etc/s6-overlay/scripts/init-bootstrap.sh \
            root/etc/s6-overlay/s6-rc.d/shim/run \
            dovecot/drp-report || rc=1
    else skip "shellcheck not installed"; fi

    if command -v ruff >/dev/null; then
        ruff check shim/ tests/ || rc=1
    else skip "ruff not installed"; fi
    python3 -m py_compile shim/spamcheck_shim.py tests/test_shim.py || rc=1

    if command -v luacheck >/dev/null; then
        luacheck rspamd/plugins/ || rc=1
    else skip "luacheck not installed"; fi
}

run_unit() {
    note "unit (pytest)"
    if command -v pytest >/dev/null; then
        pytest -q tests/ || rc=1
    elif python3 -c 'import pytest' 2>/dev/null; then
        python3 -m pytest -q tests/ || rc=1
    else skip "pytest not installed"; fi
}

run_docker() {
    note "docker integration"
    if [ "${DRP_CI_DOCKER:-1}" = "0" ] || ! command -v docker >/dev/null; then
        skip "docker disabled or absent"; return
    fi
    local img="drp-ci:test" name="drp-ci-$$" tok="ci-token-$$"
    docker build -f Dockerfile-deb -t "$img" . || { rc=1; return; }
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" -e SHIM_TOKEN="$tok" "$img" >/dev/null
    trap 'docker rm -f "$name" >/dev/null 2>&1 || true' RETURN

    # wait for health
    for _ in $(seq 1 30); do
        [ "$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null)" = healthy ] && break
        sleep 1
    done
    local h; h=$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null || echo none)
    [ "$h" = healthy ] || { echo "FAIL: container not healthy ($h)"; rc=1; }

    # shim must run as non-root
    docker exec "$name" sh -c 'id drp >/dev/null' || { echo "FAIL: no drp user"; rc=1; }

    _ec() { docker exec "$name" sh -c "$1"; }
    local c
    c=$(_ec "printf x | curl -s -o /dev/null -w '%{http_code}' --data-binary @- http://127.0.0.1:8077/check")
    [ "$c" = 401 ] || { echo "FAIL: no-token /check = $c (want 401)"; rc=1; }
    c=$(_ec "printf 'Subject: t\n\nhi\n' | curl -s -o /dev/null -w '%{http_code}' -H 'X-DRP-Token: $tok' --data-binary @- http://127.0.0.1:8077/check")
    [ "$c" = 200 ] || { echo "FAIL: token /check = $c (want 200)"; rc=1; }
    c=$(_ec "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8077/health")
    [ "$c" = 200 ] || { echo "FAIL: /health = $c"; rc=1; }
    echo "   docker integration checks done"
}

case "$want" in
    lint) run_lint ;;
    unit) run_unit ;;
    docker) run_docker ;;
    all) run_lint; run_unit; run_docker ;;
    *) echo "usage: $0 [lint|unit|docker|all]" >&2; exit 2 ;;
esac

note "result: $([ $rc -eq 0 ] && echo PASS || echo FAIL)"
exit $rc
