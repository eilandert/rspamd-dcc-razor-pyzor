#!/usr/bin/env bash
# CI / local test runner for rspamd-dcc-razor-pyzor.
#
# The backend is a static Go binary (gozer) under docker/ that speaks Razor
# (gazor) and Pyzor (gyzor) in-process and runs DCC via dccproc. Deps are
# vendored, so all Go stages build offline.
#
# Stages (each skipped with a notice if its tool is absent, so this runs in a
# minimal env; CI installs the tools so nothing is skipped there):
#   lint   — shellcheck (shell) + gofmt + go vet + luacheck (rspamd lua plugin)
#   unit   — go test (HTTP layer + config + cache + DCC parse; razor/pyzor
#            networks are not contacted — gazor/gyzor have their own suites)
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

# Run go in the module dir (docker/) regardless of the caller's cwd.
go_() { (cd docker && go "$@"); }

run_lint() {
    note "lint"
    if command -v shellcheck >/dev/null; then
        # SC1091: env files are sourced at runtime; not available to follow here.
        shellcheck -s sh -e SC1091 docker/healthcheck.sh \
            docker/root/etc/s6-overlay/scripts/init-bootstrap.sh \
            docker/root/etc/s6-overlay/s6-rc.d/gozer/run \
            dovecot/drp-report || rc=1
    else skip "shellcheck not installed"; fi

    if command -v go >/dev/null; then
        local unformatted
        unformatted=$(cd docker && gofmt -l cmd internal)
        if [ -n "$unformatted" ]; then
            echo "FAIL: gofmt needed on:"; echo "$unformatted"; rc=1
        fi
        go_ vet ./... || rc=1
    else skip "go not installed"; fi

    if command -v luacheck >/dev/null; then
        luacheck rspamd/plugins/ || rc=1
    else skip "luacheck not installed"; fi
}

run_unit() {
    note "unit (go test)"
    if command -v go >/dev/null; then
        go_ test ./... || rc=1
    else skip "go not installed"; fi
}

run_docker() {
    note "docker integration"
    if [ "${DRP_CI_DOCKER:-1}" = "0" ] || ! command -v docker >/dev/null; then
        skip "docker disabled or absent"; return
    fi
    local img="drp-ci:test" name="drp-ci-$$" tok="ci-token-$$"
    docker build -f docker/Dockerfile-deb -t "$img" docker/ || { rc=1; return; }
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" -e GOZER_TOKEN="$tok" "$img" >/dev/null
    trap 'docker rm -f "$name" >/dev/null 2>&1 || true' RETURN

    # wait for health
    for _ in $(seq 1 30); do
        [ "$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null)" = healthy ] && break
        sleep 1
    done
    local h; h=$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null || echo none)
    [ "$h" = healthy ] || { echo "FAIL: container not healthy ($h)"; rc=1; }

    # gozer must run as non-root, and be the Go binary (not python/perl)
    docker exec "$name" sh -c 'id drp >/dev/null' || { echo "FAIL: no drp user"; rc=1; }
    docker exec "$name" gozer version >/dev/null \
        || { echo "FAIL: gozer binary missing/broken"; rc=1; }
    # the image must no longer ship the per-message fork tooling: python3 (the
    # old Python implementation + pyzor) gone, and neither the razor nor pyzor apt package
    # installed. perl-base stays — it is base-essential, unrelated to razor.
    docker exec "$name" sh -c '! command -v python3 >/dev/null' \
        || { echo "FAIL: python3 still present (should be gone)"; rc=1; }
    docker exec "$name" sh -c 'for p in razor pyzor; do dpkg -s "$p" >/dev/null 2>&1 && exit 1; done; exit 0' \
        || { echo "FAIL: razor/pyzor apt package still installed"; rc=1; }

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
