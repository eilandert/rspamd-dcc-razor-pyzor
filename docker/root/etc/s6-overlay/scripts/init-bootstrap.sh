#!/bin/sh
# s6 oneshot: one-time setup for the standalone DRP backend. Must exit 0 before
# the gozer longrun starts. Backend setup failures are non-fatal — a missing
# network just degrades that filter; only a broken container would block.
#
# Identities (Razor account, DCC client-id, Pyzor account) can be supplied via
# environment so a known/shared identity survives volume resets and can be reused
# across instances. Precedence for each: explicit env > existing file in the
# volume > anonymous auto-registration. Every credential var also honours a
# "<VAR>_FILE" form (Docker/compose secrets): the value is read from that path.
#
# gozer runs as the unprivileged `drp` user, so the Razor/Pyzor homes are
# chowned to drp here. DCC's dccproc is set-UID dcc and uses /var/dcc directly.
set -eu

echo "[DRP] standalone DCC/Razor/Pyzor backend — docs: https://github.com/eilandert/rspamd-dcc-razor-pyzor"

# resolve VAR: echo $VAR, or the contents of the file named by ${VAR}_FILE.
resolve() {
    _v="$1"
    eval "_file=\${${_v}_FILE:-}"
    if [ -n "${_file}" ] && [ -r "${_file}" ]; then
        cat "${_file}"
        return 0
    fi
    eval "printf '%s' \"\${${_v}:-}\""
}

# Timezone (tolerant: /etc is read-only when the rootfs is read_only).
if [ -n "${TZ:-}" ]; then
    { rm -f /etc/timezone /etc/localtime \
        && echo "${TZ}" > /etc/timezone \
        && ln -sf "/usr/share/zoneinfo/${TZ}" /etc/localtime; } 2>/dev/null \
        || echo "[DRP] TZ: /etc not writable (read-only rootfs?); skipping" >&2
fi

# ---------------------------------------------------------------------------
# DCC (from the `dcc` package): dccproc (set-UID dcc) queries the DCC servers
# directly using /var/dcc/map. Identity: DCC_IDS (raw /var/dcc/ids content) takes
# priority, else DCC_CLIENT_ID (+ DCC_CLIENT_PASSWD) registers a client-id via
# cdcc, else DCC stays anonymous. Never fatal — DCC degrades to "unknown".
# ---------------------------------------------------------------------------
if command -v cdcc >/dev/null 2>&1; then
    mkdir -p /run/dcc
    chown dcc:dcc /run/dcc 2>/dev/null || true

    DCC_IDS="$(resolve DCC_IDS)"
    DCC_CLIENT_ID="$(resolve DCC_CLIENT_ID)"
    DCC_CLIENT_PASSWD="$(resolve DCC_CLIENT_PASSWD)"

    if [ -n "${DCC_IDS}" ]; then
        echo "[DRP] DCC: installing provided ids file"
        printf '%s\n' "${DCC_IDS}" > /var/dcc/ids
        chmod 0600 /var/dcc/ids
    elif [ -n "${DCC_CLIENT_ID}" ]; then
        echo "[DRP] DCC: registering client-id ${DCC_CLIENT_ID}"
        if [ -n "${DCC_CLIENT_PASSWD}" ]; then
            su -s /bin/sh dcc -c "cdcc \"new id ${DCC_CLIENT_ID}; id ${DCC_CLIENT_ID} ${DCC_CLIENT_PASSWD}\"" \
                2>/dev/null || true
        else
            su -s /bin/sh dcc -c "cdcc \"new id ${DCC_CLIENT_ID}\"" 2>/dev/null || true
        fi
    fi

    chown -R dcc:dcc /var/dcc 2>/dev/null || true
    if [ ! -f /var/dcc/map ]; then
        echo "[DRP] DCC: creating server map"
        su -s /bin/sh dcc -c 'cdcc "new map; add dcc.dcc-servers.net"' \
            2>/dev/null || true
    fi
fi

# ---------------------------------------------------------------------------
# Razor (RAZORHOME, owned by drp). The Go backend speaks razor in-process and
# discovers catalogue/nomination servers itself, so no razor-admin -create/
# -discover is needed — only the nomination credential for /report and /revoke.
# Precedence: RAZOR_USER+RAZOR_PASS (an existing account) > a credential already
# persisted in the volume > a fresh registration (RAZOR_REGISTER_USER registers
# a named account, otherwise anonymous). The credential is written to
# RAZORHOME/gazor-identity, which gozer loads at start. Registration touches
# the network and is best-effort: on failure /check still works, only report/
# revoke wait until a credential exists.
# ---------------------------------------------------------------------------
export RAZORHOME=/var/lib/razor
mkdir -p "$RAZORHOME"
IDFILE="$RAZORHOME/gazor-identity"

RAZOR_USER="$(resolve RAZOR_USER)"
RAZOR_PASS="$(resolve RAZOR_PASS)"
RAZOR_REGISTER_USER="$(resolve RAZOR_REGISTER_USER)"
RAZOR_REGISTER_PASS="$(resolve RAZOR_REGISTER_PASS)"

if [ -n "${RAZOR_USER}" ] && [ -n "${RAZOR_PASS}" ]; then
    echo "[DRP] Razor: using provided RAZOR_USER credential"
    printf 'user=%s\npass=%s\n' "${RAZOR_USER}" "${RAZOR_PASS}" > "$IDFILE"
elif [ ! -f "$IDFILE" ]; then
    if [ -n "${RAZOR_REGISTER_USER}" ]; then
        echo "[DRP] Razor: registering account ${RAZOR_REGISTER_USER}"
        gozer razor-register --user "${RAZOR_REGISTER_USER}" \
            --pass "${RAZOR_REGISTER_PASS}" --out "$IDFILE" >/dev/null 2>&1 \
            || echo "[DRP] Razor: registration failed (report/revoke disabled until it succeeds)" >&2
    else
        echo "[DRP] Razor: registering anonymous identity"
        gozer razor-register --out "$IDFILE" >/dev/null 2>&1 \
            || echo "[DRP] Razor: registration failed (report/revoke disabled until it succeeds)" >&2
    fi
fi
{ [ -f "$IDFILE" ] && chmod 0600 "$IDFILE"; } 2>/dev/null || true
chown -R drp:drp "$RAZORHOME" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Pyzor (PYZOR_HOME, owned by drp). The Go backend reads PYZOR_HOME/servers and
# falls back to the public server (public.pyzor.org), so no `pyzor discover` is
# needed. Optional: PYZOR_SERVERS overrides the server list; PYZOR_ACCOUNT
# supplies an accounts file for authenticated reporting.
# ---------------------------------------------------------------------------
export PYZOR_HOME=/var/lib/pyzor
mkdir -p "$PYZOR_HOME"

PYZOR_SERVERS="$(resolve PYZOR_SERVERS)"
PYZOR_ACCOUNT="$(resolve PYZOR_ACCOUNT)"

if [ -n "${PYZOR_SERVERS}" ]; then
    echo "[DRP] Pyzor: installing provided server list"
    printf '%s\n' "${PYZOR_SERVERS}" > "$PYZOR_HOME/servers"
fi
if [ -n "${PYZOR_ACCOUNT}" ]; then
    echo "[DRP] Pyzor: installing provided accounts file"
    printf '%s\n' "${PYZOR_ACCOUNT}" > "$PYZOR_HOME/accounts"
    chmod 0600 "$PYZOR_HOME/accounts"
fi
chown -R drp:drp "$PYZOR_HOME" 2>/dev/null || true

if [ -z "${GOZER_TOKEN:-}" ] && [ -z "${GOZER_TOKEN_FILE:-}" ]; then
    echo "[DRP] WARNING: no GOZER_TOKEN/_FILE set — gozer will refuse all POSTs (503)." >&2
fi

echo "[DRP] init-bootstrap complete; handing off to gozer."
exit 0
