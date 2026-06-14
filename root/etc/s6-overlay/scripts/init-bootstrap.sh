#!/bin/sh
# s6 oneshot: one-time setup for the standalone DRP backend. Must exit 0 before
# the longruns (dccifd, shim) start. Backend setup failures are non-fatal — a
# missing network just degrades that filter; only a broken container would block.
#
# Identities (Razor account, DCC client-id, Pyzor account) can be supplied via
# environment so a known/shared identity survives volume resets and can be reused
# across instances. Precedence for each: explicit env > existing file in the
# volume > anonymous auto-registration. Every credential var also honours a
# "<VAR>_FILE" form (Docker/compose secrets): the value is read from that path.
set -eu

echo "[DRP] standalone DCC/Razor/Pyzor backend — docs: https://github.com/eilandert/rspamd-dcc-razor-pyzor"

# resolve VAR: echo $VAR, or the contents of the file named by ${VAR}_FILE.
# Usage: val="$(resolve RAZOR_REGISTER_PASS)"
resolve() {
    _v="$1"
    eval "_file=\${${_v}_FILE:-}"
    if [ -n "${_file}" ] && [ -r "${_file}" ]; then
        cat "${_file}"
        return 0
    fi
    eval "printf '%s' \"\${${_v}:-}\""
}

# Timezone
if [ -n "${TZ:-}" ]; then
    rm -f /etc/timezone /etc/localtime
    echo "${TZ}" > /etc/timezone
    ln -sf "/usr/share/zoneinfo/${TZ}" /etc/localtime
fi

# ---------------------------------------------------------------------------
# DCC (from the `dcc` package): dccifd needs a /var/dcc home with a server map
# and the /run/dcc socket dir (normally created by tmpfiles, which doesn't run
# in a container). Identity: DCC_IDS (raw /var/dcc/ids content) takes priority,
# else DCC_CLIENT_ID (+ DCC_CLIENT_PASSWD) registers a client-id via cdcc, else
# DCC stays anonymous. Never fatal — DCC degrades to "unknown".
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
# Razor (RAZORHOME). Identity: RAZOR_IDENTITY (raw identity-file content) takes
# priority, else RAZOR_REGISTER_USER (+ RAZOR_REGISTER_PASS) registers/links that
# account, else an anonymous identity is auto-registered on first boot.
# Idempotent: skipped once an identity already exists in the volume.
# ---------------------------------------------------------------------------
export RAZORHOME=/var/lib/razor
if command -v razor-admin >/dev/null 2>&1; then
    mkdir -p "$RAZORHOME"
    [ -f "$RAZORHOME/razor-agent.conf" ] || \
        razor-admin -home="$RAZORHOME" -create >/dev/null 2>&1 || true
    [ -f "$RAZORHOME/servers.catalogue.lst" ] || \
        razor-admin -home="$RAZORHOME" -discover >/dev/null 2>&1 || true

    RAZOR_IDENTITY="$(resolve RAZOR_IDENTITY)"
    RAZOR_REGISTER_USER="$(resolve RAZOR_REGISTER_USER)"
    RAZOR_REGISTER_PASS="$(resolve RAZOR_REGISTER_PASS)"

    if [ -n "${RAZOR_IDENTITY}" ]; then
        echo "[DRP] Razor: installing provided identity"
        printf '%s\n' "${RAZOR_IDENTITY}" > "$RAZORHOME/identity"
        chmod 0600 "$RAZORHOME/identity"
    elif [ ! -f "$RAZORHOME/identity" ]; then
        if [ -n "${RAZOR_REGISTER_USER}" ]; then
            echo "[DRP] Razor: registering account ${RAZOR_REGISTER_USER}"
            razor-admin -home="$RAZORHOME" -register \
                -user="${RAZOR_REGISTER_USER}" -pass="${RAZOR_REGISTER_PASS}" \
                >/dev/null 2>&1 || true
        else
            echo "[DRP] Razor: registering anonymous identity"
            razor-admin -home="$RAZORHOME" -register >/dev/null 2>&1 || true
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Pyzor (PYZOR_HOME). Pyzor is anonymous against the public server by default.
# PYZOR_SERVERS overrides the server list; PYZOR_ACCOUNT supplies an accounts
# file for authenticated reporting. Otherwise discover the public list once.
# ---------------------------------------------------------------------------
export PYZOR_HOME=/var/lib/pyzor
if command -v pyzor >/dev/null 2>&1; then
    mkdir -p "$PYZOR_HOME"

    PYZOR_SERVERS="$(resolve PYZOR_SERVERS)"
    PYZOR_ACCOUNT="$(resolve PYZOR_ACCOUNT)"

    if [ -n "${PYZOR_SERVERS}" ]; then
        echo "[DRP] Pyzor: installing provided server list"
        printf '%s\n' "${PYZOR_SERVERS}" > "$PYZOR_HOME/servers"
    elif [ ! -f "$PYZOR_HOME/servers" ]; then
        echo "[DRP] Pyzor: discovering servers"
        pyzor --homedir "$PYZOR_HOME" discover >/dev/null 2>&1 || true
    fi

    if [ -n "${PYZOR_ACCOUNT}" ]; then
        echo "[DRP] Pyzor: installing provided accounts file"
        printf '%s\n' "${PYZOR_ACCOUNT}" > "$PYZOR_HOME/accounts"
        chmod 0600 "$PYZOR_HOME/accounts"
    fi
fi

echo "[DRP] init-bootstrap complete; handing off to s6-supervised services."
exit 0
