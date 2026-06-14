#!/bin/sh
# s6 oneshot: one-time setup for the standalone DRP backend. Must exit 0 before
# the longruns (dccifd, shim) start. Backend setup failures are non-fatal — a
# missing network just degrades that filter; only a broken container would block.
set -eu

echo "[DRP] standalone DCC/Razor/Pyzor backend — docs: https://github.com/eilandert/rspamd-dcc-razor-pyzor"

# Timezone
if [ -n "${TZ:-}" ]; then
    rm -f /etc/timezone /etc/localtime
    echo "${TZ}" > /etc/timezone
    ln -sf "/usr/share/zoneinfo/${TZ}" /etc/localtime
fi

# ---------------------------------------------------------------------------
# DCC (from the `dcc` package): dccifd needs a /var/dcc home with a server map
# and the /run/dcc socket dir (normally created by tmpfiles, which doesn't run
# in a container). Create the map on first run if missing. Never fatal — DCC
# degrades to "unknown".
# ---------------------------------------------------------------------------
if command -v cdcc >/dev/null 2>&1; then
    mkdir -p /run/dcc
    chown dcc:dcc /run/dcc 2>/dev/null || true
    chown -R dcc:dcc /var/dcc 2>/dev/null || true
    if [ ! -f /var/dcc/map ]; then
        echo "[DRP] DCC: creating server map"
        su -s /bin/sh dcc -c 'cdcc "new map; add dcc.dcc-servers.net"' \
            2>/dev/null || true
    fi
fi

# ---------------------------------------------------------------------------
# Razor: per-host identity + server discovery on first run (RAZORHOME).
# Idempotent: razor-admin -create is a no-op once the config exists.
# ---------------------------------------------------------------------------
export RAZORHOME=/var/lib/razor
if command -v razor-admin >/dev/null 2>&1; then
    mkdir -p "$RAZORHOME"
    if [ ! -f "$RAZORHOME/razor-agent.conf" ]; then
        echo "[DRP] Razor: creating identity + discovering servers"
        razor-admin -home="$RAZORHOME" -create   >/dev/null 2>&1 || true
        razor-admin -home="$RAZORHOME" -discover  >/dev/null 2>&1 || true
        razor-admin -home="$RAZORHOME" -register  >/dev/null 2>&1 || true
    fi
fi

# ---------------------------------------------------------------------------
# Pyzor: discover the public server list into PYZOR_HOME (first run only).
# ---------------------------------------------------------------------------
export PYZOR_HOME=/var/lib/pyzor
if command -v pyzor >/dev/null 2>&1; then
    mkdir -p "$PYZOR_HOME"
    if [ ! -f "$PYZOR_HOME/servers" ]; then
        echo "[DRP] Pyzor: discovering servers"
        pyzor --homedir "$PYZOR_HOME" discover >/dev/null 2>&1 || true
    fi
fi

echo "[DRP] init-bootstrap complete; handing off to s6-supervised services."
exit 0
