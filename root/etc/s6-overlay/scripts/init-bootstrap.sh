#!/bin/sh
# s6 oneshot: one-time container setup. Must exit 0 before the longruns
# (dccifd, shim, rspamd) start. A fatal config error aborts the boot (S6
# stage2 fail -> container stops) so a broken image never reports healthy.
set -eu

echo "[DRP] rspamd DCC/Razor/Pyzor image — docs: https://github.com/eilandert/rspamd-dcc-razor-pyzor"

# Timezone
if [ -n "${TZ:-}" ]; then
    rm -f /etc/timezone /etc/localtime
    echo "${TZ}" > /etc/timezone
    ln -sf "/usr/share/zoneinfo/${TZ}" /etc/localtime
fi

# ---------------------------------------------------------------------------
# rspamd config: first-run copy of the baked defaults, every-boot refresh of
# our plugin + local.d/override.d drop-ins (so a bind-mounted /etc/rspamd still
# gets the collaborative-filter wiring).
# ---------------------------------------------------------------------------
if [ ! -f /etc/rspamd/rspamd.conf ]; then
    echo "[DRP] seeding /etc/rspamd from defaults"
    cp -r /etc/rspamd.orig/* /etc/rspamd/
fi
mkdir -p /etc/rspamd/local.d /etc/rspamd/override.d /etc/rspamd/plugins
cp -f /opt/drp/rspamd/plugins/*.lua     /etc/rspamd/plugins/
cp -f /opt/drp/rspamd/local.d/*.conf    /etc/rspamd/local.d/
cp -f /opt/drp/rspamd/override.d/*.inc  /etc/rspamd/override.d/

# Load our plugin: append a single include to rspamd.local.lua (idempotent).
LOCAL_LUA=/etc/rspamd/rspamd.local.lua
touch "$LOCAL_LUA"
if ! grep -q "dcc_razor_pyzor.lua" "$LOCAL_LUA" 2>/dev/null; then
    echo 'dofile("/etc/rspamd/plugins/dcc_razor_pyzor.lua")' >> "$LOCAL_LUA"
fi

mkdir -p /var/log/rspamd /var/lib/rspamd /var/run/rspamd

# ---------------------------------------------------------------------------
# DCC: dccifd needs a working /var/dcc home with fetched server list. The image
# build ran `cdcc new map`; refresh the map id/IPs only if missing (offline
# builds may skip it). Never fatal — DCC degrades to "unknown".
# ---------------------------------------------------------------------------
if [ -x /var/dcc/bin/cdcc ]; then
    chown -R dcc:dcc /var/dcc 2>/dev/null || true
    if [ ! -f /var/dcc/map ]; then
        echo "[DRP] DCC: creating server map"
        su -s /bin/sh dcc -c '/var/dcc/bin/cdcc "new map; add dcc.dcc-servers.net"' \
            2>/dev/null || true
    fi
fi

# ---------------------------------------------------------------------------
# Razor: needs a per-host identity + server discovery on first run. Stored in
# /var/lib/razor (RAZORHOME). Idempotent: razor-admin -create is a no-op if the
# config already exists.
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

# rspamd config validation gate — FATAL on failure.
echo "[DRP] validating rspamd config (rspamadm configtest)"
if ! rspamadm configtest >/dev/null 2>&1; then
    echo "[DRP] ---> FATAL: rspamadm configtest failed:" >&2
    rspamadm configtest 2>&1 | sed 's/^/[DRP] ---> /' >&2
    exit 1
fi

echo "[DRP] init-bootstrap complete; handing off to s6-supervised services."
exit 0
