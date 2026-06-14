#!/bin/sh
# Container healthcheck = liveness + readiness.
#   Liveness:  rspamd controller answers its stat endpoint.
#   Readiness: the spamcheck shim answers /health (so the plugin's backends are
#              reachable). DCC/Razor/Pyzor themselves are best-effort and must
#              NOT fail the container — a dead network degrades scoring, not
#              availability.
set -eu

# --- liveness: rspamd ---
rspamadm control stat >/dev/null 2>&1 \
  || curl -fsS --max-time 3 http://127.0.0.1:11334/stat >/dev/null 2>&1 \
  || { echo "rspamd not answering" >&2; exit 1; }

# --- readiness: shim ---
curl -fsS --max-time 3 http://127.0.0.1:8077/health >/dev/null 2>&1 \
  || { echo "spamcheck shim not answering" >&2; exit 1; }

exit 0
