#!/bin/sh
# Container healthcheck: the spamcheck shim must answer /health. DCC/Razor/Pyzor
# themselves are best-effort and must NOT fail the container — a dead network
# degrades scoring, not availability.
set -eu

curl -fsS --max-time 3 http://127.0.0.1:8077/health >/dev/null 2>&1 \
  || { echo "spamcheck shim not answering" >&2; exit 1; }

exit 0
