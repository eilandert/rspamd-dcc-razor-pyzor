#!/usr/bin/env python3
"""spamcheck_shim — tiny HTTP wrapper around the DCC / Razor / Pyzor CLIs.

rspamd's dcc_razor_pyzor.lua plugin POSTs a raw RFC-822 message to /check and
gets back one JSON object with the verdict of each network. The CLIs are run
out-of-process so the rspamd event loop never blocks.

Endpoints:
  POST /check   body = raw message            -> JSON verdict (see below)
  GET  /health  ->  200 "ok"  (used by the container HEALTHCHECK)

Verdict JSON:
  { "dcc":   { "action": "reject"|"accept"|"unknown", "bulk": <int|null> },
    "razor": { "hit": true|false },
    "pyzor": { "count": <int>, "wl": <int> } }

Each backend is best-effort: a missing binary, timeout, or network error yields
that backend's "unknown"/false/zero result rather than failing the whole check —
a dead Razor must not stop DCC and Pyzor from scoring.

Config via environment:
  SHIM_HOST           bind address           (default 0.0.0.0)
  SHIM_PORT           bind port              (default 8077)
  SHIM_BACKEND_TIMEOUT  per-CLI timeout secs (default 6)
  DCCPROC             path to dccproc        (default /var/dcc/bin/dccproc)
  RAZOR_CHECK         path to razor-check    (default razor-check)
  PYZOR               path to pyzor          (default pyzor)
"""
import json
import os
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("SHIM_HOST", "0.0.0.0")
PORT = int(os.environ.get("SHIM_PORT", "8077"))
TIMEOUT = float(os.environ.get("SHIM_BACKEND_TIMEOUT", "6"))
MAX_BODY = 8 * 1024 * 1024

DCCPROC = os.environ.get("DCCPROC", "/usr/bin/dccproc")
RAZOR_CHECK = os.environ.get("RAZOR_CHECK", "razor-check")
PYZOR = os.environ.get("PYZOR", "pyzor")

# dccproc -H prints an X-DCC header line, e.g.:
#   X-DCC-foo-Metrics: host 1234; bulk Body=many Fuz1=many Fuz2=100
_DCC_BULK_RE = re.compile(rb"\bbulk\b", re.IGNORECASE)
_DCC_BODY_RE = re.compile(rb"Body=(\d+|many)", re.IGNORECASE)


def _run(argv, msg):
    """Run argv feeding msg on stdin. Returns (rc, stdout, stderr) or None."""
    try:
        p = subprocess.run(
            argv, input=msg, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=TIMEOUT,
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None


def check_dcc(msg):
    # dccproc -H -Q: query only (never report/learn), emit the X-DCC header.
    r = _run([DCCPROC, "-H", "-Q"], msg)
    if r is None:
        return {"action": "unknown", "bulk": None}
    rc, out, _ = r
    bulk = None
    m = _DCC_BODY_RE.search(out)
    if m:
        token = m.group(1)
        bulk = 2 ** 31 - 1 if token.lower() == b"many" else int(token)
    # dccproc exits 1 when it would reject (bulk over the client threshold).
    action = "reject" if rc == 1 or _DCC_BULK_RE.search(out) else "accept"
    return {"action": action, "bulk": bulk}


def check_razor(msg):
    # razor-check exits 0 = spam (signature hit), 1 = not listed.
    r = _run([RAZOR_CHECK], msg)
    if r is None:
        return {"hit": False}
    rc, _, _ = r
    return {"hit": rc == 0}


def check_pyzor(msg):
    # `pyzor check` prints: <code>\t<count>\t<wl-count>  and exits 0 on a hit.
    r = _run([PYZOR, "check"], msg)
    if r is None:
        return {"count": 0, "wl": 0}
    _, out, _ = r
    line = out.decode("ascii", "replace").strip().splitlines()
    if not line:
        return {"count": 0, "wl": 0}
    parts = line[-1].split()
    try:
        # Last two integer columns are count and whitelist count.
        ints = [int(x) for x in parts if x.lstrip("-").isdigit()]
        count = ints[-2] if len(ints) >= 2 else (ints[-1] if ints else 0)
        wl = ints[-1] if len(ints) >= 2 else 0
        return {"count": count, "wl": wl}
    except (ValueError, IndexError):
        return {"count": 0, "wl": 0}


def verdict(msg):
    return {
        "dcc": check_dcc(msg),
        "razor": check_razor(msg),
        "pyzor": check_pyzor(msg),
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, "ok", "text/plain")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        if self.path != "/check":
            self._send(404, "not found", "text/plain")
            return
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_BODY:
            self._send(400, json.dumps({"error": "bad length"}))
            return
        msg = self.rfile.read(length)
        try:
            self._send(200, json.dumps(verdict(msg)))
        except Exception as e:  # never 500 the worker; log and return unknowns
            self.log_error("check failed: %s", e)
            self._send(200, json.dumps({
                "dcc": {"action": "unknown", "bulk": None},
                "razor": {"hit": False},
                "pyzor": {"count": 0, "wl": 0},
            }))

    def log_message(self, fmt, *args):  # to stderr -> s6 captures it
        import sys
        sys.stderr.write("[shim] " + (fmt % args) + "\n")


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[shim] listening on {HOST}:{PORT} (timeout={TIMEOUT}s)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
