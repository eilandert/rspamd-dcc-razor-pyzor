#!/usr/bin/env python3
"""spamcheck_shim — tiny HTTP wrapper around the DCC / Razor / Pyzor CLIs.

rspamd's dcc_razor_pyzor.lua plugin POSTs a raw RFC-822 message to /check and
gets back one JSON object with the verdict of each network. The CLIs are run
out-of-process (concurrently) so the rspamd event loop never blocks.

Endpoints (POST body = raw RFC-822 message):
  POST /check   -> JSON verdict (query only, never reports)
  POST /report  -> report as SPAM to all three networks
  POST /revoke  -> report as HAM (not-spam) where supported
  GET  /health  -> 200 "ok"  (no auth; used by the container HEALTHCHECK)

Authentication: every POST requires a shared secret, supplied as
"Authorization: Bearer <token>" or "X-DRP-Token: <token>". The token is set via
SHIM_TOKEN (or SHIM_TOKEN_FILE for Docker secrets). If no token is configured
the POST endpoints fail closed (503) — the backend never runs unauthenticated.

Verdict JSON (/check):
  { "dcc":   { "action": "reject"|"accept"|"unknown", "bulk": <int|null> },
    "razor": { "hit": true|false },
    "pyzor": { "count": <int>, "wl": <int> } }

Report JSON (/report, /revoke):
  { "dcc": true|false|null, "razor": true|false, "pyzor": true|false }

Config via environment:
  SHIM_HOST             bind address           (default 0.0.0.0)
  SHIM_PORT             bind port              (default 8077)
  SHIM_BACKEND_TIMEOUT  per-CLI timeout secs   (default 6)
  SHIM_MAX_CONCURRENT   max in-flight requests (default 8)
  SHIM_TOKEN[_FILE]     shared secret for POST endpoints (required for POST)
  DCCPROC / RAZOR_CHECK / RAZOR_REPORT / RAZOR_REVOKE / PYZOR  CLI paths
"""
import hmac
import json
import os
import re
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("SHIM_HOST", "0.0.0.0")
PORT = int(os.environ.get("SHIM_PORT", "8077"))
TIMEOUT = float(os.environ.get("SHIM_BACKEND_TIMEOUT", "6"))
MAX_CONCURRENT = int(os.environ.get("SHIM_MAX_CONCURRENT", "8"))
MAX_BODY = 8 * 1024 * 1024

DCCPROC = os.environ.get("DCCPROC", "/usr/bin/dccproc")
RAZOR_CHECK = os.environ.get("RAZOR_CHECK", "razor-check")
RAZOR_REPORT = os.environ.get("RAZOR_REPORT", "razor-report")
RAZOR_REVOKE = os.environ.get("RAZOR_REVOKE", "razor-revoke")
PYZOR = os.environ.get("PYZOR", "pyzor")

# Explicit homedirs: the shim runs as `drp`, whose $HOME is not the state dir, so
# the CLIs must be told where their identity/servers live (env RAZORHOME works
# for razor, but pyzor needs --homedir).
RAZORHOME = os.environ.get("RAZORHOME", "/var/lib/razor")
PYZOR_HOME = os.environ.get("PYZOR_HOME", "/var/lib/pyzor")
_RAZOR_HOME_ARG = ["-home=" + RAZORHOME]
_PYZOR_HOME_ARG = ["--homedir", PYZOR_HOME]


def _load_token():
    f = os.environ.get("SHIM_TOKEN_FILE")
    if f and os.path.isfile(f):
        with open(f) as fh:
            return fh.read().strip()
    return os.environ.get("SHIM_TOKEN", "").strip()


TOKEN = _load_token()

# Bound the number of requests processed at once; each request can fork up to
# three CLIs, so an unbounded server would be a fork bomb under load.
_sem = threading.BoundedSemaphore(MAX_CONCURRENT)

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
    action = "reject" if rc == 1 or _DCC_BULK_RE.search(out) else "accept"
    return {"action": action, "bulk": bulk}


def check_razor(msg):
    # razor-check exits 0 = spam (signature hit), 1 = not listed.
    r = _run([RAZOR_CHECK] + _RAZOR_HOME_ARG, msg)
    if r is None:
        return {"hit": False}
    rc, _, _ = r
    return {"hit": rc == 0}


def check_pyzor(msg):
    # `pyzor check` prints one line per server, tab-separated, ending in the
    # report count and whitelist count, e.g.:
    #   public.pyzor.org:24441  (200, 'OK')  42  0
    # Sum the report counts and take the max whitelist count across servers.
    r = _run([PYZOR] + _PYZOR_HOME_ARG + ["check"], msg)
    if r is None:
        return {"count": 0, "wl": 0}
    _, out, _ = r
    count = 0
    wl = 0
    for line in out.decode("ascii", "replace").splitlines():
        cols = line.split("\t")
        if len(cols) < 2:
            cols = line.split()
        tail = [c for c in cols if c.lstrip("-").isdigit()]
        if len(tail) >= 2:
            count += int(tail[-2])
            wl = max(wl, int(tail[-1]))
    return {"count": count, "wl": wl}


def _ok(r):
    """True if the CLI ran and exited 0; False on failure; None if missing."""
    if r is None:
        return None
    rc, _, _ = r
    return rc == 0


def _parallel(tasks):
    """Run {key: callable} concurrently, return {key: result}."""
    out = {}
    with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
        futs = {k: ex.submit(fn) for k, fn in tasks.items()}
        for k, fut in futs.items():
            out[k] = fut.result()
    return out


def verdict(msg):
    return _parallel({
        "dcc": lambda: check_dcc(msg),
        "razor": lambda: check_razor(msg),
        "pyzor": lambda: check_pyzor(msg),
    })


def report(msg):
    """Report the message as SPAM to all three networks."""
    res = _parallel({
        # DCC: dccproc WITHOUT -Q actually submits the checksums.
        "dcc": lambda: _ok(_run([DCCPROC, "-H"], msg)),
        "razor": lambda: _ok(_run([RAZOR_REPORT] + _RAZOR_HOME_ARG, msg)),
        "pyzor": lambda: _ok(_run([PYZOR] + _PYZOR_HOME_ARG + ["report"], msg)),
    })
    res["razor"] = res["razor"] or False
    res["pyzor"] = res["pyzor"] or False
    return res


def revoke(msg):
    """Report the message as HAM where the network supports it (DCC has no
    network un-report, so it is null)."""
    res = _parallel({
        "razor": lambda: _ok(_run([RAZOR_REVOKE] + _RAZOR_HOME_ARG, msg)),
        "pyzor": lambda: _ok(_run([PYZOR] + _PYZOR_HOME_ARG + ["whitelist"], msg)),
    })
    return {"dcc": None, "razor": res["razor"] or False, "pyzor": res["pyzor"] or False}


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

    def _authed(self):
        if not TOKEN:
            return None  # fail closed -> caller returns 503
        presented = ""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            presented = auth[7:].strip()
        else:
            presented = self.headers.get("X-DRP-Token", "").strip()
        return hmac.compare_digest(presented, TOKEN)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, "ok", "text/plain")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        handler = {"/check": verdict, "/report": report, "/revoke": revoke}.get(self.path)
        if handler is None:
            self._send(404, "not found", "text/plain")
            return

        ok = self._authed()
        if ok is None:
            self._send(503, json.dumps({"error": "shim token not configured"}))
            return
        if not ok:
            self._send(401, json.dumps({"error": "unauthorized"}))
            return

        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_BODY:
            self._send(400, json.dumps({"error": "bad length"}))
            return
        msg = self.rfile.read(length)

        if not _sem.acquire(timeout=TIMEOUT):
            self._send(503, json.dumps({"error": "busy"}))
            return
        try:
            self._send(200, json.dumps(handler(msg)))
        except Exception as e:  # never 500 the caller; log and return safe defaults
            self.log_error("%s failed: %s", self.path, e)
            if self.path == "/check":
                self._send(200, json.dumps({
                    "dcc": {"action": "unknown", "bulk": None},
                    "razor": {"hit": False},
                    "pyzor": {"count": 0, "wl": 0},
                }))
            else:
                self._send(200, json.dumps({"dcc": None, "razor": False, "pyzor": False}))
        finally:
            _sem.release()

    def log_message(self, fmt, *args):  # to stderr -> s6 captures it
        import sys
        sys.stderr.write("[shim] " + (fmt % args) + "\n")


def main():
    if not TOKEN:
        import sys
        sys.stderr.write(
            "[shim] WARNING: no SHIM_TOKEN configured — POST endpoints will "
            "refuse all requests (503). Set SHIM_TOKEN or SHIM_TOKEN_FILE.\n")
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[shim] listening on {HOST}:{PORT} "
          f"(timeout={TIMEOUT}s, max_concurrent={MAX_CONCURRENT}, "
          f"auth={'on' if TOKEN else 'OFF'})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
