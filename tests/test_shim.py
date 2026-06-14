"""Unit + HTTP tests for spamcheck_shim.

Backends (dccproc/razor/pyzor) are mocked by monkeypatching shim._run, so these
run with no DCC/Razor/Pyzor installed and no network. The docker integration
smoke test (real CLIs) lives in ci-build.sh.
"""
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shim"))
import spamcheck_shim as shim  # noqa: E402


# --------------------------------------------------------------------------- #
# Backend parsing (mock _run)
# --------------------------------------------------------------------------- #
def _stub(rc, out=b"", err=b""):
    return lambda argv, msg: (rc, out, err)


def test_check_dcc_bulk_many(monkeypatch):
    monkeypatch.setattr(shim, "_run",
                        _stub(0, b"X-DCC-x: host 1; bulk Body=many Fuz2=many"))
    r = shim.check_dcc(b"m")
    assert r["action"] == "reject"
    assert r["bulk"] == 2 ** 31 - 1


def test_check_dcc_numeric_no_bulk(monkeypatch):
    monkeypatch.setattr(shim, "_run", _stub(0, b"X-DCC-x: host 1; Body=5"))
    r = shim.check_dcc(b"m")
    assert r["action"] == "accept"
    assert r["bulk"] == 5


def test_check_dcc_reject_rc(monkeypatch):
    monkeypatch.setattr(shim, "_run", _stub(1, b"X-DCC-x: nothing"))
    assert shim.check_dcc(b"m")["action"] == "reject"


def test_check_dcc_missing(monkeypatch):
    monkeypatch.setattr(shim, "_run", lambda a, m: None)
    assert shim.check_dcc(b"m") == {"action": "unknown", "bulk": None}


def test_check_razor_hit(monkeypatch):
    monkeypatch.setattr(shim, "_run", _stub(0))
    assert shim.check_razor(b"m") == {"hit": True}


def test_check_razor_miss(monkeypatch):
    monkeypatch.setattr(shim, "_run", _stub(1))
    assert shim.check_razor(b"m") == {"hit": False}


def test_check_razor_missing(monkeypatch):
    monkeypatch.setattr(shim, "_run", lambda a, m: None)
    assert shim.check_razor(b"m") == {"hit": False}


def test_check_pyzor_single(monkeypatch):
    out = b"public.pyzor.org:24441\t(200, 'OK')\t42\t0\n"
    monkeypatch.setattr(shim, "_run", _stub(0, out))
    assert shim.check_pyzor(b"m") == {"count": 42, "wl": 0}


def test_check_pyzor_multi_server_sums(monkeypatch):
    out = (b"a:24441\t(200, 'OK')\t10\t0\n"
           b"b:24441\t(200, 'OK')\t5\t2\n")
    monkeypatch.setattr(shim, "_run", _stub(0, out))
    r = shim.check_pyzor(b"m")
    assert r["count"] == 15   # summed
    assert r["wl"] == 2       # max


def test_check_pyzor_garbage(monkeypatch):
    monkeypatch.setattr(shim, "_run", _stub(0, b"connection refused\n"))
    assert shim.check_pyzor(b"m") == {"count": 0, "wl": 0}


def test_ok_helper(monkeypatch):
    assert shim._ok((0, b"", b"")) is True
    assert shim._ok((1, b"", b"")) is False
    assert shim._ok(None) is None


def test_report_maps_results(monkeypatch):
    monkeypatch.setattr(shim, "_run", _stub(0))
    r = shim.report(b"m")
    assert r == {"dcc": True, "razor": True, "pyzor": True}


def test_revoke_dcc_null(monkeypatch):
    monkeypatch.setattr(shim, "_run", _stub(0))
    r = shim.revoke(b"m")
    assert r["dcc"] is None
    assert r["razor"] is True and r["pyzor"] is True


# --------------------------------------------------------------------------- #
# HTTP layer (real server, mocked backends)
# --------------------------------------------------------------------------- #
@pytest.fixture
def server(monkeypatch):
    # benign verdict regardless of endpoint
    monkeypatch.setattr(shim, "_run", _stub(1, b"X-DCC-x: clean"))
    monkeypatch.setattr(shim, "TOKEN", "secret")
    shim._cache.clear()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), shim.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _req(url, method="GET", data=None, headers=None):
    r = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        resp = urllib.request.urlopen(r, timeout=5)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_health_no_auth(server):
    code, body = _req(server + "/health")
    assert code == 200 and body == b"ok"


def test_check_missing_token_401(server):
    code, _ = _req(server + "/check", "POST", b"hi")
    assert code == 401


def test_check_bad_token_401(server):
    code, _ = _req(server + "/check", "POST", b"hi", {"X-DRP-Token": "wrong"})
    assert code == 401


def test_check_good_token_xheader(server):
    code, body = _req(server + "/check", "POST", b"hi", {"X-DRP-Token": "secret"})
    assert code == 200
    assert set(json.loads(body)) == {"dcc", "razor", "pyzor"}


def test_check_good_token_bearer(server):
    code, _ = _req(server + "/check", "POST", b"hi",
                   {"Authorization": "Bearer secret"})
    assert code == 200


def test_unknown_path_404(server):
    code, _ = _req(server + "/nope", "POST", b"hi", {"X-DRP-Token": "secret"})
    assert code == 404


def test_empty_body_400(server):
    code, _ = _req(server + "/check", "POST", b"", {"X-DRP-Token": "secret"})
    assert code == 400


def test_check_cache_hit_skips_backends(server, monkeypatch):
    calls = {"n": 0}

    def counting(argv, msg):
        calls["n"] += 1
        return (1, b"X-DCC-x: clean", b"")

    monkeypatch.setattr(shim, "_run", counting)
    monkeypatch.setattr(shim, "CACHE_TTL", 300.0)
    shim._cache.clear()

    body = b"From: a@b.com\nSubject: bulk\n\nidentical bulk body\n"
    c1, r1 = _req(server + "/check", "POST", body, {"X-DRP-Token": "secret"})
    first = calls["n"]
    assert c1 == 200 and first == 3            # dcc+razor+pyzor ran once

    c2, r2 = _req(server + "/check", "POST", body, {"X-DRP-Token": "secret"})
    assert c2 == 200 and r2 == r1
    assert calls["n"] == first                 # cache hit -> no extra backend calls


def test_report_not_cached(server, monkeypatch):
    calls = {"n": 0}

    def counting(argv, msg):
        calls["n"] += 1
        return (0, b"", b"")

    monkeypatch.setattr(shim, "_run", counting)
    monkeypatch.setattr(shim, "CACHE_TTL", 300.0)
    body = b"From: a@b.com\n\nx\n"
    _req(server + "/report", "POST", body, {"X-DRP-Token": "secret"})
    _req(server + "/report", "POST", body, {"X-DRP-Token": "secret"})
    assert calls["n"] == 6                      # 3 backends x 2 (never cached)


def test_fail_closed_when_no_token(monkeypatch):
    monkeypatch.setattr(shim, "_run", _stub(1))
    monkeypatch.setattr(shim, "TOKEN", "")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), shim.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        code, _ = _req(f"http://127.0.0.1:{srv.server_address[1]}/check",
                       "POST", b"hi")
        assert code == 503
    finally:
        srv.shutdown()
