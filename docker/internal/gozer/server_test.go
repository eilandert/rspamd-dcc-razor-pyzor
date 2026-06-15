package gozer

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeEngine returns canned verdicts and counts calls, so HTTP-layer tests
// never touch the live razor/pyzor networks.
type fakeEngine struct {
	checks  atomic.Int32
	reports atomic.Int32
	panicOn string
}

func (f *fakeEngine) Check(msg []byte) Verdict {
	f.checks.Add(1)
	if f.panicOn == "/check" {
		panic("boom")
	}
	n := 7
	return Verdict{
		DCC:   DCCResult{Action: "reject", Bulk: &n},
		Razor: RazorResult{Hit: true},
		Pyzor: PyzorResult{Count: 3, WL: 0},
	}
}

func (f *fakeEngine) Report(msg []byte) ReportResult {
	f.reports.Add(1)
	tru := true
	return ReportResult{DCC: &tru, Razor: true, Pyzor: true}
}

func (f *fakeEngine) Revoke(msg []byte) ReportResult {
	return ReportResult{Razor: true, Pyzor: false} // DCC nil
}

func (f *fakeEngine) HasRazorIdentity() bool { return true }

func testServer(t *testing.T, token string, engine Engine, cache Cache) *httptest.Server {
	t.Helper()
	cfg := &Config{Token: token, MaxConcurrent: 4, BackendTimeout: 2 * time.Second, MaxBody: 1024}
	srv := httptest.NewServer(NewServerWithEngine(cfg, engine, cache))
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, base, path, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestHealth(t *testing.T) {
	srv := testServer(t, "tok", &fakeEngine{}, nil)
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "ok" {
		t.Errorf("health: %d %q", resp.StatusCode, b)
	}
}

func TestUnknownPaths404(t *testing.T) {
	srv := testServer(t, "tok", &fakeEngine{}, nil)
	resp, _ := http.Get(srv.URL + "/nope")
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("GET /nope: %d", resp.StatusCode)
	}
	resp = post(t, srv.URL, "/nope", "tok", "x")
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("POST /nope: %d", resp.StatusCode)
	}
}

func TestAuthFailClosed(t *testing.T) {
	// no token configured -> 503
	srv := testServer(t, "", &fakeEngine{}, nil)
	resp := post(t, srv.URL, "/check", "anything", "msg")
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Errorf("no token configured should 503, got %d", resp.StatusCode)
	}
}

func TestAuthWrongAndRight(t *testing.T) {
	eng := &fakeEngine{}
	srv := testServer(t, "secret", eng, nil)

	resp := post(t, srv.URL, "/check", "wrong", "msg")
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("wrong token should 401, got %d", resp.StatusCode)
	}

	resp = post(t, srv.URL, "/check", "secret", "msg")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("right token should 200, got %d", resp.StatusCode)
	}
	var v Verdict
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.DCC.Action != "reject" || !v.Razor.Hit || v.Pyzor.Count != 3 {
		t.Errorf("verdict mismatch: %+v", v)
	}
}

func TestXDRPTokenHeader(t *testing.T) {
	srv := testServer(t, "secret", &fakeEngine{}, nil)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/check", strings.NewReader("msg"))
	req.Header.Set("X-DRP-Token", "secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("X-DRP-Token auth should 200, got %d", resp.StatusCode)
	}
}

func TestBodyLimits(t *testing.T) {
	srv := testServer(t, "tok", &fakeEngine{}, nil)

	resp := post(t, srv.URL, "/check", "tok", "")
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("empty body should 400, got %d", resp.StatusCode)
	}

	resp = post(t, srv.URL, "/check", "tok", strings.Repeat("x", 2048)) // > MaxBody 1024
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("oversize body should 400, got %d", resp.StatusCode)
	}
}

func TestCheckCache(t *testing.T) {
	eng := &fakeEngine{}
	cache := newMemCache(8, time.Minute)
	srv := testServer(t, "tok", eng, cache)

	resp := post(t, srv.URL, "/check", "tok", "same-body")
	if h := resp.Header.Get("X-DRP-Cache"); h != "" {
		t.Errorf("first call should be a miss, got X-DRP-Cache=%q", h)
	}
	resp.Body.Close()

	resp = post(t, srv.URL, "/check", "tok", "same-body")
	if h := resp.Header.Get("X-DRP-Cache"); h != "hit" {
		t.Errorf("second call should be a hit, got %q", h)
	}
	resp.Body.Close()

	if got := eng.checks.Load(); got != 1 {
		t.Errorf("engine should run once (cached), ran %d times", got)
	}
}

func TestReportNotCached(t *testing.T) {
	eng := &fakeEngine{}
	cache := newMemCache(8, time.Minute)
	srv := testServer(t, "tok", eng, cache)

	for i := 0; i < 2; i++ {
		resp := post(t, srv.URL, "/report", "tok", "body")
		resp.Body.Close()
	}
	if got := eng.reports.Load(); got != 2 {
		t.Errorf("report must never be cached, engine ran %d times", got)
	}
}

func TestRevokeDCCNull(t *testing.T) {
	srv := testServer(t, "tok", &fakeEngine{}, nil)
	resp := post(t, srv.URL, "/revoke", "tok", "body")
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `"dcc":null`) {
		t.Errorf("revoke dcc should be null, got %s", b)
	}
}

func TestFailOpenOnPanic(t *testing.T) {
	srv := testServer(t, "tok", &fakeEngine{panicOn: "/check"}, nil)
	resp := post(t, srv.URL, "/check", "tok", "msg")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("panic must fail open with 200, got %d", resp.StatusCode)
	}
	var v Verdict
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.DCC.Action != "unknown" || v.Razor.Hit {
		t.Errorf("fail-open verdict should be safe defaults, got %+v", v)
	}
}
