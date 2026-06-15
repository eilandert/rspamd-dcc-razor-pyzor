package gozer

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeDccproc writes a stub dccproc that echoes $DCC_OUT and exits $DCC_RC,
// after draining stdin (gozer feeds the message there).
func fakeDccproc(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dccproc")
	script := "#!/bin/sh\ncat >/dev/null\nprintf '%s' \"$DCC_OUT\"\nexit \"${DCC_RC:-0}\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil { // #nosec G306 -- test stub must be executable
		t.Fatal(err)
	}
	return path
}

func dccBackend(t *testing.T, out string, rc string) *Backends {
	t.Setenv("DCC_OUT", out)
	t.Setenv("DCC_RC", rc)
	return &Backends{cfg: &Config{Dccproc: fakeDccproc(t), BackendTimeout: 3 * time.Second}, logf: func(string, ...any) {}}
}

func TestCheckDCCBulkBody(t *testing.T) {
	b := dccBackend(t, "X-DCC-Brand-Metrics: bulk\nBody=42\n", "0")
	r := b.checkDCC(nil)
	if r.Action != "reject" {
		t.Errorf("bulk should reject, got %q", r.Action)
	}
	if r.Bulk == nil || *r.Bulk != 42 {
		t.Errorf("bulk count: %v", r.Bulk)
	}
}

func TestCheckDCCManyAndExitOne(t *testing.T) {
	b := dccBackend(t, "Body=many\n", "1")
	r := b.checkDCC(nil)
	if r.Action != "reject" { // exit 1 also means reject
		t.Errorf("exit 1 should reject, got %q", r.Action)
	}
	if r.Bulk == nil || *r.Bulk != (1<<31)-1 {
		t.Errorf("many should be 2^31-1, got %v", r.Bulk)
	}
}

func TestCheckDCCAccept(t *testing.T) {
	b := dccBackend(t, "X-DCC: ok\n", "0")
	r := b.checkDCC(nil)
	if r.Action != "accept" {
		t.Errorf("clean should accept, got %q", r.Action)
	}
	if r.Bulk != nil {
		t.Errorf("no Body= should be nil bulk, got %v", r.Bulk)
	}
}

func TestCheckDCCMissingBinary(t *testing.T) {
	b := &Backends{cfg: &Config{Dccproc: "/nonexistent/dccproc", BackendTimeout: time.Second}, logf: func(string, ...any) {}}
	r := b.checkDCC(nil)
	if r.Action != "unknown" || r.Bulk != nil {
		t.Errorf("missing binary should be unknown/nil, got %q/%v", r.Action, r.Bulk)
	}
}

func TestReportDCC(t *testing.T) {
	if v := dccBackend(t, "", "0").reportDCC(nil); v == nil || !*v {
		t.Errorf("rc 0 should report true, got %v", v)
	}
	if v := dccBackend(t, "", "1").reportDCC(nil); v == nil || *v {
		t.Errorf("rc 1 should report false, got %v", v)
	}
	missing := &Backends{cfg: &Config{Dccproc: "/nonexistent", BackendTimeout: time.Second}, logf: func(string, ...any) {}}
	if v := missing.reportDCC(nil); v != nil {
		t.Errorf("missing binary should be nil, got %v", v)
	}
}

func TestReportRazorNoIdentity(t *testing.T) {
	b := &Backends{cfg: &Config{BackendTimeout: time.Second}, logf: func(string, ...any) {}}
	if b.HasRazorIdentity() {
		t.Fatal("no identity expected")
	}
	if b.reportRazor(nil) || b.revokeRazor(nil) {
		t.Error("report/revoke without identity must be false (no network call)")
	}
}
