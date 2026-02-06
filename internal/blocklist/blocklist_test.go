package blocklist

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReloadLoadsEntriesAndStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.csv")
	content := "fqdn,reason\nBad.Example.test,Abuse complaint\nspam.example.test,Phishing\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write blocklist file: %v", err)
	}

	m := New(path, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}

	reason, ok := m.Lookup("BAD.example.test.")
	if !ok {
		t.Fatalf("expected domain to be blocked")
	}
	if reason != "Abuse complaint" {
		t.Fatalf("unexpected reason: %q", reason)
	}

	stats := m.Stats()
	if stats.BlockedDomains != 2 {
		t.Fatalf("expected 2 blocked domains, got %d", stats.BlockedDomains)
	}
	if stats.LastReload.IsZero() {
		t.Fatalf("expected non-zero reload timestamp")
	}
}

func TestReloadMissingFileReturnsEmptyBlocklist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.csv")
	m := New(path, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := m.Reload(); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}

	stats := m.Stats()
	if stats.BlockedDomains != 0 {
		t.Fatalf("expected 0 blocked domains, got %d", stats.BlockedDomains)
	}
	if stats.LastReload.IsZero() {
		t.Fatalf("expected reload timestamp to be set")
	}
}

func TestReloadDoesNotReplaceStateWhenFileIsInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.csv")
	if err := os.WriteFile(path, []byte("fqdn,reason\nblocked.example.test,Abuse\n"), 0o644); err != nil {
		t.Fatalf("failed to write valid blocklist: %v", err)
	}

	m := New(path, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}

	if err := os.WriteFile(path, []byte("fqdn,reason\ninvalid_domain,Abuse\n"), 0o644); err != nil {
		t.Fatalf("failed to write invalid blocklist: %v", err)
	}

	if err := m.Reload(); err == nil {
		t.Fatalf("expected reload error for invalid blocklist")
	}

	reason, ok := m.Lookup("blocked.example.test")
	if !ok {
		t.Fatalf("expected previous entry to remain active")
	}
	if reason != "Abuse" {
		t.Fatalf("unexpected reason after failed reload: %q", reason)
	}
}

func TestRunPeriodicallyReloadsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.csv")
	if err := os.WriteFile(path, []byte("fqdn,reason\none.example.test,Initial\n"), 0o644); err != nil {
		t.Fatalf("failed to write blocklist file: %v", err)
	}

	m := New(path, 20*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()

	if err := os.WriteFile(path, []byte("fqdn,reason\none.example.test,Updated\ntwo.example.test,Second\n"), 0o644); err != nil {
		t.Fatalf("failed to update blocklist file: %v", err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		reason, ok := m.Lookup("two.example.test")
		if ok && reason == "Second" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	reason, ok := m.Lookup("two.example.test")
	if !ok || reason != "Second" {
		t.Fatalf("expected periodic reload to pick up updated file")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("timed out waiting for reload loop to stop")
	}
}
