package config

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestLoadUsesEnvironmentDefaults(t *testing.T) {
	t.Setenv("XIP_DOMAIN", "Example.TEST")
	t.Setenv("XIP_ROOT_ADDRESSES", "10.0.0.1,10.0.0.2")
	t.Setenv("XIP_NS_ADDRESSES", "10.0.0.3 10.0.0.4")
	t.Setenv("XIP_TIMESTAMP", "42")
	t.Setenv("XIP_TTL", "600")
	t.Setenv("XIP_LISTEN", ":8053")
	t.Setenv("XIP_LISTEN_HTTP", ":8080")
	t.Setenv("XIP_ROOT_REDIRECT_URL", "https://pullpreview.com/?ref=xip")

	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Domain != "example.test" {
		t.Fatalf("expected normalized domain, got %q", cfg.Domain)
	}
	if cfg.Timestamp != 42 {
		t.Fatalf("unexpected timestamp: %d", cfg.Timestamp)
	}
	if cfg.TTL != 600 {
		t.Fatalf("unexpected ttl: %d", cfg.TTL)
	}
	if cfg.ListenUDP != ":8053" || cfg.ListenTCP != ":8053" {
		t.Fatalf("expected listen addresses to use XIP_LISTEN, got udp=%q tcp=%q", cfg.ListenUDP, cfg.ListenTCP)
	}
	if cfg.ListenHTTP != ":8080" {
		t.Fatalf("unexpected listen-http: %q", cfg.ListenHTTP)
	}
	if cfg.RootRedirectURL != "https://pullpreview.com/?ref=xip" {
		t.Fatalf("unexpected root redirect URL: %q", cfg.RootRedirectURL)
	}

	expectedRoot := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}
	if !reflect.DeepEqual(cfg.RootAddresses, expectedRoot) {
		t.Fatalf("unexpected root addresses: %#v", cfg.RootAddresses)
	}

	expectedNS := []netip.Addr{netip.MustParseAddr("10.0.0.3"), netip.MustParseAddr("10.0.0.4")}
	if !reflect.DeepEqual(cfg.NSAddresses, expectedNS) {
		t.Fatalf("unexpected NS addresses: %#v", cfg.NSAddresses)
	}
}

func TestLoadFlagsOverrideEnvironment(t *testing.T) {
	t.Setenv("XIP_DOMAIN", "env.test")
	t.Setenv("XIP_ROOT_ADDRESSES", "10.0.0.1")
	t.Setenv("XIP_NS_ADDRESSES", "10.0.0.2")
	t.Setenv("XIP_TIMESTAMP", "1")
	t.Setenv("XIP_TTL", "100")
	t.Setenv("XIP_LISTEN_UDP", ":2053")
	t.Setenv("XIP_LISTEN_TCP", ":3053")
	t.Setenv("XIP_LISTEN_HTTP", ":2080")
	t.Setenv("XIP_ROOT_REDIRECT_URL", "https://env.example")

	cfg, err := Load([]string{
		"--domain", "flag.test",
		"--root-addresses", "192.168.1.10",
		"--ns-addresses", "192.168.1.20",
		"--timestamp", "77",
		"--ttl", "1200",
		"--listen-udp", ":4053",
		"--listen-tcp", ":5053",
		"--listen-http", ":4080",
		"--root-redirect-url", "https://flag.example/?src=xip",
	})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Domain != "flag.test" {
		t.Fatalf("expected domain override, got %q", cfg.Domain)
	}
	if cfg.Timestamp != 77 {
		t.Fatalf("expected timestamp override, got %d", cfg.Timestamp)
	}
	if cfg.TTL != 1200 {
		t.Fatalf("expected ttl override, got %d", cfg.TTL)
	}
	if cfg.ListenUDP != ":4053" || cfg.ListenTCP != ":5053" {
		t.Fatalf("expected listen overrides, got udp=%q tcp=%q", cfg.ListenUDP, cfg.ListenTCP)
	}
	if cfg.ListenHTTP != ":4080" {
		t.Fatalf("expected listen-http override, got %q", cfg.ListenHTTP)
	}
	if cfg.RootRedirectURL != "https://flag.example/?src=xip" {
		t.Fatalf("expected root redirect URL override, got %q", cfg.RootRedirectURL)
	}

	if got := cfg.RootAddresses[0].String(); got != "192.168.1.10" {
		t.Fatalf("unexpected root address: %s", got)
	}
	if got := cfg.NSAddresses[0].String(); got != "192.168.1.20" {
		t.Fatalf("unexpected NS address: %s", got)
	}
}

func TestLoadRejectsInvalidAddress(t *testing.T) {
	t.Setenv("XIP_ROOT_ADDRESSES", "not-an-ip")

	_, err := Load(nil)
	if err == nil {
		t.Fatalf("expected error for invalid address")
	}
}

func TestLoadRejectsInvalidRootRedirectURL(t *testing.T) {
	t.Setenv("XIP_ROOT_REDIRECT_URL", "not-a-url")

	_, err := Load(nil)
	if err == nil {
		t.Fatalf("expected error for invalid root redirect URL")
	}
}

func TestLoadAllowsEmptyListenHTTPWithoutRedirect(t *testing.T) {
	cfg, err := Load([]string{"--listen-http", ""})
	if err != nil {
		t.Fatalf("did not expect error when redirect is disabled: %v", err)
	}
	if cfg.RootRedirectURL != "" {
		t.Fatalf("expected empty redirect url, got %q", cfg.RootRedirectURL)
	}
}

func TestLoadRejectsEmptyListenHTTPWithRedirect(t *testing.T) {
	_, err := Load([]string{"--listen-http", "", "--root-redirect-url", "https://pullpreview.com/?ref=xip"})
	if err == nil {
		t.Fatalf("expected error for empty listen-http with redirect configured")
	}
}
