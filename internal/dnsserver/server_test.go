package dnsserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/pullpreview/docker-sslip/internal/config"
)

func testConfig() config.Config {
	return config.Config{
		Domain:        "example.test",
		RootAddresses: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		NSAddresses:   []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
		Timestamp:     123,
		TTL:           300,
		ListenUDP:     ":0",
		ListenTCP:     ":0",
	}
}

func newTestServer() *Server {
	return New(testConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
}

func TestResolveRootA(t *testing.T) {
	srv := newTestServer()

	rcode, answer, _ := srv.resolve(dns.Question{Name: "example.test.", Qclass: dns.ClassINET, Qtype: dns.TypeA})
	if rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected rcode: %d", rcode)
	}
	if len(answer) != 1 {
		t.Fatalf("expected one A record, got %d", len(answer))
	}

	aRecord, ok := answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", answer[0])
	}
	if got := aRecord.A.String(); got != "1.2.3.4" {
		t.Fatalf("unexpected A record value: %s", got)
	}
}

func TestResolveDashedIPUseCases(t *testing.T) {
	srv := newTestServer()

	cases := []string{
		"1-2-3-4-whatever.example.test.",
		"whatever-1-2-3-4.example.test.",
		"subdomain.1-2-3-4-whatever.example.test.",
		"subdomain.whatever-1-2-3-4.example.test.",
	}

	for _, name := range cases {
		rcode, answer, _ := srv.resolve(dns.Question{Name: name, Qclass: dns.ClassINET, Qtype: dns.TypeA})
		if rcode != dns.RcodeSuccess {
			t.Fatalf("%s: unexpected rcode: %d", name, rcode)
		}
		if len(answer) != 1 {
			t.Fatalf("%s: expected one answer, got %d", name, len(answer))
		}
		aRecord, ok := answer[0].(*dns.A)
		if !ok {
			t.Fatalf("%s: expected A record, got %T", name, answer[0])
		}
		if got := aRecord.A.String(); got != "1.2.3.4" {
			t.Fatalf("%s: expected 1.2.3.4, got %s", name, got)
		}
	}
}

func TestResolveBlockedDomainReturnsRootIP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.csv")
	if err := os.WriteFile(path, []byte("fqdn,reason\npreview-9-9-9-9.example.test,Malware\n"), 0o644); err != nil {
		t.Fatalf("failed to write blocklist file: %v", err)
	}

	cfg := testConfig()
	cfg.BlocklistPath = path
	cfg.BlocklistReloadInterval = time.Minute
	srv := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	rcode, answer, _ := srv.resolve(dns.Question{Name: "preview-9-9-9-9.example.test.", Qclass: dns.ClassINET, Qtype: dns.TypeA})
	if rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected rcode: %d", rcode)
	}
	if len(answer) != 1 {
		t.Fatalf("expected one A record, got %d", len(answer))
	}

	aRecord, ok := answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", answer[0])
	}
	if got := aRecord.A.String(); got != "1.2.3.4" {
		t.Fatalf("expected blocked domain to resolve to root IP, got %s", got)
	}
}

func TestDashedIPv4ForName(t *testing.T) {
	srv := newTestServer()

	tests := []struct {
		name     string
		host     string
		expected string
		ok       bool
	}{
		{
			name:     "suffix",
			host:     "preview-1-2-3-4.example.test.",
			expected: "1.2.3.4",
			ok:       true,
		},
		{
			name:     "prefix",
			host:     "1-2-3-4-preview.example.test.",
			expected: "1.2.3.4",
			ok:       true,
		},
		{
			name:     "label boundary",
			host:     "foo.1-2-3-4.example.test.",
			expected: "1.2.3.4",
			ok:       true,
		},
		{
			name: "invalid octet",
			host: "preview-256-2-3-4.example.test.",
			ok:   false,
		},
		{
			name: "incomplete",
			host: "preview-1-2-3.example.test.",
			ok:   false,
		},
		{
			name: "extra numeric segment at tail",
			host: "preview-1-2-3-4-5.example.test.",
			ok:   false,
		},
		{
			name: "extra numeric segment at head",
			host: "5-1-2-3-4-preview.example.test.",
			ok:   false,
		},
		{
			name:     "outside zone",
			host:     "preview-1-2-3-4.example.org.",
			expected: "1.2.3.4",
			ok:       true,
		},
		{
			name: "root domain",
			host: "example.test.",
			ok:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := srv.dashedIPv4ForName(normalizeName(tc.host))
			if ok != tc.ok {
				t.Fatalf("expected ok=%v, got %v", tc.ok, ok)
			}

			if tc.ok && got.String() != tc.expected {
				t.Fatalf("expected %s, got %s", tc.expected, got)
			}
		})
	}
}

func TestMetricDomainForFQDN(t *testing.T) {
	tests := []struct {
		name     string
		fqdn     string
		expected string
	}{
		{name: "prefix style", fqdn: "1-2-3-4-preview.run", expected: "preview.run"},
		{name: "suffix style", fqdn: "preview-1-2-3-4.run", expected: "preview.run"},
		{name: "ip prefix token", fqdn: "ip-1-2-3-4.preview.run", expected: "preview.run"},
		{name: "nested ip prefix token", fqdn: "foo-ip-1-2-3-4.preview.run", expected: "foo.preview.run"},
		{name: "no ip token", fqdn: "preview.run", expected: "preview.run"},
		{name: "invalid ip chain", fqdn: "preview-1-2-3-4-5.run", expected: "preview-1-2-3-4-5.run"},
		{name: "empty", fqdn: "", expected: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := metricDomainForFQDN(tc.fqdn)
			if got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestResolveNSRecords(t *testing.T) {
	srv := newTestServer()

	rcode, answer, _ := srv.resolve(dns.Question{Name: "example.test.", Qclass: dns.ClassINET, Qtype: dns.TypeNS})
	if rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected rcode: %d", rcode)
	}
	if len(answer) != 2 {
		t.Fatalf("expected two NS records, got %d", len(answer))
	}
}

func TestResolveRootAnyIncludesSOAAndNSAndA(t *testing.T) {
	srv := newTestServer()

	rcode, answer, authority := srv.resolve(dns.Question{Name: "example.test.", Qclass: dns.ClassINET, Qtype: dns.TypeANY})
	if rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected rcode: %d", rcode)
	}
	if len(authority) != 0 {
		t.Fatalf("expected empty authority section, got %d", len(authority))
	}
	if len(answer) != 4 {
		t.Fatalf("expected SOA + 2 NS + 1 A records, got %d", len(answer))
	}
}

func TestResolveNameserverARecord(t *testing.T) {
	srv := newTestServer()

	rcode, answer, _ := srv.resolve(dns.Question{Name: "ns-1.example.test.", Qclass: dns.ClassINET, Qtype: dns.TypeA})
	if rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected rcode: %d", rcode)
	}
	if len(answer) != 1 {
		t.Fatalf("expected one A record, got %d", len(answer))
	}

	aRecord, ok := answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", answer[0])
	}
	if got := aRecord.A.String(); got != "10.0.0.2" {
		t.Fatalf("unexpected nameserver A value: %s", got)
	}
}

func TestResolveOutsideZoneReturnsNXDomain(t *testing.T) {
	srv := newTestServer()

	rcode, answer, authority := srv.resolve(dns.Question{Name: "example.org.", Qclass: dns.ClassINET, Qtype: dns.TypeA})
	if rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %d", rcode)
	}
	if len(answer) != 0 {
		t.Fatalf("expected no answers, got %d", len(answer))
	}
	if len(authority) != 1 {
		t.Fatalf("expected SOA authority record, got %d", len(authority))
	}
	if _, ok := authority[0].(*dns.SOA); !ok {
		t.Fatalf("expected SOA authority record, got %T", authority[0])
	}
}

func TestResolveDashedIPOutsideZoneReturnsA(t *testing.T) {
	srv := newTestServer()

	rcode, answer, authority := srv.resolve(dns.Question{Name: "preview-1-2-3-4.example.org.", Qclass: dns.ClassINET, Qtype: dns.TypeA})
	if rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected rcode: %d", rcode)
	}
	if len(authority) != 0 {
		t.Fatalf("expected no authority records, got %d", len(authority))
	}
	if len(answer) != 1 {
		t.Fatalf("expected one A record, got %d", len(answer))
	}

	aRecord, ok := answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", answer[0])
	}
	if got := aRecord.A.String(); got != "1.2.3.4" {
		t.Fatalf("expected 1.2.3.4, got %s", got)
	}
}

func TestResolveUnknownInZoneReturnsNXDomain(t *testing.T) {
	srv := newTestServer()

	rcode, answer, authority := srv.resolve(dns.Question{Name: "unknown.example.test.", Qclass: dns.ClassINET, Qtype: dns.TypeA})
	if rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %d", rcode)
	}
	if len(answer) != 0 {
		t.Fatalf("expected no answers, got %d", len(answer))
	}
	if len(authority) != 1 {
		t.Fatalf("expected SOA authority record, got %d", len(authority))
	}
	if _, ok := authority[0].(*dns.SOA); !ok {
		t.Fatalf("expected SOA authority record, got %T", authority[0])
	}
}

func TestResolveUnsupportedClassReturnsNoData(t *testing.T) {
	srv := newTestServer()

	rcode, answer, authority := srv.resolve(dns.Question{Name: "example.test.", Qclass: dns.ClassCHAOS, Qtype: dns.TypeA})
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected success rcode, got %d", rcode)
	}
	if len(answer) != 0 || len(authority) != 0 {
		t.Fatalf("expected no records for unsupported class")
	}
}

func TestHandleDNSEmptyQuestionReturnsFormatError(t *testing.T) {
	srv := newTestServer()

	writer := &recordingWriter{}
	req := new(dns.Msg)
	srv.handleDNS(writer, req)

	if writer.msg == nil {
		t.Fatalf("expected response message to be written")
	}
	if writer.msg.Rcode != dns.RcodeFormatError {
		t.Fatalf("expected format error, got %d", writer.msg.Rcode)
	}
}

func TestHandleDNSRecordsMetricsEveryRequest(t *testing.T) {
	recorder := &recordingMetrics{}
	srv := New(testConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), recorder)

	req1 := new(dns.Msg)
	req1.SetQuestion("ip-1-2-3-4.preview.run.", dns.TypeA)
	srv.handleDNS(&recordingWriter{}, req1)

	req2 := new(dns.Msg)
	srv.handleDNS(&recordingWriter{}, req2)

	calls := recorder.calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 metric calls, got %d", len(calls))
	}

	if calls[0].fqdn != "ip-1-2-3-4.preview.run" {
		t.Fatalf("unexpected first fqdn: %q", calls[0].fqdn)
	}
	if calls[0].domain != "preview.run" {
		t.Fatalf("unexpected first domain: %q", calls[0].domain)
	}
	if calls[1].fqdn != "" || calls[1].domain != "" {
		t.Fatalf("unexpected second call payload: fqdn=%q domain=%q", calls[1].fqdn, calls[1].domain)
	}
}

func TestHandleHTTPBlockedDomainShowsReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.csv")
	if err := os.WriteFile(path, []byte("fqdn,reason\nabuse.example.test,Abusive content\n"), 0o644); err != nil {
		t.Fatalf("failed to write blocklist file: %v", err)
	}

	cfg := testConfig()
	cfg.BlocklistPath = path
	cfg.BlocklistReloadInterval = time.Minute
	srv := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	req := httptest.NewRequest(http.MethodGet, "http://abuse.example.test/", nil)
	req.Host = "abuse.example.test"
	rec := httptest.NewRecorder()

	srv.handleHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnavailableForLegalReasons {
		t.Fatalf("expected status %d, got %d", http.StatusUnavailableForLegalReasons, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "Abusive content") {
		t.Fatalf("expected reason to appear in body, got %q", text)
	}
	if !strings.Contains(text, "support@pullpreview.com") {
		t.Fatalf("expected support contact in body")
	}
}

func TestHandleHTTPHealthReturnsBlocklistStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.csv")
	if err := os.WriteFile(path, []byte("fqdn,reason\na.example.test,Abuse\nb.example.test,Spam\n"), 0o644); err != nil {
		t.Fatalf("failed to write blocklist file: %v", err)
	}

	cfg := testConfig()
	cfg.BlocklistPath = path
	cfg.BlocklistReloadInterval = time.Minute
	srv := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.test/health", nil)
	req.Host = "example.test"
	rec := httptest.NewRecorder()

	srv.handleHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	var payload struct {
		BlockedDomains int    `json:"blocked_domains"`
		LastReloadTime string `json:"last_reload_time"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}

	if payload.BlockedDomains != 2 {
		t.Fatalf("expected blocked_domains=2, got %d", payload.BlockedDomains)
	}
	if payload.LastReloadTime == "" {
		t.Fatalf("expected last_reload_time to be set")
	}
}

func TestAllowCertificateHostAllowsInZoneHost(t *testing.T) {
	srv := newTestServer()

	if err := srv.allowCertificateHost(context.Background(), "My.Example.Test"); err != nil {
		t.Fatalf("expected in-zone host to be allowed, got error: %v", err)
	}
	if err := srv.allowCertificateHost(context.Background(), "foo.bar.example.test."); err != nil {
		t.Fatalf("expected nested in-zone host to be allowed, got error: %v", err)
	}
}

func TestAllowCertificateHostRejectsOutsideZoneHost(t *testing.T) {
	srv := newTestServer()

	if err := srv.allowCertificateHost(context.Background(), "outside.example.org"); err == nil {
		t.Fatalf("expected outside-zone host to be rejected")
	}
}

func TestStartServesUDPAndTCP(t *testing.T) {
	cfg := testConfig()
	cfg.ListenUDP = "127.0.0.1:0"
	cfg.ListenTCP = "127.0.0.1:0"
	srv := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	udpAddr, tcpAddr := waitForListeners(t, srv, errCh)
	if srv.httpLn != nil {
		t.Fatalf("expected HTTP listener to be disabled when no redirect URL is configured")
	}

	assertQueryARecord(t, "udp", udpAddr, "preview-1-2-3-4.example.test.", "1.2.3.4")
	assertQueryARecord(t, "tcp", tcpAddr, "1-2-3-5-preview.example.test.", "1.2.3.5")

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for server shutdown")
	}
}

func TestStartServesHTTPRedirectWhenConfigured(t *testing.T) {
	cfg := testConfig()
	cfg.ListenUDP = "127.0.0.1:0"
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.ListenHTTP = "127.0.0.1:0"
	cfg.RootRedirectURL = "https://pullpreview.com/?ref=xip"
	srv := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	_, _ = waitForListeners(t, srv, errCh)
	httpAddr := waitForHTTPListener(t, srv, errCh)

	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get("http://" + httpAddr + "/anything?test=1")
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != cfg.RootRedirectURL {
		t.Fatalf("expected Location %q, got %q", cfg.RootRedirectURL, got)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for server shutdown")
	}
}

func waitForListeners(t *testing.T, srv *Server, errCh <-chan error) (string, string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("server failed before listeners were ready: %v", err)
		default:
		}

		if srv.udp != nil && srv.udp.PacketConn != nil && srv.tcp != nil && srv.tcp.Listener != nil {
			return srv.udp.PacketConn.LocalAddr().String(), srv.tcp.Listener.Addr().String()
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for UDP/TCP listeners")
	return "", ""
}

func waitForHTTPListener(t *testing.T, srv *Server, errCh <-chan error) string {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("server failed before HTTP listener was ready: %v", err)
		default:
		}

		if srv.httpLn != nil {
			return srv.httpLn.Addr().String()
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for HTTP listener")
	return ""
}

func assertQueryARecord(t *testing.T, network, serverAddr, question, expectedA string) {
	t.Helper()

	client := &dns.Client{
		Net:     network,
		Timeout: 2 * time.Second,
	}

	msg := new(dns.Msg)
	msg.SetQuestion(question, dns.TypeA)

	resp, _, err := client.Exchange(msg, serverAddr)
	if err != nil {
		t.Fatalf("exchange failed (%s %s): %v", network, serverAddr, err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected rcode: %d", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected exactly one answer, got %d", len(resp.Answer))
	}

	aRecord, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if got := aRecord.A.String(); got != expectedA {
		t.Fatalf("expected %s, got %s", expectedA, got)
	}
}

type recordingWriter struct {
	msg *dns.Msg
}

type metricCall struct {
	fqdn   string
	domain string
}

type recordingMetrics struct {
	mu    sync.Mutex
	items []metricCall
}

func (r *recordingMetrics) RecordDNSRequest(_ context.Context, fqdn string, domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, metricCall{fqdn: fqdn, domain: domain})
}

func (r *recordingMetrics) calls() []metricCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]metricCall, len(r.items))
	copy(out, r.items)
	return out
}

func (w *recordingWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (w *recordingWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (w *recordingWriter) WriteMsg(msg *dns.Msg) error {
	w.msg = msg.Copy()
	return nil
}

func (w *recordingWriter) Write(buf []byte) (int, error) {
	return len(buf), nil
}

func (w *recordingWriter) Close() error {
	return nil
}

func (w *recordingWriter) TsigStatus() error {
	return nil
}

func (w *recordingWriter) TsigTimersOnly(bool) {}

func (w *recordingWriter) Hijack() {}
