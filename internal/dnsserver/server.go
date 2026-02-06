package dnsserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/acme/autocert"

	"github.com/pullpreview/docker-sslip/internal/blocklist"
	"github.com/pullpreview/docker-sslip/internal/config"
)

var dashedIPv4Pattern = regexp.MustCompile(`(?:^|[.-])((?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})-(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})-(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})-(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2}))(?:$|[.-])`)

const supportEmail = "support@pullpreview.com"

// RequestMetrics records per-request metrics for DNS traffic.
type RequestMetrics interface {
	RecordDNSRequest(ctx context.Context, fqdn string, domain string)
}

type noopRequestMetrics struct{}

func (noopRequestMetrics) RecordDNSRequest(context.Context, string, string) {}

// Server hosts the DNS service for the xip zone.
type Server struct {
	cfg       config.Config
	zone      string
	log       *slog.Logger
	metrics   RequestMetrics
	blocklist *blocklist.Manager
	autocert  *autocert.Manager
	udp       *dns.Server
	tcp       *dns.Server
	httpSrv   *http.Server
	httpLn    net.Listener
	httpsSrv  *http.Server
	httpsLn   net.Listener
	hdlr      dns.Handler
}

func New(cfg config.Config, logger *slog.Logger, metrics RequestMetrics) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	if metrics == nil {
		metrics = noopRequestMetrics{}
	}

	s := &Server{
		cfg:       cfg,
		zone:      dns.Fqdn(cfg.Domain),
		log:       logger,
		metrics:   metrics,
		blocklist: blocklist.New(cfg.BlocklistPath, cfg.BlocklistReloadInterval, logger.With("component", "blocklist")),
	}
	s.hdlr = dns.HandlerFunc(s.handleDNS)
	if err := s.blocklist.Reload(); err != nil {
		s.log.Warn("failed to load blocklist", "path", cfg.BlocklistPath, "error", err)
	}

	if strings.TrimSpace(cfg.ListenHTTPS) != "" {
		s.autocert = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cfg.ACMECacheDir),
			Email:      cfg.ACMEEmail,
			HostPolicy: s.allowCertificateHost,
		}
	}

	return s
}

func (s *Server) Start(ctx context.Context) error {
	s.udp = &dns.Server{
		Addr:    s.cfg.ListenUDP,
		Net:     "udp",
		Handler: s.hdlr,
	}

	s.tcp = &dns.Server{
		Addr:    s.cfg.ListenTCP,
		Net:     "tcp",
		Handler: s.hdlr,
	}

	errCh := make(chan error, 4)

	go s.blocklist.Run(ctx)

	go func() {
		if err := s.udp.ListenAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
			errCh <- fmt.Errorf("udp listener failed: %w", err)
		}
	}()

	go func() {
		if err := s.tcp.ListenAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
			errCh <- fmt.Errorf("tcp listener failed: %w", err)
		}
	}()

	webHandler := http.Handler(http.HandlerFunc(s.handleHTTP))
	if s.autocert != nil {
		webHandler = s.autocert.HTTPHandler(webHandler)
	}

	if strings.TrimSpace(s.cfg.ListenHTTP) != "" {
		httpLn, err := net.Listen("tcp", s.cfg.ListenHTTP)
		if err != nil {
			s.shutdown()
			return fmt.Errorf("http listener failed: %w", err)
		}

		s.httpLn = httpLn
		s.httpSrv = &http.Server{
			Handler:           webHandler,
			ReadHeaderTimeout: 5 * time.Second,
		}

		go func() {
			if err := s.httpSrv.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("http listener failed: %w", err)
			}
		}()
	}

	if strings.TrimSpace(s.cfg.ListenHTTPS) != "" && s.autocert != nil {
		httpsLn, err := net.Listen("tcp", s.cfg.ListenHTTPS)
		if err != nil {
			s.shutdown()
			return fmt.Errorf("https listener failed: %w", err)
		}

		tlsConfig := s.autocert.TLSConfig()
		tlsConfig.MinVersion = tls.VersionTLS12

		s.httpsLn = httpsLn
		s.httpsSrv = &http.Server{
			Handler:           http.HandlerFunc(s.handleHTTP),
			ReadHeaderTimeout: 5 * time.Second,
			TLSConfig:         tlsConfig,
		}

		go func() {
			if err := s.httpsSrv.ServeTLS(httpsLn, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("https listener failed: %w", err)
			}
		}()
	}

	select {
	case <-ctx.Done():
		s.shutdown()
		return nil
	case err := <-errCh:
		s.shutdown()
		return err
	}
}

func (s *Server) shutdown() {
	if s.udp != nil {
		_ = s.udp.Shutdown()
	}
	if s.tcp != nil {
		_ = s.tcp.Shutdown()
	}
	if s.httpSrv != nil {
		_ = s.httpSrv.Close()
	}
	if s.httpLn != nil {
		_ = s.httpLn.Close()
	}
	if s.httpsSrv != nil {
		_ = s.httpsSrv.Close()
	}
	if s.httpsLn != nil {
		_ = s.httpsLn.Close()
	}
}

func (s *Server) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	fqdn := ""
	if len(req.Question) > 0 {
		fqdn = normalizeName(req.Question[0].Name)
	}
	s.metrics.RecordDNSRequest(context.Background(), fqdn, metricDomainForFQDN(fqdn))

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = false

	if len(req.Question) == 0 {
		resp.Rcode = dns.RcodeFormatError
		if err := w.WriteMsg(resp); err != nil {
			s.log.Error("failed to write DNS response", "error", err)
		}
		return
	}

	question := req.Question[0]
	rcode, answer, authority := s.resolve(question)
	resp.Rcode = rcode
	resp.Answer = answer
	resp.Ns = authority

	s.log.Debug("dns query",
		"name", question.Name,
		"type", dns.TypeToString[question.Qtype],
		"class", question.Qclass,
		"rcode", dns.RcodeToString[rcode],
		"answers", len(answer),
	)

	if err := w.WriteMsg(resp); err != nil {
		s.log.Error("failed to write DNS response", "error", err)
	}
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		s.handleHealth(w)
		return
	}

	if reason, ok := s.blocklist.Lookup(hostFromRequest(r)); ok {
		s.writeBlockedPage(w, reason)
		return
	}

	if strings.TrimSpace(s.cfg.RootRedirectURL) != "" {
		http.Redirect(w, r, s.cfg.RootRedirectURL, http.StatusFound)
		return
	}

	http.NotFound(w, r)
}

func (s *Server) resolve(question dns.Question) (int, []dns.RR, []dns.RR) {
	if question.Qclass != dns.ClassINET && question.Qclass != dns.ClassANY {
		return dns.RcodeSuccess, nil, nil
	}

	name := normalizeName(question.Name)

	answers := make([]dns.RR, 0, len(s.cfg.RootAddresses)+len(s.cfg.NSAddresses)+2)
	nameExists := false

	if name == s.cfg.Domain {
		nameExists = true

		if queryMatches(question.Qtype, dns.TypeSOA) {
			answers = append(answers, s.soaRecord())
		}
		if queryMatches(question.Qtype, dns.TypeNS) {
			answers = append(answers, s.nsRecords()...)
		}
		if queryMatches(question.Qtype, dns.TypeA) {
			answers = append(answers, s.aRecordsForName(s.zone, s.cfg.RootAddresses)...)
		}
	}

	if name != s.cfg.Domain {
		if _, blocked := s.blocklist.Lookup(name); blocked {
			nameExists = true
			if queryMatches(question.Qtype, dns.TypeA) {
				answers = append(answers, s.aRecordsForName(dns.Fqdn(name), s.cfg.RootAddresses)...)
			}
		} else {
			if nsIndex, ok := s.nsIndexForName(name); ok {
				nameExists = true
				if queryMatches(question.Qtype, dns.TypeA) {
					nsName := dns.Fqdn(name)
					answers = append(answers, s.aRecordsForName(nsName, []netip.Addr{s.cfg.NSAddresses[nsIndex]})...)
				}
			}

			if dashedIP, ok := s.dashedIPv4ForName(name); ok {
				nameExists = true
				if queryMatches(question.Qtype, dns.TypeA) {
					answers = append(answers, s.aRecordsForName(dns.Fqdn(name), []netip.Addr{dashedIP})...)
				}
			}
		}
	}

	if !nameExists {
		return dns.RcodeNameError, nil, []dns.RR{s.soaRecord()}
	}

	return dns.RcodeSuccess, answers, nil
}

func (s *Server) inZone(name string) bool {
	if name == s.cfg.Domain {
		return true
	}
	return strings.HasSuffix(name, "."+s.cfg.Domain)
}

func (s *Server) dashedIPv4ForName(name string) (netip.Addr, bool) {
	matches := dashedIPv4Pattern.FindAllStringSubmatchIndex(name, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		start, end := match[2], match[3]
		if hasNumericDashBoundary(name, start, end) {
			continue
		}

		candidate := strings.ReplaceAll(name[start:end], "-", ".")
		addr, err := netip.ParseAddr(candidate)
		if err == nil && addr.Is4() {
			return addr, true
		}
	}

	return netip.Addr{}, false
}

func hasNumericDashBoundary(input string, start, end int) bool {
	// Prevent partial matches inside longer dashed numeric chains:
	// preview-1-2-3-4-5.example.test should not resolve as 1.2.3.4.
	if start >= 2 && input[start-1] == '-' && isASCIIDigit(input[start-2]) {
		return true
	}
	if end < len(input)-1 && input[end] == '-' && isASCIIDigit(input[end+1]) {
		return true
	}
	return false
}

func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func metricDomainForFQDN(rawFQDN string) string {
	fqdn := normalizeName(rawFQDN)
	if fqdn == "" {
		return ""
	}

	matches := dashedIPv4Pattern.FindAllStringSubmatchIndex(fqdn, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		start, end := match[2], match[3]
		if hasNumericDashBoundary(fqdn, start, end) {
			continue
		}

		expandedStart := start
		if start >= 3 && fqdn[start-3:start] == "ip-" {
			if start == 3 || fqdn[start-4] == '.' || fqdn[start-4] == '-' {
				expandedStart = start - 3
			}
		}

		candidate := fqdn[:expandedStart] + fqdn[end:]
		cleaned := cleanupMetricDomain(candidate)
		if cleaned == "" {
			return fqdn
		}
		return cleaned
	}

	return fqdn
}

func cleanupMetricDomain(value string) string {
	domain := strings.Trim(value, ".-")
	if domain == "" {
		return ""
	}

	for strings.Contains(domain, "..") {
		domain = strings.ReplaceAll(domain, "..", ".")
	}
	for strings.Contains(domain, "-.") {
		domain = strings.ReplaceAll(domain, "-.", ".")
	}
	for strings.Contains(domain, ".-") {
		domain = strings.ReplaceAll(domain, ".-", ".")
	}
	for strings.Contains(domain, "--") {
		domain = strings.ReplaceAll(domain, "--", "-")
	}

	return strings.Trim(domain, ".-")
}

func (s *Server) nsIndexForName(name string) (int, bool) {
	prefix := "ns-"
	suffix := "." + s.cfg.Domain
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return 0, false
	}

	left := strings.TrimSuffix(name, suffix)
	if strings.Count(left, ".") != 0 {
		return 0, false
	}

	indexRaw := strings.TrimPrefix(left, prefix)
	index, err := strconv.Atoi(indexRaw)
	if err != nil || index < 0 || index >= len(s.cfg.NSAddresses) {
		return 0, false
	}

	return index, true
}

func (s *Server) soaRecord() dns.RR {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   s.zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    s.cfg.TTL,
		},
		Ns:      dns.Fqdn("ns-0." + s.cfg.Domain),
		Mbox:    dns.Fqdn("admin." + s.cfg.Domain),
		Serial:  s.cfg.Timestamp,
		Refresh: s.cfg.TTL,
		Retry:   s.cfg.TTL,
		Expire:  s.cfg.TTL,
		Minttl:  s.cfg.TTL,
	}
}

func (s *Server) nsRecords() []dns.RR {
	records := make([]dns.RR, 0, len(s.cfg.NSAddresses))
	for index := range s.cfg.NSAddresses {
		records = append(records, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   s.zone,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    s.cfg.TTL,
			},
			Ns: dns.Fqdn(fmt.Sprintf("ns-%d.%s", index, s.cfg.Domain)),
		})
	}
	return records
}

func (s *Server) aRecordsForName(name string, addresses []netip.Addr) []dns.RR {
	records := make([]dns.RR, 0, len(addresses))
	for _, addr := range addresses {
		records = append(records, &dns.A{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    s.cfg.TTL,
			},
			A: net.IP(addr.AsSlice()),
		})
	}
	return records
}

func normalizeName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".")
	return n
}

func queryMatches(queryType uint16, recordType uint16) bool {
	return queryType == recordType || queryType == dns.TypeANY
}

func (s *Server) handleHealth(w http.ResponseWriter) {
	stats := s.blocklist.Stats()
	lastReload := ""
	if !stats.LastReload.IsZero() {
		lastReload = stats.LastReload.Format(time.RFC3339)
	}

	payload := struct {
		BlockedDomains int    `json:"blocked_domains"`
		LastReloadTime string `json:"last_reload_time"`
	}{
		BlockedDomains: stats.BlockedDomains,
		LastReloadTime: lastReload,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.log.Error("failed to write health response", "error", err)
	}
}

func (s *Server) writeBlockedPage(w http.ResponseWriter, reason string) {
	trimmedReason := strings.TrimSpace(reason)
	if trimmedReason == "" {
		trimmedReason = "This domain has been disabled."
	}
	escapedReason := html.EscapeString(trimmedReason)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnavailableForLegalReasons)

	if _, err := fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Domain Disabled</title>
<style>
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
	margin: 0;
	min-height: 100vh;
	display: grid;
	place-items: center;
	padding: 24px;
	background: linear-gradient(140deg, #f8fafc, #ecfeff);
	font-family: "Avenir Next", "Segoe UI", sans-serif;
	color: #0f172a;
}
.card {
	max-width: 680px;
	background: #ffffff;
	border: 1px solid #e2e8f0;
	border-radius: 18px;
	padding: 32px;
	box-shadow: 0 18px 40px rgba(15, 23, 42, 0.1);
}
h1 {
	margin: 0 0 14px;
	font-size: 1.8rem;
}
p {
	margin: 0 0 14px;
	line-height: 1.55;
	font-size: 1rem;
}
.reason {
	margin: 18px 0;
	padding: 14px 16px;
	border-left: 4px solid #dc2626;
	background: #fef2f2;
	border-radius: 10px;
}
a {
	color: #0f766e;
	font-weight: 600;
}
</style>
</head>
<body>
<main class="card">
	<h1>This domain has been disabled</h1>
	<p>Traffic to this hostname has been blocked.</p>
	<div class="reason"><strong>Reason:</strong> %s</div>
	<p>If you believe this is an error, contact <a href="mailto:%s">%s</a>.</p>
</main>
</body>
</html>`, escapedReason, supportEmail, supportEmail); err != nil {
		s.log.Error("failed to write blocked domain page", "error", err)
	}
}

func hostFromRequest(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if host == "" {
		return ""
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}

	host = strings.Trim(host, "[]")
	return normalizeName(host)
}

func (s *Server) allowCertificateHost(_ context.Context, host string) error {
	normalized := normalizeName(host)
	if normalized == "" {
		return fmt.Errorf("invalid certificate host: %q", host)
	}
	if s.inZone(normalized) {
		return nil
	}
	return fmt.Errorf("certificate host is not allowed: %s", normalized)
}
