package config

import (
	"errors"
	"flag"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// Config captures runtime settings for the xip DNS service.
type Config struct {
	Domain                  string
	RootAddresses           []netip.Addr
	NSAddresses             []netip.Addr
	Timestamp               uint32
	TTL                     uint32
	ListenUDP               string
	ListenTCP               string
	ListenHTTP              string
	ListenHTTPS             string
	RootRedirectURL         string
	BlocklistPath           string
	BlocklistReloadInterval time.Duration
	ACMECacheDir            string
	ACMEEmail               string
}

// Load builds a Config from environment variables and CLI flags.
// CLI flags take precedence over environment variables.
func Load(args []string) (Config, error) {
	cfg := Config{}

	domainDefault := getenv("XIP_DOMAIN", "xip.test")
	rootDefault := getenv("XIP_ROOT_ADDRESSES", "127.0.0.1")
	nsDefault := getenv("XIP_NS_ADDRESSES", "127.0.0.1")
	listenDefault := getenv("XIP_LISTEN", ":53")
	listenUDPDefault := getenv("XIP_LISTEN_UDP", listenDefault)
	listenTCPDefault := getenv("XIP_LISTEN_TCP", listenDefault)
	listenHTTPDefault := getenv("XIP_LISTEN_HTTP", ":80")
	listenHTTPSDefault := getenv("XIP_LISTEN_HTTPS", ":443")
	rootRedirectDefault := strings.TrimSpace(getenv("XIP_ROOT_REDIRECT_URL", ""))
	blocklistPathDefault := getenv("XIP_BLOCKLIST_PATH", "/etc/xip/blocklist.csv")
	acmeCacheDirDefault := getenv("XIP_ACME_CACHE_DIR", "/etc/xip/acme-cache")
	acmeEmailDefault := strings.TrimSpace(getenv("XIP_ACME_EMAIL", ""))

	timestampDefault, err := getenvUint32("XIP_TIMESTAMP", 0)
	if err != nil {
		return Config{}, err
	}

	ttlDefault, err := getenvUint32("XIP_TTL", 300)
	if err != nil {
		return Config{}, err
	}

	blocklistReloadDefault, err := getenvDuration("XIP_BLOCKLIST_RELOAD_INTERVAL", 60*time.Second)
	if err != nil {
		return Config{}, err
	}

	var rootAddressesRaw string
	var nsAddressesRaw string
	var timestampRaw uint64
	var ttlRaw uint64

	fs := flag.NewFlagSet("xip", flag.ContinueOnError)
	fs.StringVar(&cfg.Domain, "domain", domainDefault, "root domain for the xip DNS zone")
	fs.StringVar(&rootAddressesRaw, "root-addresses", rootDefault, "comma or space separated IPv4 addresses returned for the root domain")
	fs.StringVar(&nsAddressesRaw, "ns-addresses", nsDefault, "comma or space separated IPv4 addresses for nameservers")
	fs.Uint64Var(&timestampRaw, "timestamp", uint64(timestampDefault), "SOA serial number")
	fs.Uint64Var(&ttlRaw, "ttl", uint64(ttlDefault), "TTL for all records")
	fs.StringVar(&cfg.ListenUDP, "listen-udp", listenUDPDefault, "UDP listen address")
	fs.StringVar(&cfg.ListenTCP, "listen-tcp", listenTCPDefault, "TCP listen address")
	fs.StringVar(&cfg.ListenHTTP, "listen-http", listenHTTPDefault, "HTTP listen address used for root redirect service")
	fs.StringVar(&cfg.ListenHTTPS, "listen-https", listenHTTPSDefault, "HTTPS listen address used for block page service")
	fs.StringVar(&cfg.RootRedirectURL, "root-redirect-url", rootRedirectDefault, "HTTP redirect target URL for root traffic")
	fs.StringVar(&cfg.BlocklistPath, "blocklist-path", blocklistPathDefault, "path to CSV blocklist file with fqdn,reason rows")
	fs.DurationVar(&cfg.BlocklistReloadInterval, "blocklist-reload-interval", blocklistReloadDefault, "reload interval for the CSV blocklist")
	fs.StringVar(&cfg.ACMECacheDir, "acme-cache-dir", acmeCacheDirDefault, "directory for Let's Encrypt certificate cache")
	fs.StringVar(&cfg.ACMEEmail, "acme-email", acmeEmailDefault, "email used for Let's Encrypt registration")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	normalizedDomain, err := normalizeDomain(cfg.Domain)
	if err != nil {
		return Config{}, err
	}
	cfg.Domain = normalizedDomain

	if timestampRaw > math.MaxUint32 {
		return Config{}, errors.New("timestamp must be <= 4294967295")
	}
	cfg.Timestamp = uint32(timestampRaw)

	if ttlRaw > math.MaxUint32 {
		return Config{}, errors.New("ttl must be <= 4294967295")
	}
	cfg.TTL = uint32(ttlRaw)

	rootAddresses, err := parseIPv4List(rootAddressesRaw)
	if err != nil {
		return Config{}, fmt.Errorf("invalid root addresses: %w", err)
	}
	cfg.RootAddresses = rootAddresses

	nsAddresses, err := parseIPv4List(nsAddressesRaw)
	if err != nil {
		return Config{}, fmt.Errorf("invalid NS addresses: %w", err)
	}
	cfg.NSAddresses = nsAddresses

	if strings.TrimSpace(cfg.ListenUDP) == "" {
		return Config{}, errors.New("listen-udp cannot be empty")
	}
	if strings.TrimSpace(cfg.ListenTCP) == "" {
		return Config{}, errors.New("listen-tcp cannot be empty")
	}
	if cfg.BlocklistReloadInterval <= 0 {
		return Config{}, errors.New("blocklist-reload-interval must be greater than 0")
	}
	if strings.TrimSpace(cfg.ListenHTTPS) != "" && strings.TrimSpace(cfg.ACMECacheDir) == "" {
		return Config{}, errors.New("acme-cache-dir cannot be empty when listen-https is configured")
	}
	if strings.TrimSpace(cfg.RootRedirectURL) != "" {
		if strings.TrimSpace(cfg.ListenHTTP) == "" {
			return Config{}, errors.New("listen-http cannot be empty when root redirect is configured")
		}
		if err := validateAbsoluteURL(cfg.RootRedirectURL); err != nil {
			return Config{}, fmt.Errorf("invalid root redirect URL: %w", err)
		}
	}

	return cfg, nil
}

func getenv(key, fallback string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func getenvUint32(key string, fallback uint32) (uint32, error) {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}

	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}

	return uint32(parsed), nil
}

func getenvDuration(key string, fallback time.Duration) (time.Duration, error) {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}

	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}

	return parsed, nil
}

func parseIPv4List(raw string) ([]netip.Addr, error) {
	parts := splitList(raw)
	if len(parts) == 0 {
		return nil, errors.New("at least one IPv4 address is required")
	}

	addresses := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", part, err)
		}
		if !addr.Is4() {
			return nil, fmt.Errorf("%q is not an IPv4 address", part)
		}
		addresses = append(addresses, addr)
	}

	return addresses, nil
}

func splitList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', ';', ' ', '\t', '\n', '\r':
			return true
		default:
			return false
		}
	})
}

func normalizeDomain(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))
	domain = strings.TrimSuffix(domain, ".")

	if domain == "" {
		return "", errors.New("domain cannot be empty")
	}
	if len(domain) > 253 {
		return "", errors.New("domain exceeds 253 characters")
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return "", errors.New("domain contains empty label")
		}
		if len(label) > 63 {
			return "", fmt.Errorf("label %q exceeds 63 characters", label)
		}
		if !labelPattern.MatchString(label) {
			return "", fmt.Errorf("invalid label %q", label)
		}
	}

	return domain, nil
}

func validateAbsoluteURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if !parsed.IsAbs() {
		return errors.New("must be absolute and include scheme")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return errors.New("must include host")
	}
	return nil
}
