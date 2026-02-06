package blocklist

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// Stats represents the current blocklist health state.
type Stats struct {
	BlockedDomains int
	LastReload     time.Time
}

// Manager keeps an in-memory blocklist refreshed from a CSV file.
type Manager struct {
	path           string
	reloadInterval time.Duration
	log            *slog.Logger

	mu         sync.RWMutex
	blocked    map[string]string
	lastReload time.Time
}

func New(path string, reloadInterval time.Duration, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	if reloadInterval <= 0 {
		reloadInterval = 60 * time.Second
	}

	return &Manager{
		path:           strings.TrimSpace(path),
		reloadInterval: reloadInterval,
		log:            logger,
		blocked:        make(map[string]string),
	}
}

func (m *Manager) Reload() error {
	entries, err := readEntries(m.path)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.blocked = entries
	m.lastReload = time.Now().UTC()
	m.mu.Unlock()

	m.log.Debug("reloaded blocklist", "path", m.path, "blocked_domains", len(entries))
	return nil
}

func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(m.reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Reload(); err != nil {
				m.log.Warn("failed to reload blocklist", "path", m.path, "error", err)
			}
		}
	}
}

func (m *Manager) Lookup(host string) (string, bool) {
	normalized := normalizeFQDN(host)
	if normalized == "" {
		return "", false
	}

	m.mu.RLock()
	reason, ok := m.blocked[normalized]
	m.mu.RUnlock()
	return reason, ok
}

func (m *Manager) Stats() Stats {
	m.mu.RLock()
	stats := Stats{
		BlockedDomains: len(m.blocked),
		LastReload:     m.lastReload,
	}
	m.mu.RUnlock()
	return stats
}

func readEntries(path string) (map[string]string, error) {
	entries := make(map[string]string)
	if strings.TrimSpace(path) == "" {
		return entries, nil
	}

	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return entries, nil
		}
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1

	row := 0
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("row %d: %w", row+1, err)
		}
		row++

		if len(record) == 0 {
			continue
		}
		if row == 1 && isHeader(record) {
			continue
		}
		if len(record) != 2 {
			return nil, fmt.Errorf("row %d: expected 2 columns, got %d", row, len(record))
		}

		fqdn, err := normalizeFQDNStrict(record[0])
		if err != nil {
			return nil, fmt.Errorf("row %d: invalid fqdn: %w", row, err)
		}

		reason := strings.TrimSpace(record[1])
		if reason == "" {
			return nil, fmt.Errorf("row %d: reason cannot be empty", row)
		}

		entries[fqdn] = reason
	}

	return entries, nil
}

func isHeader(record []string) bool {
	if len(record) < 2 {
		return false
	}
	first := strings.EqualFold(strings.TrimSpace(record[0]), "fqdn")
	second := strings.EqualFold(strings.TrimSpace(record[1]), "reason")
	return first && second
}

func normalizeFQDN(raw string) string {
	fqdn, err := normalizeFQDNStrict(raw)
	if err != nil {
		return ""
	}
	return fqdn
}

func normalizeFQDNStrict(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))
	domain = strings.TrimSuffix(domain, ".")

	if domain == "" {
		return "", errors.New("fqdn cannot be empty")
	}
	if len(domain) > 253 {
		return "", errors.New("fqdn exceeds 253 characters")
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return "", errors.New("fqdn contains empty label")
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
