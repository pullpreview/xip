package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

const (
	globalEndpointEnv  = "OTEL_EXPORTER_OTLP_ENDPOINT"
	metricsEndpointEnv = "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"
)

// DNSRequestRecorder records telemetry for DNS requests.
type DNSRequestRecorder struct {
	counter metric.Int64Counter
}

// RecordDNSRequest increments the DNS request counter with request attributes.
func (r *DNSRequestRecorder) RecordDNSRequest(ctx context.Context, fqdn string, domain string, tld string) {
	if r == nil || r.counter == nil {
		return
	}

	r.counter.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("fqdn", fqdn),
			attribute.String("domain", domain),
			attribute.String("tld", tld),
		),
	)
}

// NewDNSRequestRecorder builds an OTEL-backed DNS request recorder from standard OTEL env vars.
// If no OTLP endpoint is configured, it returns a no-op recorder.
func NewDNSRequestRecorder(ctx context.Context, logger *slog.Logger) (*DNSRequestRecorder, func(context.Context) error, error) {
	if logger == nil {
		logger = slog.Default()
	}

	rawEndpoint, fromEnv := configuredEndpoint()
	if rawEndpoint == "" {
		logger.Info("otel metrics disabled", "reason", globalEndpointEnv+" / "+metricsEndpointEnv+" not set")
		return &DNSRequestRecorder{}, nil, nil
	}

	normalizedURL := normalizeEndpointURL(rawEndpoint)
	exporter, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpointURL(normalizedURL))
	if err != nil {
		return nil, nil, fmt.Errorf("create otel metric exporter: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(10*time.Second))
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := provider.Meter("xip")

	counter, err := meter.Int64Counter(
		"xip_dns_requests_total",
		metric.WithDescription("Number of DNS requests handled by xip"),
	)
	if err != nil {
		_ = provider.Shutdown(ctx)
		return nil, nil, fmt.Errorf("create otel counter: %w", err)
	}

	logger.Info("otel metrics enabled", "env", fromEnv, "endpoint", normalizedURL)

	return &DNSRequestRecorder{counter: counter}, provider.Shutdown, nil
}

func configuredEndpoint() (string, string) {
	if value := strings.TrimSpace(os.Getenv(metricsEndpointEnv)); value != "" {
		return value, metricsEndpointEnv
	}
	if value := strings.TrimSpace(os.Getenv(globalEndpointEnv)); value != "" {
		return value, globalEndpointEnv
	}
	return "", ""
}

func normalizeEndpointURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "://") {
		return trimmed
	}

	// If scheme is omitted, default to HTTPS.
	return "https://" + trimmed
}
