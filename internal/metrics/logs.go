package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path"
	"strings"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

const logsEndpointEnv = "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"

// NewOTELLogHandler builds an OTEL-backed slog handler from standard OTEL env vars.
// If no OTLP endpoint is configured, it returns nil.
func NewOTELLogHandler(ctx context.Context, logger *slog.Logger) (slog.Handler, func(context.Context) error, error) {
	if logger == nil {
		logger = slog.Default()
	}

	rawEndpoint, fromEnv := configuredLogsEndpoint()
	if rawEndpoint == "" {
		logger.Info("otel logs disabled", "reason", globalEndpointEnv+" / "+logsEndpointEnv+" not set")
		return nil, nil, nil
	}

	normalizedURL := normalizeLogsEndpointURL(rawEndpoint)
	exporter, err := otlploghttp.New(ctx, otlploghttp.WithEndpointURL(normalizedURL))
	if err != nil {
		return nil, nil, fmt.Errorf("create otel log exporter: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(resource.NewSchemaless(attribute.String("service.name", "xip"))),
	)

	logger.Info("otel logs enabled", "env", fromEnv, "endpoint", normalizedURL)
	return otelslog.NewHandler("xip", otelslog.WithLoggerProvider(provider)), provider.Shutdown, nil
}

func configuredLogsEndpoint() (string, string) {
	if value := strings.TrimSpace(os.Getenv(logsEndpointEnv)); value != "" {
		return value, logsEndpointEnv
	}
	if value := strings.TrimSpace(os.Getenv(globalEndpointEnv)); value != "" {
		return value, globalEndpointEnv
	}
	return "", ""
}

func normalizeLogsEndpointURL(raw string) string {
	normalized := normalizeEndpointURL(raw)
	if normalized == "" {
		return ""
	}

	parsed, err := url.Parse(normalized)
	if err != nil {
		return normalized
	}

	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/v1/logs"
	} else if !strings.HasSuffix(parsed.Path, "/v1/logs") {
		parsed.Path = path.Join(parsed.Path, "v1", "logs")
	}

	return parsed.String()
}
