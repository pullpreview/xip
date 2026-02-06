package metrics

import "testing"

func TestNormalizeEndpointURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty", input: "", expected: ""},
		{name: "already http", input: "http://ingest.eu.signoz.cloud", expected: "http://ingest.eu.signoz.cloud"},
		{name: "already https", input: "https://ingest.eu.signoz.cloud", expected: "https://ingest.eu.signoz.cloud"},
		{name: "host only defaults to https", input: "ingest.eu.signoz.cloud", expected: "https://ingest.eu.signoz.cloud"},
		{name: "host with port defaults to https", input: "ingest.eu.signoz.cloud:4318", expected: "https://ingest.eu.signoz.cloud:4318"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeEndpointURL(tc.input); got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestConfiguredEndpointPrecedence(t *testing.T) {
	t.Setenv(globalEndpointEnv, "global.example")
	t.Setenv(metricsEndpointEnv, "metrics.example")

	endpoint, fromEnv := configuredEndpoint()
	if endpoint != "metrics.example" {
		t.Fatalf("expected metrics endpoint, got %q", endpoint)
	}
	if fromEnv != metricsEndpointEnv {
		t.Fatalf("expected %q source, got %q", metricsEndpointEnv, fromEnv)
	}
}

func TestConfiguredLogsEndpointPrecedence(t *testing.T) {
	t.Setenv(globalEndpointEnv, "global.example")
	t.Setenv(logsEndpointEnv, "logs.example")

	endpoint, fromEnv := configuredLogsEndpoint()
	if endpoint != "logs.example" {
		t.Fatalf("expected logs endpoint, got %q", endpoint)
	}
	if fromEnv != logsEndpointEnv {
		t.Fatalf("expected %q source, got %q", logsEndpointEnv, fromEnv)
	}
}

func TestNormalizeLogsEndpointURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty", input: "", expected: ""},
		{name: "host only", input: "ingest.eu.signoz.cloud", expected: "https://ingest.eu.signoz.cloud/v1/logs"},
		{name: "host with slash", input: "https://ingest.eu.signoz.cloud/", expected: "https://ingest.eu.signoz.cloud/v1/logs"},
		{name: "host with custom path", input: "https://collector.example.com/otel", expected: "https://collector.example.com/otel/v1/logs"},
		{name: "already logs path", input: "https://collector.example.com/v1/logs", expected: "https://collector.example.com/v1/logs"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeLogsEndpointURL(tc.input); got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}
