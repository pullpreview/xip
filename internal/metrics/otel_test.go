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
