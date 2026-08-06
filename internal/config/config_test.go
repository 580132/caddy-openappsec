package config

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// update rewrites the golden files when set:
// go test ./internal/config/ -run Defaults -update
var update = flag.Bool("update", false, "update golden files")

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func requireErrorContaining(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("expected error containing %q, got: %v", substr, err)
	}
}

// requireJSONEqual compares two JSON documents semantically (order-insensitive).
func requireJSONEqual(t *testing.T, want, got string) {
	t.Helper()
	var wantV, gotV any
	requireNoError(t, json.Unmarshal([]byte(want), &wantV))
	requireNoError(t, json.Unmarshal([]byte(got), &gotV))
	if !reflect.DeepEqual(wantV, gotV) {
		t.Fatalf("JSON mismatch\nwant: %s\ngot:  %s", want, got)
	}
}

// checkGolden compares got against the golden file in testdata, or writes it
// when -update is set.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	golden := filepath.Join("testdata", name)
	if *update {
		requireNoError(t, os.WriteFile(golden, got, 0o644))
	}
	want, err := os.ReadFile(golden)
	requireNoError(t, err)
	requireJSONEqual(t, string(want), string(got))
}

func Test_EngineConfig_roundtrips_when_fully_populated(t *testing.T) {
	// Given
	want := EngineConfig{
		RegistrationSocket:        "/tmp/cp-nano/registration",
		KeepAlivePath:             "/tmp/cp-nano/keep-alive",
		VerdictSignalPath:         "/tmp/cp-nano/verdict",
		FamilyName:                "test-family",
		WorkerID:                  2,
		Workers:                   4,
		AttachmentType:            "nginx",
		KeepAliveIntervalMs:       60000,
		RegistrationTimeoutMs:     200,
		ReconnectBackoffMinMs:     50,
		ReconnectBackoffMaxMs:     10000,
		FailOpen:                  boolPtr(false),
		FailOpenTimeoutMs:         25,
		FailOpenHoldTimeoutMs:     75,
		ReqMaxProcessingMs:        5000,
		ResMaxProcessingMs:        6000,
		MinRetriesForVerdict:      2,
		MaxRetriesForVerdict:      20,
		HoldVerdictRetries:        5,
		HoldVerdictPollingMs:      2,
		BodySizeTrigger:           100000,
		DecompressionPoolSize:     131072,
		RecompressionPoolSize:     8192,
		IsBrotliInspectionEnabled: true,
		LogLevel:                  "debug",
	}

	// When
	data, err := json.Marshal(want)
	requireNoError(t, err)
	var got EngineConfig
	requireNoError(t, json.Unmarshal(data, &got))

	// Then
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v\njson: %s", want, got, data)
	}
}

func Test_HandlerConfig_roundtrips_when_fully_populated(t *testing.T) {
	// Given
	want := HandlerConfig{
		BodyBufferLimit:              20971520,
		ResponseBufferLimit:          8388608,
		BlockStatusCode:              429,
		BlockPageTitle:               "Blocked by openappsec",
		BlockPageBody:                "Access denied by security policy.",
		Mode:                         ModeLearn,
		SkipCompressedBodyInspection: true,
		FailOpen:                     boolPtr(false),
		CustomHeaders:                map[string]string{"X-WAF-Engine": "openappsec", "Retry-After": "60"},
	}

	// When
	data, err := json.Marshal(want)
	requireNoError(t, err)
	var got HandlerConfig
	requireNoError(t, json.Unmarshal(data, &got))

	// Then
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v\njson: %s", want, got, data)
	}
}

func Test_EngineConfig_Defaults_match_golden(t *testing.T) {
	// Given — an empty JSON document, as a user would provide for all-defaults.
	// family_name is required and has no default, so it is not part of the golden.
	var cfg EngineConfig
	requireNoError(t, json.Unmarshal([]byte("{}"), &cfg))

	// When
	cfg.SetDefaults()
	got, err := json.MarshalIndent(cfg, "", "  ")
	requireNoError(t, err)

	// Then
	checkGolden(t, "engine_defaults.golden.json", got)
}

func Test_HandlerConfig_Defaults_match_golden(t *testing.T) {
	// Given — an empty JSON document.
	var cfg HandlerConfig
	requireNoError(t, json.Unmarshal([]byte("{}"), &cfg))

	// When
	cfg.SetDefaults()
	got, err := json.MarshalIndent(cfg, "", "  ")
	requireNoError(t, err)

	// Then
	checkGolden(t, "handler_defaults.golden.json", got)
}

func Test_EngineConfig_Validate_rejects_invalid_configs(t *testing.T) {
	// Given — a valid base config (defaults + required family_name).
	tests := []struct {
		name    string
		mutate  func(*EngineConfig)
		wantErr string
	}{
		{"empty family_name", func(c *EngineConfig) { c.FamilyName = "" }, "family_name"},
		{"whitespace family_name", func(c *EngineConfig) { c.FamilyName = "   " }, "family_name"},
		{"unknown attachment_type", func(c *EngineConfig) { c.AttachmentType = "apache" }, "attachment_type"},
		{"negative keep_alive_interval_ms", func(c *EngineConfig) { c.KeepAliveIntervalMs = -1 }, "keep_alive_interval_ms"},
		{"zero keep_alive_interval_ms", func(c *EngineConfig) { c.KeepAliveIntervalMs = 0 }, "keep_alive_interval_ms"},
		{"zero registration_timeout_ms", func(c *EngineConfig) { c.RegistrationTimeoutMs = 0 }, "registration_timeout_ms"},
		{"negative fail_open_timeout_ms", func(c *EngineConfig) { c.FailOpenTimeoutMs = -50 }, "fail_open_timeout_ms"},
		{"backoff max below min", func(c *EngineConfig) { c.ReconnectBackoffMinMs = 1000; c.ReconnectBackoffMaxMs = 100 }, "reconnect_backoff_max_ms"},
		{"retries max below min", func(c *EngineConfig) { c.MinRetriesForVerdict = 10; c.MaxRetriesForVerdict = 5 }, "max_retries_for_verdict"},
		{"zero workers", func(c *EngineConfig) { c.Workers = 0 }, "workers"},
		{"negative workers", func(c *EngineConfig) { c.Workers = -1 }, "workers"},
		{"negative worker_id", func(c *EngineConfig) { c.WorkerID = -2 }, "worker_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			c := EngineConfig{FamilyName: "test"}
			c.SetDefaults()
			tt.mutate(&c)

			// When
			err := c.Validate()

			// Then
			requireErrorContaining(t, err, tt.wantErr)
		})
	}
}

func Test_HandlerConfig_Validate_rejects_invalid_configs(t *testing.T) {
	// Given — a valid base config (defaults).
	tests := []struct {
		name    string
		mutate  func(*HandlerConfig)
		wantErr string
	}{
		{"zero body_buffer_limit", func(c *HandlerConfig) { c.BodyBufferLimit = 0 }, "body_buffer_limit"},
		{"negative response_buffer_limit", func(c *HandlerConfig) { c.ResponseBufferLimit = -1 }, "response_buffer_limit"},
		{"bad mode", func(c *HandlerConfig) { c.Mode = "banana" }, "mode"},
		{"status code below 400", func(c *HandlerConfig) { c.BlockStatusCode = 200 }, "block_status_code"},
		{"status code above 599", func(c *HandlerConfig) { c.BlockStatusCode = 600 }, "block_status_code"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			c := HandlerConfig{}
			c.SetDefaults()
			tt.mutate(&c)

			// When
			err := c.Validate()

			// Then
			requireErrorContaining(t, err, tt.wantErr)
		})
	}
}

func Test_EngineConfig_Validate_requires_family_name(t *testing.T) {
	// Given — empty JSON, defaults applied.
	var cfg EngineConfig
	requireNoError(t, json.Unmarshal([]byte("{}"), &cfg))
	cfg.SetDefaults()

	// When
	err := cfg.Validate()

	// Then
	requireErrorContaining(t, err, "family_name")
}

func Test_EngineConfig_Defaults_are_valid_when_family_name_provided(t *testing.T) {
	// Given
	var cfg EngineConfig
	requireNoError(t, json.Unmarshal([]byte(`{"family_name": "test"}`), &cfg))

	// When
	cfg.SetDefaults()
	err := cfg.Validate()

	// Then
	requireNoError(t, err)
}

func Test_HandlerConfig_Defaults_are_valid(t *testing.T) {
	// Given
	var cfg HandlerConfig
	requireNoError(t, json.Unmarshal([]byte("{}"), &cfg))

	// When
	cfg.SetDefaults()
	err := cfg.Validate()

	// Then
	requireNoError(t, err)
}

func Test_HandlerConfig_Validate_allows_explicit_fail_closed(t *testing.T) {
	// Given — fail_open explicitly false must survive SetDefaults.
	cfg := HandlerConfig{FailOpen: boolPtr(false)}
	cfg.SetDefaults()

	// When
	err := cfg.Validate()

	// Then
	requireNoError(t, err)
	if cfg.FailOpen == nil || *cfg.FailOpen {
		t.Fatalf("explicit fail_open:false was overridden by defaults, got %v", cfg.FailOpen)
	}
}
