package handler

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"

	"github.com/yourname/caddy-openappsec/internal/config"
)

// fullyPopulatedHandler returns a Handler with every exported field set, as a
// caddy user would after configuring all options.
func fullyPopulatedHandler() *Handler {
	return &Handler{
		Engine: config.EngineConfig{
			RegistrationSocket:    "/tmp/cp-nano/registration",
			KeepAlivePath:         "/tmp/cp-nano/keep-alive",
			VerdictSignalPath:     "/tmp/cp-nano/verdict",
			FamilyName:            "test-family",
			WorkerID:              2,
			Workers:               4,
			AttachmentType:        "nginx",
			KeepAliveIntervalMs:   60000,
			RegistrationTimeoutMs: 200,
			ReconnectBackoffMinMs: 50,
			ReconnectBackoffMaxMs: 10000,
			FailOpenTimeoutMs:     25,
			ReqMaxProcessingMs:    5000,
			ResMaxProcessingMs:    6000,
			LogLevel:              "debug",
		},
		Mode:                         config.ModeLearn,
		BodyBufferLimit:              10 << 20,
		ResponseBufferLimit:          512 << 10,
		BlockStatusCode:              429,
		BlockPageTitle:               "Blocked by openappsec",
		BlockPageBody:                "Access denied by the security policy.",
		FailOpen:                     boolPtr(false),
		SkipCompressedBodyInspection: true,
		CustomHeaders:                map[string]string{"X-WAF-Engine": "openappsec", "Retry-After": "60"},
	}
}

// Test_Handler_JSON_roundtrips_when_fully_populated verifies
// json.Marshal followed by json.Unmarshal preserves every exported field of
// the module.
func Test_Handler_JSON_roundtrips_when_fully_populated(t *testing.T) {
	// Given a fully populated handler
	want := fullyPopulatedHandler()

	// When it is marshaled and unmarshaled back
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var got Handler
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Then every exported field survives the round trip
	if !reflect.DeepEqual(want, &got) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v\njson: %s", want, &got, data)
	}
}

// Test_Handler_JSON_snake_case_keys_unmarshal verifies a hand-written caddy
// JSON config (snake_case keys) populates the module exactly.
func Test_Handler_JSON_snake_case_keys_unmarshal(t *testing.T) {
	// Given the JSON a caddy user writes for the module
	const cfgJSON = `{
		"engine": {
			"registration_socket": "/tmp/cp-nano/registration",
			"keep_alive_path": "/tmp/cp-nano/keep-alive",
			"verdict_signal_path": "/tmp/cp-nano/verdict",
			"family_name": "test-family",
			"worker_id": 2,
			"workers": 4,
			"attachment_type": "nginx",
			"keep_alive_interval_ms": 60000,
			"registration_timeout_ms": 200,
			"reconnect_backoff_min_ms": 50,
			"reconnect_backoff_max_ms": 10000,
			"fail_open_timeout_ms": 25,
			"req_max_processing_ms": 5000,
			"res_max_processing_ms": 6000,
			"log_level": "debug"
		},
		"mode": "learn",
		"body_buffer_limit": 10485760,
		"response_buffer_limit": 524288,
		"block_status_code": 429,
		"block_page_title": "Blocked by openappsec",
		"block_page_body": "Access denied by the security policy.",
		"fail_open": false,
		"skip_compressed_body_inspection": true,
		"custom_headers": {
			"X-WAF-Engine": "openappsec",
			"Retry-After": "60"
		}
	}`

	// When it is unmarshaled into a handler
	var hnd Handler
	if err := json.Unmarshal([]byte(cfgJSON), &hnd); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Then every field is populated from its snake_case key
	want := fullyPopulatedHandler()
	if !reflect.DeepEqual(&hnd, want) {
		t.Fatalf("unmarshal mismatch:\nwant: %+v\ngot:  %+v", want, &hnd)
	}
}

// Test_Handler_JSON_marshals_snake_case_keys documents the exact JSON key
// names the module emits, so the README can document the config surface.
func Test_Handler_JSON_marshals_snake_case_keys(t *testing.T) {
	// Given a fully populated handler
	hnd := fullyPopulatedHandler()

	// When it is marshaled
	data, err := json.Marshal(hnd)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	// Then the keys are the snake_case names caddy uses
	for _, key := range []string{
		`"engine"`, `"mode"`, `"body_buffer_limit"`, `"response_buffer_limit"`,
		`"block_status_code"`, `"block_page_title"`, `"block_page_body"`,
		`"fail_open"`, `"skip_compressed_body_inspection"`, `"custom_headers"`,
	} {
		if !strings.Contains(string(data), key) {
			t.Fatalf("marshaled JSON missing key %s: %s", key, data)
		}
	}
}

// Test_Handler_JSON_defaults_after_set_defaults verifies an empty JSON config
// plus SetDefaults (the same defaults Provision applies) yields the config
// defaults, with the fail-open tri-state left nil.
func Test_Handler_JSON_defaults_after_set_defaults(t *testing.T) {
	// Given an empty JSON config
	var hnd Handler
	if err := json.Unmarshal([]byte("{}"), &hnd); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// When defaults are applied the way Provision applies them
	hnd.SetDefaults()

	// Then every zero field takes the config default
	if hnd.Mode != config.DefaultMode {
		t.Fatalf("Mode = %q, want %q", hnd.Mode, config.DefaultMode)
	}
	if hnd.BodyBufferLimit != config.DefaultBodyBufferLimit {
		t.Fatalf("BodyBufferLimit = %d, want %d", hnd.BodyBufferLimit, config.DefaultBodyBufferLimit)
	}
	if hnd.ResponseBufferLimit != config.DefaultResponseBufferLimit {
		t.Fatalf("ResponseBufferLimit = %d, want %d", hnd.ResponseBufferLimit, config.DefaultResponseBufferLimit)
	}
	if hnd.BlockStatusCode != config.DefaultBlockStatusCode {
		t.Fatalf("BlockStatusCode = %d, want %d", hnd.BlockStatusCode, config.DefaultBlockStatusCode)
	}
	if hnd.BlockPageTitle != DefaultBlockPageTitle {
		t.Fatalf("BlockPageTitle = %q, want %q", hnd.BlockPageTitle, DefaultBlockPageTitle)
	}
	if hnd.BlockPageBody != DefaultBlockPageBody {
		t.Fatalf("BlockPageBody = %q, want %q", hnd.BlockPageBody, DefaultBlockPageBody)
	}
	if hnd.FailOpen != nil {
		t.Fatalf("FailOpen = %v, want nil (fail-open default path)", hnd.FailOpen)
	}
	if hnd.Engine.RegistrationSocket != config.DefaultRegistrationSocket {
		t.Fatalf("Engine.RegistrationSocket = %q, want %q", hnd.Engine.RegistrationSocket, config.DefaultRegistrationSocket)
	}
	if hnd.Engine.AttachmentType != config.DefaultAttachmentType {
		t.Fatalf("Engine.AttachmentType = %q, want %q", hnd.Engine.AttachmentType, config.DefaultAttachmentType)
	}
}

// Test_Handler_JSON_fail_open_tristate verifies the *bool tri-state: an
// absent fail_open stays nil (the fail-open default path), while explicit
// false and true survive unmarshaling.
func Test_Handler_JSON_fail_open_tristate(t *testing.T) {
	// Given JSON configs with fail_open absent, false and true
	tests := []struct {
		name string
		cfg  string
		want *bool
	}{
		{"absent", `{}`, nil},
		{"explicit false", `{"fail_open": false}`, boolPtr(false)},
		{"explicit true", `{"fail_open": true}`, boolPtr(true)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When the config is unmarshaled
			var hnd Handler
			if err := json.Unmarshal([]byte(tt.cfg), &hnd); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}

			// Then the tri-state is preserved
			if !reflect.DeepEqual(hnd.FailOpen, tt.want) {
				t.Fatalf("FailOpen = %v, want %v", hnd.FailOpen, tt.want)
			}
		})
	}
}

// Test_Handler_JSON_unknown_key_behavior documents how unknown JSON keys are
// treated: plain json.Unmarshal ignores them, while caddy's
// StrictUnmarshalJSON — the decoder caddy uses for module configs — rejects
// them (caddy.StrictUnmarshalJSON sets DisallowUnknownFields).
func Test_Handler_JSON_unknown_key_behavior(t *testing.T) {
	// Given a JSON config carrying an unrecognized key
	const cfgJSON = `{"mode": "prevent", "bogus_key": 1}`

	// When decoded with the standard decoder, the unknown key is ignored
	var withStd Handler
	if err := json.Unmarshal([]byte(cfgJSON), &withStd); err != nil {
		t.Fatalf("json.Unmarshal rejected the unknown key: %v", err)
	}
	if withStd.Mode != config.ModePrevent {
		t.Fatalf("Mode = %q, want %q (known keys still decode)", withStd.Mode, config.ModePrevent)
	}

	// When decoded with caddy's strict decoder, the unknown key is rejected
	var withStrict Handler
	err := caddy.StrictUnmarshalJSON([]byte(cfgJSON), &withStrict)
	if err == nil {
		t.Fatal("StrictUnmarshalJSON accepted the unknown key")
	}
	if !strings.Contains(err.Error(), "bogus_key") {
		t.Fatalf("error = %v, want it to name the unknown key", err)
	}
}
