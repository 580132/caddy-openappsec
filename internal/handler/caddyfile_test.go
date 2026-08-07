package handler

import (
	"reflect"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

	"github.com/580132/caddy-openappsec/internal/config"
)

// parseCaddyfileBlock drives parseCaddyfile over a raw Caddyfile snippet the
// way the adapter would: a Helper built from a test Dispenser, exactly like
// caddy's own httpcaddyfile tests. The input must be a single openappsec
// directive, with or without a block.
func parseCaddyfileBlock(t *testing.T, input string) (*Handler, error) {
	t.Helper()
	h := httpcaddyfile.Helper{Dispenser: caddyfile.NewTestDispenser(input)}
	mh, err := parseCaddyfile(h)
	if err != nil {
		return nil, err
	}
	hnd, ok := mh.(*Handler)
	if !ok {
		t.Fatalf("parseCaddyfile returned %T, want *Handler", mh)
	}
	return hnd, nil
}

// Test_Caddyfile_FullBlock_populates_all_fields verifies every option maps
// onto the Handler fields: the engine sub-block onto the EngineConfig, byte-
// suffix sizes, the block page, the fail-open tri-state, and custom_headers.
func Test_Caddyfile_FullBlock_populates_all_fields(t *testing.T) {
	// Given a directive with every supported option set
	const block = `
openappsec {
    engine {
        registration_socket      /tmp/cp-nano/registration
        keep_alive_path          /tmp/cp-nano/keep-alive
        verdict_signal_path      /tmp/cp-nano/verdict
        transport                socket
        family_name              test-family
        worker_id                2
        workers                  4
        attachment_type          nginx
        keep_alive_interval_ms   60000
        registration_timeout_ms  200
        reconnect_backoff_min_ms 50
        reconnect_backoff_max_ms 10000
        fail_open_timeout_ms     25
        req_max_processing_ms    5000
        res_max_processing_ms    6000
        log_level                debug
    }
    mode learn
    body_buffer_limit 10MiB
    response_buffer_limit 512KB
    block_status_code 429
    block_page_title "Blocked by openappsec"
    block_page_body "Access denied by the security policy."
    fail_open false
    skip_compressed_body_inspection true
    custom_headers {
        X-WAF-Engine openappsec
        Retry-After 60
    }
}
`

	// When the directive is parsed
	hnd, err := parseCaddyfileBlock(t, block)
	if err != nil {
		t.Fatalf("parseCaddyfile returned an error: %v", err)
	}

	// Then the engine sub-block maps onto the EngineConfig, with the config
	// defaults applied to the fields the block does not set
	wantEngine := config.EngineConfig{}
	wantEngine.SetDefaults()
	wantEngine.RegistrationSocket = "/tmp/cp-nano/registration"
	wantEngine.KeepAlivePath = "/tmp/cp-nano/keep-alive"
	wantEngine.VerdictSignalPath = "/tmp/cp-nano/verdict"
	wantEngine.Transport = config.TransportSocket
	wantEngine.FamilyName = "test-family"
	wantEngine.WorkerID = 2
	wantEngine.Workers = 4
	wantEngine.AttachmentType = "nginx"
	wantEngine.KeepAliveIntervalMs = 60000
	wantEngine.RegistrationTimeoutMs = 200
	wantEngine.ReconnectBackoffMinMs = 50
	wantEngine.ReconnectBackoffMaxMs = 10000
	wantEngine.FailOpenTimeoutMs = 25
	wantEngine.ReqMaxProcessingMs = 5000
	wantEngine.ResMaxProcessingMs = 6000
	wantEngine.LogLevel = "debug"
	if !reflect.DeepEqual(hnd.Engine, wantEngine) {
		t.Fatalf("engine mismatch:\nwant: %+v\ngot:  %+v", wantEngine, hnd.Engine)
	}

	// Then the handler options map onto the config values
	want := &Handler{
		Engine:                       wantEngine,
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
	if !reflect.DeepEqual(hnd, want) {
		t.Fatalf("handler mismatch:\nwant: %+v\ngot:  %+v", want, hnd)
	}
}

// Test_Caddyfile_MinimalBlock_applies_defaults verifies a directive with no
// options parses to a Handler carrying the config defaults, and that the
// fail-open tri-state stays nil (the default fail-open path).
func Test_Caddyfile_MinimalBlock_applies_defaults(t *testing.T) {
	// Given a directive with no options at all
	hnd, err := parseCaddyfileBlock(t, "openappsec")
	if err != nil {
		t.Fatalf("parseCaddyfile returned an error: %v", err)
	}

	// Then the handler carries the config defaults
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
		t.Fatalf("FailOpen = %v, want nil (tri-state default)", hnd.FailOpen)
	}
	if hnd.Engine.RegistrationSocket != config.DefaultRegistrationSocket {
		t.Fatalf("Engine.RegistrationSocket = %q, want %q", hnd.Engine.RegistrationSocket, config.DefaultRegistrationSocket)
	}
	if hnd.Engine.AttachmentType != config.DefaultAttachmentType {
		t.Fatalf("Engine.AttachmentType = %q, want %q", hnd.Engine.AttachmentType, config.DefaultAttachmentType)
	}
	if hnd.Engine.Workers != config.DefaultWorkers {
		t.Fatalf("Engine.Workers = %d, want %d", hnd.Engine.Workers, config.DefaultWorkers)
	}
}

// Test_Caddyfile_UnknownOption_errors verifies an option the directive does
// not know fails parsing with the option name in the error.
func Test_Caddyfile_UnknownOption_errors(t *testing.T) {
	// Given directives containing an option the directive does not know
	tests := []struct {
		name    string
		block   string
		wantErr string
	}{
		{"top-level", "openappsec {\n\tbogus 1\n}", "bogus"},
		{"engine sub-block", "openappsec {\n\tengine {\n\t\tbogus_engine 1\n\t}\n}", "bogus_engine"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When the directive is parsed
			_, err := parseCaddyfileBlock(t, tt.block)

			// Then parsing fails and the error names the unknown option
			if err == nil {
				t.Fatal("parseCaddyfile succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

// Test_Caddyfile_InvalidValues_error verifies malformed option values fail
// parsing: non-integer ints, non-boolean bools, missing arguments, and
// unparsable sizes.
func Test_Caddyfile_InvalidValues_error(t *testing.T) {
	tests := []struct {
		name    string
		block   string
		wantErr string // empty means: any error suffices
	}{
		{"block_status_code non-integer", "openappsec {\n\tblock_status_code teapot\n}", "block_status_code"},
		{"fail_open non-boolean", "openappsec {\n\tfail_open maybe\n}", "fail_open"},
		{"skip_compressed_body_inspection non-boolean", "openappsec {\n\tskip_compressed_body_inspection maybe\n}", "skip_compressed_body_inspection"},
		{"mode missing value", "openappsec {\n\tmode\n}", ""},
		{"body_buffer_limit missing value", "openappsec {\n\tbody_buffer_limit\n}", ""},
		{"body_buffer_limit unknown suffix", "openappsec {\n\tbody_buffer_limit 10XB\n}", "invalid size"},
		{"engine worker_id non-integer", "openappsec {\n\tengine {\n\t\tworker_id abc\n\t}\n}", "worker_id"},
		{"engine keep_alive_interval_ms non-integer", "openappsec {\n\tengine {\n\t\tkeep_alive_interval_ms soon\n\t}\n}", "keep_alive_interval_ms"},
		{"engine family_name missing value", "openappsec {\n\tengine {\n\t\tfamily_name\n\t}\n}", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When the directive is parsed
			_, err := parseCaddyfileBlock(t, tt.block)

			// Then parsing fails, mentioning the offending option
			if err == nil {
				t.Fatalf("parseCaddyfile(%q) succeeded, want an error", tt.block)
			}
			if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

// Test_Caddyfile_Engine_Transport_parses verifies the engine transport
// subdirective maps each supported value onto EngineConfig.Transport.
func Test_Caddyfile_Engine_Transport_parses(t *testing.T) {
	// Given engine blocks selecting each supported transport
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"memory", "memory", config.TransportMemory},
		{"socket", "socket", config.TransportSocket},
		{"shm", "shm", config.TransportSHM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := "openappsec {\n\tengine {\n\t\ttransport " + tt.value + "\n\t}\n}"

			// When the directive is parsed
			hnd, err := parseCaddyfileBlock(t, block)
			if err != nil {
				t.Fatalf("parseCaddyfile returned an error: %v", err)
			}

			// Then the transport lands in the engine config
			if hnd.Engine.Transport != tt.want {
				t.Fatalf("Engine.Transport = %q, want %q", hnd.Engine.Transport, tt.want)
			}
		})
	}
}

// Test_Caddyfile_Engine_Transport_rejects_unknown_value verifies parsing
// accepts the raw value (consistent with the other engine string options) and
// the config validation rejects transports outside memory|socket|shm.
func Test_Caddyfile_Engine_Transport_rejects_unknown_value(t *testing.T) {
	// Given an engine block with an unsupported transport value
	hnd, err := parseCaddyfileBlock(t, "openappsec {\n\tengine {\n\t\ttransport bogus\n\t\tfamily_name test\n\t}\n}")
	if err != nil {
		t.Fatalf("parseCaddyfile returned an error: %v", err)
	}

	// When the parsed handler is validated the way caddy validates it
	err = hnd.Validate()

	// Then the unsupported transport is rejected with the option named
	if err == nil {
		t.Fatal("Validate succeeded, want an error")
	}
	if !strings.Contains(err.Error(), `transport "bogus" is not supported`) {
		t.Fatalf("error = %v, want it to reject the unsupported transport", err)
	}
}

// Test_ParseSize_byte_suffixes verifies parseSize handles bare byte counts and
// the case-insensitive binary suffixes, and rejects malformed input.
func Test_ParseSize_byte_suffixes(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{"bare bytes", "100", 100, false},
		{"zero", "0", 0, false},
		{"b suffix", "10B", 10, false},
		{"kb suffix", "2KB", 2 << 10, false},
		{"kib suffix", "1KiB", 1 << 10, false},
		{"mb suffix", "4MB", 4 << 20, false},
		{"mib suffix", "10MiB", 10 << 20, false},
		{"gb suffix", "1GB", 1 << 30, false},
		{"gib suffix", "1GiB", 1 << 30, false},
		{"case-insensitive suffix", "10mib", 10 << 20, false},
		{"surrounding whitespace", " 10MiB ", 10 << 20, false},
		{"empty", "", 0, true},
		{"whitespace only", "   ", 0, true},
		{"suffix only", "MiB", 0, true},
		{"negative", "-10MiB", 0, true},
		{"fractional", "10.5MiB", 0, true},
		{"unknown suffix", "10XB", 0, true},
		{"overflow", "999999999999999999999999GiB", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When the size is parsed
			got, err := parseSize(tt.input)

			// Then the byte count is returned or the error is reported
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSize(%q) = %d, want an error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSize(%q): %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("parseSize(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}
