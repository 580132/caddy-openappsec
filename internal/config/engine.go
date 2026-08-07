package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// supportedAttachmentTypes lists the attachment_type values the engine accepts.
// The openappsec engine defines an attachment type for nginx (§G.1) but none
// for Caddy, so "nginx" is the only supported value for now.
var supportedAttachmentTypes = []string{"nginx"}

// supportedTransports lists the EngineConfig.Transport values the attachment
// dialer supports. The empty value is intentionally absent: it is valid and
// means the platform default.
var supportedTransports = []string{TransportMemory, TransportSocket, TransportSHM}

// EngineConfig configures the attachment's connection to the openappsec nano
// engine: shared-memory socket paths, registration and keep-alive timing,
// fail-open behavior, verdict retries, and inspection limits. Defaults mirror
// the openappsec nginx attachment reference (docs/attachment-protocol.md §H.1).
type EngineConfig struct {
	// Transport selects how the attachment connects to the openappsec engine.
	// "memory" is in-process pipes (tests/local E2E), "socket" is cross-process
	// TCP (mock engine CLI / local E2E), and "shm" is linux shared-memory
	// (production). Empty means the platform default (linux: shm, others:
	// unreachable stub), resolved by the dialer.
	Transport string `json:"transport,omitempty"`
	// RegistrationSocket is where the engine listens for attachment
	// registration (SHARED_REGISTRATION_SIGNAL_PATH, §G.1).
	RegistrationSocket string `json:"registration_socket,omitempty"`
	// KeepAlivePath is where the engine listens for keep-alive pings
	// (SHARED_KEEP_ALIVE_PATH, §G.3).
	KeepAlivePath string `json:"keep_alive_path,omitempty"`
	// VerdictSignalPath is the path the engine publishes for the verdict
	// signal (SHARED_VERDICT_SIGNAL_PATH, §G.2).
	VerdictSignalPath string `json:"verdict_signal_path,omitempty"`
	// FamilyName identifies this attachment family to the engine in the
	// registration and keep-alive handshakes (§G.1, §G.3); the nginx reference
	// sends its container id. Required, no default.
	FamilyName string `json:"family_name,omitempty"`
	// WorkerID is the zero-based index of this worker in the attachment.
	WorkerID int `json:"worker_id,omitempty"`
	// Workers is the number of attachment worker processes.
	Workers int `json:"workers,omitempty"`
	// AttachmentType is the family the attachment presents to the engine
	// (§G.1). "nginx" is the only supported value today.
	AttachmentType string `json:"attachment_type,omitempty"`
	// KeepAliveIntervalMs is the keep-alive interval. The engine expires a
	// registration not kept alive within DEFAULT_KEEP_ALIVE_INTERVAL_MSEC
	// (300000 ms), so the interval must stay below that expiry window.
	KeepAliveIntervalMs int `json:"keep_alive_interval_ms,omitempty"`
	// RegistrationTimeoutMs bounds the registration handshake.
	RegistrationTimeoutMs int `json:"registration_timeout_ms,omitempty"`
	// ReconnectBackoffMinMs is the initial reconnect backoff; reconnects grow
	// exponentially with jitter up to ReconnectBackoffMaxMs.
	ReconnectBackoffMinMs int `json:"reconnect_backoff_min_ms,omitempty"`
	// ReconnectBackoffMaxMs caps the exponential reconnect backoff.
	ReconnectBackoffMaxMs int `json:"reconnect_backoff_max_ms,omitempty"`
	// FailOpen is nil for the default (true, fail-open). The nginx reference
	// never fails closed by default (§H.1); set it explicitly to false to
	// fail closed.
	FailOpen *bool `json:"fail_open,omitempty"`
	// FailOpenTimeoutMs is how long to wait for the engine before failing
	// open (ngx_cp_utils.c:99).
	FailOpenTimeoutMs int `json:"fail_open_timeout_ms,omitempty"`
	// FailOpenHoldTimeoutMs is how long a hold-verdict transaction may last
	// before failing open.
	FailOpenHoldTimeoutMs int `json:"fail_open_hold_timeout_ms,omitempty"`
	// ReqMaxProcessingMs bounds request inspection time before timeout.
	ReqMaxProcessingMs int `json:"req_max_processing_ms,omitempty"`
	// ResMaxProcessingMs bounds response inspection time before timeout.
	ResMaxProcessingMs int `json:"res_max_processing_ms,omitempty"`
	// MinRetriesForVerdict is the minimum number of verdict poll retries.
	MinRetriesForVerdict int `json:"min_retries_for_verdict,omitempty"`
	// MaxRetriesForVerdict is the maximum number of verdict poll retries.
	MaxRetriesForVerdict int `json:"max_retries_for_verdict,omitempty"`
	// HoldVerdictRetries is how many times a DELAYED verdict is re-polled.
	HoldVerdictRetries int `json:"hold_verdict_retries,omitempty"`
	// HoldVerdictPollingMs is the delay between verdict polls.
	HoldVerdictPollingMs int `json:"hold_verdict_polling_ms,omitempty"`
	// BodySizeTrigger is the body size above which buffered inspection
	// switches to the trigger path (ngx_cp_utils.c:119).
	BodySizeTrigger int `json:"body_size_trigger,omitempty"`
	// DecompressionPoolSize sizes the response decompression pool (§J).
	DecompressionPoolSize int `json:"decompression_pool_size,omitempty"`
	// RecompressionPoolSize sizes the response recompression pool (§J).
	RecompressionPoolSize int `json:"recompression_pool_size,omitempty"`
	// IsBrotliInspectionEnabled gates brotli decompression (§H, §J).
	IsBrotliInspectionEnabled bool `json:"is_brotli_inspection_enabled,omitempty"`
	// LogLevel is the attachment's log level.
	LogLevel string `json:"log_level,omitempty"`
}

// UniqueID returns the instance-aware identity this attachment presents to
// the engine: "<family>_<worker_id+1>" when a family name is set, else just
// "<worker_id+1>" — mirroring the nginx reference (ngx_cp_initializer.c:798-804).
// The engine uses this same value as the shared-memory queue name
// (nginx_attachment.cc:537-538 initIpc(curr_instance_unique_id) →
// shmem_ipc.c:78 "__cp_nano_%s_shared_memory_%s__") and validates the phase-2
// comm uid against it (nginx_attachment.cc getUidFromSocket), so every wire
// value that names the instance — the comm-frame uid and the shm queue name —
// must be this exact string.
func (c *EngineConfig) UniqueID() string {
	if c.FamilyName != "" {
		return fmt.Sprintf("%s_%d", c.FamilyName, c.WorkerID+1)
	}
	return fmt.Sprintf("%d", c.WorkerID+1)
}

// SetDefaults fills zero-valued fields with the openappsec reference defaults.
// Fields explicitly set by the user are left untouched, so an empty config
// becomes the reference default configuration. Call before Validate.
func (c *EngineConfig) SetDefaults() {
	if c.RegistrationSocket == "" {
		c.RegistrationSocket = DefaultRegistrationSocket
	}
	if c.KeepAlivePath == "" {
		c.KeepAlivePath = DefaultKeepAlivePath
	}
	if c.VerdictSignalPath == "" {
		c.VerdictSignalPath = DefaultVerdictSignalPath
	}
	if c.Workers == 0 {
		c.Workers = DefaultWorkers
	}
	if c.AttachmentType == "" {
		c.AttachmentType = DefaultAttachmentType
	}
	if c.KeepAliveIntervalMs == 0 {
		c.KeepAliveIntervalMs = DefaultKeepAliveIntervalMs
	}
	if c.RegistrationTimeoutMs == 0 {
		c.RegistrationTimeoutMs = DefaultRegistrationTimeoutMs
	}
	if c.ReconnectBackoffMinMs == 0 {
		c.ReconnectBackoffMinMs = DefaultReconnectBackoffMinMs
	}
	if c.ReconnectBackoffMaxMs == 0 {
		c.ReconnectBackoffMaxMs = DefaultReconnectBackoffMaxMs
	}
	if c.FailOpen == nil {
		c.FailOpen = boolPtr(true)
	}
	if c.FailOpenTimeoutMs == 0 {
		c.FailOpenTimeoutMs = DefaultFailOpenTimeoutMs
	}
	if c.FailOpenHoldTimeoutMs == 0 {
		c.FailOpenHoldTimeoutMs = DefaultFailOpenHoldTimeoutMs
	}
	if c.ReqMaxProcessingMs == 0 {
		c.ReqMaxProcessingMs = DefaultReqMaxProcessingMs
	}
	if c.ResMaxProcessingMs == 0 {
		c.ResMaxProcessingMs = DefaultResMaxProcessingMs
	}
	if c.MinRetriesForVerdict == 0 {
		c.MinRetriesForVerdict = DefaultMinRetriesForVerdict
	}
	if c.MaxRetriesForVerdict == 0 {
		c.MaxRetriesForVerdict = DefaultMaxRetriesForVerdict
	}
	if c.HoldVerdictRetries == 0 {
		c.HoldVerdictRetries = DefaultHoldVerdictRetries
	}
	if c.HoldVerdictPollingMs == 0 {
		c.HoldVerdictPollingMs = DefaultHoldVerdictPollingMs
	}
	if c.BodySizeTrigger == 0 {
		c.BodySizeTrigger = DefaultBodySizeTrigger
	}
	if c.DecompressionPoolSize == 0 {
		c.DecompressionPoolSize = DefaultDecompressionPoolSize
	}
	if c.RecompressionPoolSize == 0 {
		c.RecompressionPoolSize = DefaultRecompressionPoolSize
	}
	if c.LogLevel == "" {
		c.LogLevel = DefaultLogLevel
	}
}

// Validate checks the config against the protocol constraints. It never
// panics and returns a joined, descriptive error listing every violation.
func (c *EngineConfig) Validate() error {
	var errs []error

	if strings.TrimSpace(c.FamilyName) == "" {
		errs = append(errs, errors.New("family_name is required and must be non-empty"))
	}
	if !slices.Contains(supportedAttachmentTypes, c.AttachmentType) {
		errs = append(errs, fmt.Errorf(
			"attachment_type %q is not supported (supported: %s)",
			c.AttachmentType, strings.Join(supportedAttachmentTypes, ", "),
		))
	}
	if c.Transport != "" && !slices.Contains(supportedTransports, c.Transport) {
		errs = append(errs, fmt.Errorf(
			"transport %q is not supported (supported: %s)",
			c.Transport, strings.Join(supportedTransports, ", "),
		))
	}
	if c.WorkerID < 0 {
		errs = append(errs, fmt.Errorf("worker_id must be >= 0, got %d", c.WorkerID))
	}
	if c.Workers <= 0 {
		errs = append(errs, fmt.Errorf("workers must be > 0, got %d", c.Workers))
	}
	errs = append(errs, positiveErrors([]intField{
		{"keep_alive_interval_ms", c.KeepAliveIntervalMs},
		{"registration_timeout_ms", c.RegistrationTimeoutMs},
		{"reconnect_backoff_min_ms", c.ReconnectBackoffMinMs},
		{"reconnect_backoff_max_ms", c.ReconnectBackoffMaxMs},
		{"fail_open_timeout_ms", c.FailOpenTimeoutMs},
		{"fail_open_hold_timeout_ms", c.FailOpenHoldTimeoutMs},
		{"req_max_processing_ms", c.ReqMaxProcessingMs},
		{"res_max_processing_ms", c.ResMaxProcessingMs},
		{"min_retries_for_verdict", c.MinRetriesForVerdict},
		{"max_retries_for_verdict", c.MaxRetriesForVerdict},
		{"hold_verdict_retries", c.HoldVerdictRetries},
		{"hold_verdict_polling_ms", c.HoldVerdictPollingMs},
		{"body_size_trigger", c.BodySizeTrigger},
		{"decompression_pool_size", c.DecompressionPoolSize},
		{"recompression_pool_size", c.RecompressionPoolSize},
	})...)
	if c.ReconnectBackoffMaxMs < c.ReconnectBackoffMinMs {
		errs = append(errs, fmt.Errorf(
			"reconnect_backoff_max_ms (%d) must be >= reconnect_backoff_min_ms (%d)",
			c.ReconnectBackoffMaxMs, c.ReconnectBackoffMinMs,
		))
	}
	if c.MaxRetriesForVerdict < c.MinRetriesForVerdict {
		errs = append(errs, fmt.Errorf(
			"max_retries_for_verdict (%d) must be >= min_retries_for_verdict (%d)",
			c.MaxRetriesForVerdict, c.MinRetriesForVerdict,
		))
	}
	return errors.Join(errs...)
}
