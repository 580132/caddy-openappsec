package config

import "fmt"

// Default values for EngineConfig, mirroring the openappsec nginx attachment
// reference configuration (docs/attachment-protocol.md §H.1, ngx_cp_utils.c:96-125)
// and the shared-memory path constants (docs/attachment-protocol.md §B).
const (
	// DefaultRegistrationSocket is SHARED_REGISTRATION_SIGNAL_PATH
	// (nano_attachment_common.h:28).
	DefaultRegistrationSocket = "/dev/shm/check-point/cp-nano-attachment-registration"
	// DefaultKeepAlivePath is SHARED_KEEP_ALIVE_PATH (nano_attachment_common.h:29).
	DefaultKeepAlivePath = "/dev/shm/check-point/cp-nano-attachment-registration-expiration-socket"
	// DefaultVerdictSignalPath is SHARED_VERDICT_SIGNAL_PATH
	// (nano_attachment_common.h:30).
	DefaultVerdictSignalPath = "/dev/shm/check-point/cp-nano-http-transaction-handler"
	// DefaultWorkers is the number of attachment worker processes.
	DefaultWorkers = 1
	// DefaultAttachmentType is "nginx": the openappsec engine defines an
	// attachment_type for nginx (NGINX_ATT_ID, §G.1) but none for Caddy, so the
	// Caddy attachment must present itself as the nginx family to interoperate.
	DefaultAttachmentType = "nginx"
	// DefaultKeepAliveIntervalMs matches DEFAULT_KEEP_ALIVE_INTERVAL_MSEC
	// (nano_attachment_common.h:26, §G.3). The engine expires a registration
	// that has not kept alive within 300000 ms, so the interval must stay below
	// that expiry window.
	DefaultKeepAliveIntervalMs   = 300000
	DefaultRegistrationTimeoutMs = 100
	DefaultReconnectBackoffMinMs = 100
	DefaultReconnectBackoffMaxMs = 5000
	DefaultFailOpenTimeoutMs     = 50
	DefaultFailOpenHoldTimeoutMs = 150
	DefaultReqMaxProcessingMs    = 3000
	DefaultResMaxProcessingMs    = 3000
	DefaultMinRetriesForVerdict  = 3
	DefaultMaxRetriesForVerdict  = 15
	DefaultHoldVerdictRetries    = 3
	DefaultHoldVerdictPollingMs  = 1
	DefaultBodySizeTrigger       = 200000
	DefaultDecompressionPoolSize = 262144
	DefaultRecompressionPoolSize = 16384
	DefaultLogLevel              = "info"
)

// Default values for HandlerConfig.
const (
	// DefaultBodyBufferLimit caps the request body buffered for inspection
	// (10 MiB).
	DefaultBodyBufferLimit = 10 * 1024 * 1024
	// DefaultResponseBufferLimit caps the response body buffered for
	// inspection (4 MiB).
	DefaultResponseBufferLimit = 4 * 1024 * 1024
	// DefaultBlockStatusCode is the HTTP status returned for blocked requests.
	DefaultBlockStatusCode = 403
)

// intField pairs a config field name with its value for positive-value checks.
type intField struct {
	name  string
	value int
}

// positiveErrors reports an error for every field whose value is not > 0.
func positiveErrors(fields []intField) []error {
	errs := make([]error, 0, len(fields))
	for _, f := range fields {
		if f.value <= 0 {
			errs = append(errs, fmt.Errorf("%s must be > 0, got %d", f.name, f.value))
		}
	}
	return errs
}

// boolPtr returns a pointer to b. Config fields use *bool so that "unset"
// (nil, meaning the default applies) can be distinguished from an explicit
// false in JSON.
func boolPtr(b bool) *bool { return &b }
