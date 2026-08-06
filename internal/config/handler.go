package config

import (
	"errors"
	"fmt"
)

// Mode selects how the middleware treats engine verdicts.
type Mode string

const (
	// ModePrevent enforces verdicts: blocked requests get the block response.
	ModePrevent Mode = "prevent"
	// ModeLearn logs verdicts without blocking.
	ModeLearn Mode = "learn"
)

// DefaultMode is the mode applied when none is configured.
const DefaultMode = ModePrevent

// IsValid reports whether m is a known mode.
func (m Mode) IsValid() bool {
	switch m {
	case ModePrevent, ModeLearn:
		return true
	}
	return false
}

// HandlerConfig configures the HTTP middleware: body buffering limits, the
// block response, the inspection mode, and fail-open behavior.
type HandlerConfig struct {
	// BodyBufferLimit caps the request body buffered for inspection
	// (10 MiB default).
	BodyBufferLimit int `json:"body_buffer_limit,omitempty"`
	// ResponseBufferLimit caps the response body buffered for inspection
	// (4 MiB default).
	ResponseBufferLimit int `json:"response_buffer_limit,omitempty"`
	// BlockStatusCode is the HTTP status returned for blocked requests
	// (403 default).
	BlockStatusCode int `json:"block_status_code,omitempty"`
	// BlockPageTitle is an optional title for the block response page.
	BlockPageTitle string `json:"block_page_title,omitempty"`
	// BlockPageBody is an optional body for the block response page.
	BlockPageBody string `json:"block_page_body,omitempty"`
	// Mode is ModePrevent (verdicts enforced) or ModeLearn (verdicts logged
	// only). Defaults to ModePrevent.
	Mode Mode `json:"mode,omitempty"`
	// SkipCompressedBodyInspection disables decompressing compressed bodies
	// for inspection.
	SkipCompressedBodyInspection bool `json:"skip_compressed_body_inspection,omitempty"`
	// FailOpen is nil for the default (true, fail-open); set it explicitly to
	// false to fail closed when the engine is unavailable.
	FailOpen *bool `json:"fail_open,omitempty"`
	// CustomHeaders are extra headers attached to block responses.
	CustomHeaders map[string]string `json:"custom_headers,omitempty"`
}

// SetDefaults fills zero-valued fields with defaults; call before Validate.
func (c *HandlerConfig) SetDefaults() {
	if c.BodyBufferLimit == 0 {
		c.BodyBufferLimit = DefaultBodyBufferLimit
	}
	if c.ResponseBufferLimit == 0 {
		c.ResponseBufferLimit = DefaultResponseBufferLimit
	}
	if c.BlockStatusCode == 0 {
		c.BlockStatusCode = DefaultBlockStatusCode
	}
	if c.Mode == "" {
		c.Mode = DefaultMode
	}
	if c.FailOpen == nil {
		c.FailOpen = boolPtr(true)
	}
}

// Validate checks the handler config and returns a joined, descriptive error
// listing every violation. It never panics.
func (c *HandlerConfig) Validate() error {
	var errs []error

	errs = append(errs, positiveErrors([]intField{
		{"body_buffer_limit", c.BodyBufferLimit},
		{"response_buffer_limit", c.ResponseBufferLimit},
	})...)
	if c.BlockStatusCode < 400 || c.BlockStatusCode > 599 {
		errs = append(errs, fmt.Errorf(
			"block_status_code must be a valid HTTP status in [400, 599], got %d",
			c.BlockStatusCode,
		))
	}
	if !c.Mode.IsValid() {
		errs = append(errs, fmt.Errorf("mode must be %q or %q, got %q", ModePrevent, ModeLearn, c.Mode))
	}
	return errors.Join(errs...)
}
