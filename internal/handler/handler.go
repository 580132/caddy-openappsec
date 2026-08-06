package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/yourname/caddy-openappsec/internal/app"
	"github.com/yourname/caddy-openappsec/internal/config"
	"github.com/yourname/caddy-openappsec/internal/protocol"
)

// DefaultBlockPageTitle and DefaultBlockPageBody form the synthesized block
// response when neither the verdict nor the handler config supplies one.
const (
	DefaultBlockPageTitle = "Request blocked"
	DefaultBlockPageBody  = "Your request was blocked by the security policy."
)

// Handler is the Caddy HTTP middleware that runs open-appsec engine verdicts.
// For every request it acquires a verdict from the engine (via the app's
// fail-open policy), enforces DROP/INJECT verdicts, and buffers the response
// so it can be inspected and re-emitted after the verdict.
type Handler struct {
	// Engine is the open-appsec engine connection configuration.
	Engine config.EngineConfig
	// Mode is ModePrevent (default; verdicts enforced) or ModeLearn
	// (verdicts logged only, requests always forwarded).
	Mode config.Mode
	// BodyBufferLimit caps the request body buffered for inspection.
	BodyBufferLimit int
	// ResponseBufferLimit caps the response body buffered for inspection.
	ResponseBufferLimit int
	// BlockStatusCode is the HTTP status returned for blocked requests.
	BlockStatusCode int
	// BlockPageTitle is the title of the synthesized block response page.
	BlockPageTitle string
	// BlockPageBody is the body of the synthesized block response page.
	BlockPageBody string
	// FailOpen is nil for the default (fail-open). Set it explicitly to
	// false to fail closed when the engine is unavailable.
	FailOpen *bool
	// SkipCompressedBodyInspection disables decompressing compressed request
	// bodies for inspection.
	SkipCompressedBodyInspection bool
	// CustomHeaders are extra headers attached to block responses.
	CustomHeaders map[string]string

	// logger is the module logger, built in Provision.
	logger *zap.Logger
	// acquirer is the verdict surface; Provision wires the app fail-open
	// policy unless a test seam provided one.
	acquirer app.VerdictAcquirer
	// pool is the shared engine connection pool Provision keeps alive so
	// Cleanup can release the registration.
	pool *app.Pool
}

// compile-time interface assertions.
var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)

// SetDefaults fills zero-valued fields with the config defaults. Call before
// Validate. The tri-state FailOpen is left untouched so "unset" stays
// distinguishable from an explicit false.
func (h *Handler) SetDefaults() {
	h.Engine.SetDefaults()
	if h.Mode == "" {
		h.Mode = config.DefaultMode
	}
	if h.BodyBufferLimit == 0 {
		h.BodyBufferLimit = config.DefaultBodyBufferLimit
	}
	if h.ResponseBufferLimit == 0 {
		h.ResponseBufferLimit = config.DefaultResponseBufferLimit
	}
	if h.BlockStatusCode == 0 {
		h.BlockStatusCode = config.DefaultBlockStatusCode
	}
	if h.BlockPageTitle == "" {
		h.BlockPageTitle = DefaultBlockPageTitle
	}
	if h.BlockPageBody == "" {
		h.BlockPageBody = DefaultBlockPageBody
	}
}

// Validate checks the handler configuration.
func (h *Handler) Validate() error {
	var errs []error
	if err := h.Engine.Validate(); err != nil {
		errs = append(errs, err)
	}
	if !h.Mode.IsValid() {
		errs = append(errs, fmt.Errorf("handler: mode must be %q or %q, got %q",
			config.ModePrevent, config.ModeLearn, h.Mode))
	}
	if h.BodyBufferLimit <= 0 {
		errs = append(errs, fmt.Errorf("handler: body_buffer_limit must be > 0, got %d", h.BodyBufferLimit))
	}
	if h.ResponseBufferLimit <= 0 {
		errs = append(errs, fmt.Errorf("handler: response_buffer_limit must be > 0, got %d", h.ResponseBufferLimit))
	}
	if h.BlockStatusCode < 400 || h.BlockStatusCode > 599 {
		errs = append(errs, fmt.Errorf("handler: block_status_code must be in [400, 599], got %d", h.BlockStatusCode))
	}
	return errors.Join(errs...)
}

// Provision wires the shared engine pool and the fail-open verdict policy.
// It has no side effects beyond pool construction: the engine is not
// contacted. When fail-open is explicitly disabled, Provision verifies the
// engine is reachable so a boot-time misconfiguration fails fast.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.SetDefaults()
	if h.logger == nil {
		h.logger = ctx.Logger(Handler{})
	}

	if h.acquirer == nil {
		h.pool = app.GlobalPool(h.Engine, app.NewDialer(h.Engine))
		h.acquirer = app.NewFailOpenPolicy(h.Engine, h.pool)
	}

	if h.failClosed() {
		timeout := time.Duration(h.Engine.RegistrationTimeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if _, err := h.pool.Acquire(ctx, h.Engine.RegistrationSocket); err != nil {
			return fmt.Errorf("handler: engine unavailable: %w", err)
		}
	}
	return nil
}

// Cleanup releases the pooled engine connection acquired at Provision (or by
// the fail-closed reachability check). Other users of the same engine address
// keep their connection; the last release tears it down.
func (h *Handler) Cleanup() error {
	if h.pool != nil {
		h.pool.Release(h.Engine.RegistrationSocket)
	}
	return nil
}

// ServeHTTP acquires a verdict for r, enforces it, and forwards to next.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// An unprovisioned handler cannot reach the engine; the policy surface
	// decides posture (fail-open by default).
	if h.acquirer == nil {
		if h.failClosed() {
			return h.writeUnavailable(w, errors.New("handler: not provisioned, failing closed"))
		}
		return next.ServeHTTP(w, r)
	}

	// Read the request body for inspection. The origin must receive the
	// ORIGINAL bytes (compression intact), so restore them for forwarding.
	original, err := h.readRequestBody(r)
	if err != nil {
		h.logger.Debug("failed to read request body", zap.Error(err))
		return h.forward(w, r, next)
	}
	r.Body = newRequestBody(original)

	verdict, err := h.acquirer.AcquireVerdict(r.Context(), app.RequestData{
		Start: h.requestStart(r),
	})
	if err != nil {
		if h.failClosed() {
			h.logger.Error("engine unavailable, failing closed", zap.Error(err))
			return h.writeUnavailable(w, err)
		}
		h.logger.Warn("engine unavailable, failing open", zap.Error(err))
		return h.forward(w, r, next)
	}

	switch verdict.Kind {
	case protocol.VerdictDrop, protocol.VerdictCustomResponse:
		if h.Mode == config.ModeLearn {
			h.logger.Info("learn mode: would block request",
				zap.String("method", r.Method),
				zap.String("uri", r.RequestURI),
				zap.Uint16("status", verdictStatusCode(verdict)))
			// fall through to forward
		} else {
			return h.writeBlock(w, verdict)
		}
	case protocol.VerdictInject:
		if applied, ok := h.applyInjections(r, original, verdict.Injections); ok {
			r.Body = newRequestBody(applied)
		}
	}

	return h.forward(w, r, next)
}

// forward invokes next with the response wrapped in a buffering response
// writer, then re-emits the buffered body after the verdict.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	rw := newResponseWriter(w, h, r)
	if err := next.ServeHTTP(rw, r); err != nil {
		return err
	}
	return rw.finalize()
}

// writeUnavailable emits a 502 Bad Gateway response for the fail-closed
// posture. It returns nil so the middleware chain does not treat the
// synthesized response as an internal error.
func (h *Handler) writeUnavailable(w http.ResponseWriter, err error) error {
	h.logger.Error("request failed closed", zap.Error(err))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = io.WriteString(w, "Bad Gateway\n")
	return nil
}

// writeBlock synthesizes the block response for a DROP or CUSTOM_RESPONSE
// verdict. When the verdict carries a custom web response (Custom), its
// status, title and body are used; otherwise the handler's configured block
// page and status are used. It returns nil so the middleware chain does not
// treat the synthesized response as an internal error.
func (h *Handler) writeBlock(w http.ResponseWriter, verdict *protocol.Verdict) error {
	status := h.BlockStatusCode
	title := h.BlockPageTitle
	page := h.BlockPageBody
	if wr := verdict.WebResponse; wr != nil && wr.Type == protocol.WebResponseCustom {
		if wr.StatusCode != 0 {
			status = int(wr.StatusCode)
		}
		if wr.Title != "" {
			title = wr.Title
		}
		if wr.Body != "" {
			page = wr.Body
		}
	}
	html := fmt.Sprintf("<!DOCTYPE html>\n<html>\n<head><title>%s</title></head>\n<body>\n<h1>%s</h1>\n<p>%s</p>\n</body>\n</html>\n", title, title, page)
	h.logger.Debug("request blocked",
		zap.String("method", ""),
		zap.Int("status", status))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, html)
	return nil
}

// requestStart builds the REQUEST_START metadata block for the engine.
func (h *Handler) requestStart(r *http.Request) protocol.RequestStart {
	host, port := splitHostPort(r.Host)
	return protocol.RequestStart{
		HTTPProtocol:  r.Proto,
		Method:        r.Method,
		Host:          host,
		ListeningPort: port,
		UnparsedURI:   r.RequestURI,
		ClientIP:      remoteIP(r),
		ClientPort:    remotePort(r),
		ParsedHost:    host,
		ParsedURI:     r.URL.RequestURI(),
		WAFTag:        "",
	}
}

// failClosed reports whether FailOpen is explicitly false.
func (h *Handler) failClosed() bool {
	return h.FailOpen != nil && !*h.FailOpen
}

// verdictStatusCode extracts the block status from a verdict for logging.
func verdictStatusCode(v *protocol.Verdict) uint16 {
	if v != nil && v.WebResponse != nil && v.WebResponse.StatusCode != 0 {
		return v.WebResponse.StatusCode
	}
	return 403
}

// splitHostPort splits "host:port" into its parts, returning 0 for a missing
// or unparsable port.
func splitHostPort(hostport string) (string, uint16) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, 0
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return host, 0
	}
	return host, uint16(port)
}

// remoteIP and remotePort split the peer address recorded by Caddy.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func remotePort(r *http.Request) uint16 {
	_, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return 0
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(port)
}
