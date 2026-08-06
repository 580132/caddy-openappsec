package handler

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/yourname/caddy-openappsec/internal/body"
	"github.com/yourname/caddy-openappsec/internal/protocol"
)

// readRequestBody buffers the request body so it can be inspected; the caller
// restores the ORIGINAL bytes for forwarding. A body larger than
// BodyBufferLimit is still buffered but logged (the trigger path of the nginx
// reference is out of scope for this wave). On error the body is unusable and
// the caller forwards the request untouched (fail-open).
func (h *Handler) readRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(b) > h.BodyBufferLimit {
		h.logger.Debug("request body exceeds body_buffer_limit",
			zap.Int("limit", h.BodyBufferLimit),
			zap.Int("actual", len(b)))
	}
	return b, nil
}

// newRequestBody restores the buffered bytes as the request body for the
// origin handler.
func newRequestBody(b []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(b))
}

// inspectBody validates that a compressed request body can be decompressed,
// so corrupt or unsupported encodings are surfaced without submitting garbage
// to the engine. It is inspection-only: the origin still receives the
// original encoded bytes. Failures are logged and tolerated (fail-open).
func (h *Handler) inspectBody(raw []byte, r *http.Request) {
	if h.SkipCompressedBodyInspection {
		return
	}
	enc := r.Header.Get("Content-Encoding")
	if enc == "" || strings.EqualFold(enc, "identity") {
		return
	}
	dec, err := body.OpenRequestBody(bytes.NewReader(raw), enc)
	if err != nil {
		h.logger.Debug("request body encoding unsupported, skipping inspection", zap.Error(err))
		return
	}
	defer dec.Close()
	if _, err := io.Copy(io.Discard, dec); err != nil {
		h.logger.Debug("request body decompression failed, skipping inspection", zap.Error(err))
	}
}

// applyInjections applies an INJECT verdict's modifications. Header
// injections are added to the request headers; body injections are appended
// to the buffered request body. It returns the (possibly modified) body and
// whether any modification was applied.
func (h *Handler) applyInjections(r *http.Request, body []byte, injections []protocol.Injection) ([]byte, bool) {
	applied := body
	changed := false
	for _, inj := range injections {
		if inj.IsHeader {
			name, value, ok := strings.Cut(string(inj.Data), ":")
			if !ok {
				h.logger.Warn("injection is not a valid header, skipping",
					zap.ByteString("data", inj.Data))
				continue
			}
			r.Header.Add(strings.TrimSpace(name), strings.TrimSpace(value))
			changed = true
			continue
		}
		applied = append(applied, inj.Data...)
		changed = true
	}
	return applied, changed
}
