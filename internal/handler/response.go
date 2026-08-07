package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/580132/caddy-openappsec/internal/body"
)

// responseWriter wraps the origin response with the response-side buffering
// policy. It buffers the body up to the configured cap so it can be
// re-emitted after the verdict, and it switches to passthrough — streaming
// unmodified — for SSE, for responses whose declared Content-Length exceeds
// the cap, and for responses that overflow the cap mid-stream. A fully
// buffered identity response is recompressed for clients that accept gzip.
//
// The header is deferred until the body's fate is known: a buffered response
// gets its Content-Encoding/Content-Length set before the header is written,
// while a passthrough response flushes the header immediately so streaming
// starts without delay.
type responseWriter struct {
	http.ResponseWriter
	buf            *body.ResponseBuffer
	acceptEncoding string

	status      int
	wroteHeader bool
	passThrough bool
}

// newResponseWriter wraps w with a response buffer capped at the handler's
// ResponseBufferLimit. The request's Accept-Encoding drives recompression.
func newResponseWriter(w http.ResponseWriter, h *Handler, r *http.Request) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		buf:            body.NewResponseBuffer(h.ResponseBufferLimit),
		acceptEncoding: r.Header.Get("Accept-Encoding"),
	}
}

// WriteHeader records the status and, if the buffer is already in passthrough
// (SSE or an over-cap Content-Length), flushes the header immediately so the
// client can start receiving the stream.
func (rw *responseWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.status = code
	if ct := rw.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/event-stream") {
		rw.buf.MarkSSE()
	}
	if cl := rw.Header().Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
			rw.buf.SetContentLength(n)
		}
	}
	if rw.buf.PassThrough() {
		rw.passThrough = true
		rw.flushHeader()
	}
}

// Write buffers the payload while in buffering state. When the buffer
// transitions to passthrough mid-write, the header, the buffered prefix, and
// the remainder of p are forwarded so no bytes are lost.
func (rw *responseWriter) Write(p []byte) (int, error) {
	if rw.passThrough {
		return rw.ResponseWriter.Write(p)
	}
	if rw.buf.PassThrough() {
		// Already in passthrough (SSE or Content-Length pre-check): stream.
		rw.passThrough = true
		return rw.ResponseWriter.Write(p)
	}
	n, err := rw.buf.Write(p)
	if err != nil {
		return n, err
	}
	if rw.buf.PassThrough() {
		// Transitioned mid-write: forward the buffered prefix and the rest.
		rw.passThrough = true
		rw.flushHeader()
		if _, err := rw.ResponseWriter.Write(rw.buf.Buffered()); err != nil {
			return 0, err
		}
		if n < len(p) {
			if _, err := rw.ResponseWriter.Write(p[n:]); err != nil {
				return 0, err
			}
		}
		return len(p), nil
	}
	return n, nil
}

// Flush forwards to the underlying writer so streaming responses (SSE) flush
// promptly. It also makes responseWriter satisfy http.Flusher.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// finalize re-emits a fully buffered response after the verdict: it
// recompresses an identity body for gzip-accepting clients, sets the
// Content-Length, and writes the header and body. A passthrough response is
// already fully streamed; only a deferred header is flushed.
func (rw *responseWriter) finalize() error {
	if rw.passThrough {
		rw.flushHeader()
		return nil
	}

	buf := rw.buf.Buffered()
	enc := rw.Header().Get("Content-Encoding")
	if enc == "" || strings.EqualFold(enc, "identity") {
		if re, e, err := body.Recompress(buf, rw.acceptEncoding); err == nil && e != "identity" {
			buf = re
			rw.Header().Set("Content-Encoding", e)
		}
	}
	rw.Header().Set("Content-Length", strconv.Itoa(len(buf)))
	rw.flushHeader()
	if len(buf) > 0 {
		_, err := rw.ResponseWriter.Write(buf)
		return err
	}
	return nil
}

// flushHeader writes the recorded status (defaulting to 200) exactly once.
func (rw *responseWriter) flushHeader() {
	if rw.wroteHeader {
		return
	}
	rw.wroteHeader = true
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	rw.ResponseWriter.WriteHeader(rw.status)
}
