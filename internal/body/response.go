package body

// DefaultResponseBufferCap is the buffer cap used when the caller has no
// configured value. It mirrors config.DefaultResponseBufferLimit (4 MiB,
// internal/config/config.go), the response-side inspection limit of the
// Caddy handler config.
//
// There is no response-cap field in EngineConfig
// (internal/config/engine.go); the config task owner should wire
// HandlerConfig.ResponseBufferLimit (json: response_buffer_limit) through to
// NewResponseBuffer when the handler wave lands.
const DefaultResponseBufferCap = 4 * 1024 * 1024

// ResponseBuffer is the response-side buffering policy state machine. It
// buffers the response body up to a cap so it can be inspected and re-emitted
// after the verdict, and it switches to passthrough — never buffering again —
// once any of these conditions holds:
//
//   - the declared Content-Length exceeds the cap (SetContentLength pre-check)
//   - buffered bytes exceed the cap mid-stream (Write transition)
//   - the content type is text/event-stream (MarkSSE)
//   - the cap is zero or negative (constructed already in passthrough)
//
// When the mid-stream transition fires, Write returns fewer bytes than it
// received; the caller must forward Buffered() followed by the remainder of
// that write, then stream everything after. A ResponseBuffer is
// single-goroutine: one caller drives it.
type ResponseBuffer struct {
	cap         int
	buf         []byte
	passThrough bool
}

// NewResponseBuffer returns a ResponseBuffer that stops buffering once
// len(buf) would exceed cap. A cap <= 0 starts the buffer in passthrough
// state (never buffers).
func NewResponseBuffer(cap int) *ResponseBuffer {
	rb := &ResponseBuffer{cap: cap}
	if cap <= 0 {
		rb.passThrough = true
	}
	return rb
}

// Write appends p to the buffer while in buffering state and returns the
// number of bytes accepted. While in passthrough state it accepts nothing and
// returns len(p) — the caller streams p directly.
//
// If appending p would push the buffered total past the cap, Write buffers
// only the prefix that fits, transitions to passthrough, and returns that
// prefix length; the caller must then forward Buffered() and the rest of p.
// The transition fires at most once.
func (rb *ResponseBuffer) Write(p []byte) (int, error) {
	if rb.passThrough {
		return len(p), nil
	}
	room := rb.cap - len(rb.buf)
	if room >= len(p) {
		rb.buf = append(rb.buf, p...)
		return len(p), nil
	}
	rb.buf = append(rb.buf, p[:room]...)
	rb.passThrough = true
	return room, nil
}

// PassThrough reports whether the buffer is in passthrough state. Once true
// it stays true.
func (rb *ResponseBuffer) PassThrough() bool {
	return rb.passThrough
}

// Buffered returns the bytes accumulated so far, in order. The returned slice
// is owned by the buffer and must not be modified; it is valid until the next
// Write.
func (rb *ResponseBuffer) Buffered() []byte {
	return rb.buf
}

// Len returns the number of buffered bytes.
func (rb *ResponseBuffer) Len() int {
	return len(rb.buf)
}

// SetContentLength performs the Content-Length pre-check: if the response's
// declared length exceeds the cap, the buffer transitions to passthrough
// immediately without buffering. A length within the cap keeps buffering; the
// byte-level check in Write still guards against a lying Content-Length. Call
// it once with the parsed header value before the first Write.
func (rb *ResponseBuffer) SetContentLength(n int64) {
	if n > int64(rb.cap) {
		rb.passThrough = true
	}
}

// MarkSSE forces passthrough for text/event-stream responses, which must
// stream to the client unmodified and unbuffered.
func (rb *ResponseBuffer) MarkSSE() {
	rb.passThrough = true
}
