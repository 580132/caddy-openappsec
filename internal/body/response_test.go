package body

import (
	"bytes"
	"testing"
)

func TestResponseBuffer_buffers_when_under_cap(t *testing.T) {
	rb := NewResponseBuffer(1024)
	payload := []byte("small response body")

	n, err := rb.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned %d, want %d", n, len(payload))
	}
	if rb.PassThrough() {
		t.Fatal("PassThrough() = true, want false under cap")
	}
	if !bytes.Equal(rb.Buffered(), payload) {
		t.Fatalf("Buffered() = %q, want %q", rb.Buffered(), payload)
	}
	if rb.Len() != len(payload) {
		t.Fatalf("Len() = %d, want %d", rb.Len(), len(payload))
	}
}

func TestResponseBuffer_passthrough_transition_fires_exactly_once(t *testing.T) {
	rb := NewResponseBuffer(100)
	transitions := 0
	for i := 0; i < 5; i++ {
		n, err := rb.Write(bytes.Repeat([]byte{byte('a' + i)}, 60))
		if err != nil {
			t.Fatalf("Write #%d: %v", i, err)
		}
		if n < 60 {
			transitions++
		}
	}
	if transitions != 1 {
		t.Fatalf("passthrough transition fired %d times, want exactly 1", transitions)
	}
	if !rb.PassThrough() {
		t.Fatal("PassThrough() = false, want true after cap exceeded")
	}
	if rb.Len() > 100 {
		t.Fatalf("buffered %d bytes, want <= cap 100", rb.Len())
	}
}

func TestResponseBuffer_passthrough_stops_buffering(t *testing.T) {
	rb := NewResponseBuffer(64)
	if _, err := rb.Write(bytes.Repeat([]byte("x"), 100)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	before := rb.Len()

	n, err := rb.Write([]byte("after transition"))
	if err != nil {
		t.Fatalf("Write after transition: %v", err)
	}
	if n != len("after transition") {
		t.Fatalf("Write after transition returned %d, want %d", n, len("after transition"))
	}
	if rb.Len() != before {
		t.Fatalf("Len() changed from %d to %d after passthrough", before, rb.Len())
	}
}

func TestResponseBuffer_buffered_content_is_exact_prefix(t *testing.T) {
	rb := NewResponseBuffer(10)
	// Write 6 bytes, then 6 bytes: room is 4, so 4 fit and the transition
	// fires with exactly 10 buffered.
	if _, err := rb.Write([]byte("abcdef")); err != nil {
		t.Fatalf("Write #1: %v", err)
	}
	n, err := rb.Write([]byte("ghijkl"))
	if err != nil {
		t.Fatalf("Write #2: %v", err)
	}
	if n != 4 {
		t.Fatalf("Write #2 accepted %d bytes, want 4", n)
	}
	if got := rb.Buffered(); !bytes.Equal(got, []byte("abcdefghij")) {
		t.Fatalf("Buffered() = %q, want %q", got, "abcdefghij")
	}
	if !rb.PassThrough() {
		t.Fatal("PassThrough() = false after cap exceeded")
	}
}

func TestResponseBuffer_content_length_precheck_short_circuits(t *testing.T) {
	rb := NewResponseBuffer(100)
	rb.SetContentLength(101)
	if !rb.PassThrough() {
		t.Fatal("PassThrough() = false, want true when CL > cap")
	}
	if _, err := rb.Write([]byte("not buffered")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rb.Len() != 0 {
		t.Fatalf("Len() = %d, want 0 (never buffered)", rb.Len())
	}
}

func TestResponseBuffer_content_length_under_cap_still_buffers(t *testing.T) {
	rb := NewResponseBuffer(100)
	rb.SetContentLength(50)
	if rb.PassThrough() {
		t.Fatal("PassThrough() = true, want false when CL <= cap")
	}
	if _, err := rb.Write([]byte("ok")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rb.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", rb.Len())
	}
}

func TestResponseBuffer_sse_never_buffers(t *testing.T) {
	rb := NewResponseBuffer(1024)
	rb.MarkSSE()
	if !rb.PassThrough() {
		t.Fatal("PassThrough() = false, want true for text/event-stream")
	}
	if _, err := rb.Write([]byte("data: event\n\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rb.Len() != 0 {
		t.Fatalf("Len() = %d, want 0 (SSE never buffers)", rb.Len())
	}
	if len(rb.Buffered()) != 0 {
		t.Fatalf("Buffered() = %q, want empty", rb.Buffered())
	}
}

func TestResponseBuffer_zero_cap_is_always_passthrough(t *testing.T) {
	rb := NewResponseBuffer(0)
	if !rb.PassThrough() {
		t.Fatal("PassThrough() = false, want true for cap 0")
	}
	if _, err := rb.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rb.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", rb.Len())
	}
}

func TestResponseBuffer_default_cap_matches_config_reference(t *testing.T) {
	if DefaultResponseBufferCap != 4*1024*1024 {
		t.Fatalf("DefaultResponseBufferCap = %d, want 4194304 (config DefaultResponseBufferLimit)", DefaultResponseBufferCap)
	}
}
