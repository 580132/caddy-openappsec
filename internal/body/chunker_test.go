package body

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestChunker_empty_body_yields_zero_chunks(t *testing.T) {
	c := NewChunker(bytes.NewReader(nil))
	if _, err := c.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("Next on empty body = %v, want io.EOF", err)
	}
}

func TestChunker_exact_boundary_read_yields_one_chunk_then_EOF(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), ChunkSize)
	c := NewChunker(bytes.NewReader(payload))

	chunk, err := c.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(chunk) != ChunkSize {
		t.Fatalf("chunk len = %d, want %d", len(chunk), ChunkSize)
	}
	if !bytes.Equal(chunk, payload) {
		t.Fatal("chunk content differs from input")
	}

	if _, err := c.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("second Next = %v, want io.EOF", err)
	}
}

func TestChunker_exact_multi_boundary_yields_n_chunks(t *testing.T) {
	payload := bytes.Repeat([]byte("bc"), ChunkSize) // 2 * ChunkSize bytes = exactly 2 chunks
	c := NewChunker(bytes.NewReader(payload))

	total := 0
	chunks := 0
	for {
		chunk, err := c.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		chunks++
		total += len(chunk)
	}
	if chunks != 2 {
		t.Fatalf("chunks = %d, want 2", chunks)
	}
	if total != len(payload) {
		t.Fatalf("total = %d, want %d", total, len(payload))
	}
}

func TestChunker_never_exceeds_size_cap(t *testing.T) {
	payload := bytes.Repeat([]byte("xyz"), ChunkSize+12345)
	c := NewChunker(bytes.NewReader(payload))

	total := 0
	maxSeen := 0
	for {
		chunk, err := c.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if len(chunk) > ChunkSize {
			t.Fatalf("chunk len %d exceeds ChunkSize %d", len(chunk), ChunkSize)
		}
		if len(chunk) > maxSeen {
			maxSeen = len(chunk)
		}
		total += len(chunk)
	}
	if total != len(payload) {
		t.Fatalf("total = %d, want %d", total, len(payload))
	}
	if maxSeen != ChunkSize {
		t.Fatalf("max chunk = %d, want %d", maxSeen, ChunkSize)
	}
}

func TestChunker_partial_final_chunk_is_yielded(t *testing.T) {
	payload := bytes.Repeat([]byte("q"), ChunkSize-7)
	c := NewChunker(bytes.NewReader(payload))

	chunk, err := c.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(chunk) != ChunkSize-7 {
		t.Fatalf("chunk len = %d, want %d", len(chunk), ChunkSize-7)
	}
	if _, err := c.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("second Next = %v, want io.EOF", err)
	}
}

// errorReader yields some bytes and then fails with a non-EOF error.
type errorReader struct {
	data []byte
	off  int
	err  error
}

func (r *errorReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

func TestChunker_midstream_error_is_returned(t *testing.T) {
	boom := errors.New("chunker: simulated read failure")
	c := NewChunker(&errorReader{data: bytes.Repeat([]byte("z"), 100), err: boom})

	// io.ReadFull consumes the 100 partial bytes and the error in one call,
	// so the first Next returns the error: partial data is discarded and the
	// caller aborts the session.
	if _, err := c.Next(); !errors.Is(err, boom) {
		t.Fatalf("Next = %v, want simulated error", err)
	}
	if _, err := c.Next(); !errors.Is(err, boom) {
		t.Fatalf("Next after error = %v, want error sticky", err)
	}
}

func TestChunker_is_sticky_after_eof(t *testing.T) {
	c := NewChunker(bytes.NewReader([]byte("short")))
	if _, err := c.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := c.Next(); !errors.Is(err, io.EOF) {
			t.Fatalf("Next #%d = %v, want io.EOF", i+2, err)
		}
	}
}
