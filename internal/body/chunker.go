package body

import (
	"errors"
	"io"
)

// ChunkSize is the payload size of one BODY_CHUNK frame, in bytes.
//
// Justification (docs/attachment-protocol.md §D.3, §E.8): the ring queue caps
// a single message at max_write_size = 0xfffc = 65532 bytes, and the BODY
// frame adds 8 bytes of framing on top of the payload (uint16 data_type,
// uint32 session_id, uint8 is_last_chunk, uint8 part_count), so the largest
// legal payload is 65524 bytes. 60000 is a conservative choice: it fits any
// frame well inside the ring cap, leaves headroom for future framing growth,
// and keeps per-chunk allocations modest.
const ChunkSize = 60000

// Chunker splits an io.Reader into payloads of at most ChunkSize bytes, sized
// to wrap directly in a protocol.BodyChunk frame. The caller owns framing:
// it sets IsLastChunk on the chunk returned by the final successful Next
// call and PartCount from its own counter.
//
// A Chunker is single-goroutine: one caller drives it to completion.
type Chunker struct {
	r    io.Reader
	buf  []byte
	done bool
	err  error
}

// NewChunker returns a Chunker reading from r. A nil reader is not allowed;
// pass an empty reader for an empty body.
func NewChunker(r io.Reader) *Chunker {
	return &Chunker{r: r, buf: make([]byte, ChunkSize)}
}

// Next returns the next chunk of at most ChunkSize bytes, or io.EOF when the
// stream is exhausted. An empty body yields io.EOF on the first call (zero
// chunks). A stream whose length is an exact multiple of ChunkSize yields all
// full chunks and then io.EOF — Next never reports EOF on the call that
// returned the final full chunk.
//
// If the underlying reader fails mid-stream, Next returns that error and the
// Chunker is finished: any bytes read before the error are discarded, the
// caller should abort the session (the body is incomplete), and subsequent
// calls keep returning the same error.
//
// The returned slice is owned by the Chunker and is only valid until the next
// call to Next; the caller must not retain or modify it.
func (c *Chunker) Next() ([]byte, error) {
	if c.done {
		return nil, c.err
	}
	n, err := io.ReadFull(c.r, c.buf)
	switch {
	case err == nil:
		// Full chunk; the stream may continue, so EOF is deferred.
		return c.buf, nil
	case errors.Is(err, io.EOF):
		// ReadFull returns io.EOF only when zero bytes were read.
		c.done, c.err = true, io.EOF
		return nil, io.EOF
	case errors.Is(err, io.ErrUnexpectedEOF):
		// Partial final chunk, then clean EOF.
		c.done, c.err = true, io.EOF
		return c.buf[:n], nil
	default:
		c.done, c.err = true, err
		return nil, err
	}
}
