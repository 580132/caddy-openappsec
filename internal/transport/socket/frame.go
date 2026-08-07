package socket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// maxFrameSize caps the length of a single frame. A frame is prefixed by a
// 4-byte little-endian length, so the encoding could express up to 4 GiB of
// payload; the cap exists to reject absurd length prefixes without trying to
// allocate them.
const maxFrameSize = 256 << 20 // 256 MiB

// frameHeaderSize is the number of bytes in a frame's length prefix.
const frameHeaderSize = 4

// writeFrame writes payload to w as one frame: a 4-byte little-endian length
// followed by the payload bytes. It rejects payloads larger than maxFrameSize
// so a sender never emits a frame the reader would refuse. A single write is
// not atomic: the header and payload are written separately, and callers that
// need frames to arrive intact must serialize concurrent writes (Send does).
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf("socket: frame of %d bytes exceeds the %d byte maximum", len(payload), maxFrameSize)
	}
	var hdr [frameHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("socket: write frame header: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("socket: write frame payload: %w", err)
		}
	}
	return nil
}

// readFrame reads one frame from r and returns its payload. It blocks until a
// complete frame is available, the stream ends, or the read is otherwise
// interrupted.
//
// A clean io.EOF with no bytes of the frame read yet is returned as-is, so
// callers can detect a peer that closed the stream between frames. A frame
// that declares more bytes than the stream delivers is reported as truncated,
// and a length prefix larger than maxFrameSize is rejected without being
// allocated. The returned slice is freshly allocated and owned by the caller.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [frameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("socket: reading frame header: %w", err)
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n > maxFrameSize {
		return nil, fmt.Errorf("socket: frame declares %d bytes, which exceeds the %d byte maximum", n, maxFrameSize)
	}
	buf := make([]byte, int(n))
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("socket: truncated frame: declares %d bytes but the stream ended early: %w", n, err)
	}
	return buf, nil
}
