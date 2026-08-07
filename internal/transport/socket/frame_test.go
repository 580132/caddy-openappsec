package socket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func Test_writeFrame_readFrame_round_trip(t *testing.T) {
	payloads := [][]byte{
		nil,
		{},
		[]byte("hello"),
		bytes.Repeat([]byte{0x42}, 4096),
	}
	for _, p := range payloads {
		var buf bytes.Buffer
		if err := writeFrame(&buf, p); err != nil {
			t.Fatalf("writeFrame(%d bytes): unexpected error: %v", len(p), err)
		}
		got, err := readFrame(&buf)
		if err != nil {
			t.Fatalf("readFrame(%d bytes): unexpected error: %v", len(p), err)
		}
		if !bytes.Equal(got, p) {
			t.Fatalf("readFrame: got %d bytes, want %d", len(got), len(p))
		}
	}
}

func Test_readFrame_parses_back_to_back_frames(t *testing.T) {
	// Given three frames written back to back
	var buf bytes.Buffer
	for _, msg := range []string{"first", "second", "third"} {
		if err := writeFrame(&buf, []byte(msg)); err != nil {
			t.Fatalf("writeFrame: unexpected error: %v", err)
		}
	}
	// When each is read in turn
	// Then each read yields exactly one frame, in order
	for _, want := range []string{"first", "second", "third"} {
		got, err := readFrame(&buf)
		if err != nil {
			t.Fatalf("readFrame: unexpected error: %v", err)
		}
		if string(got) != want {
			t.Fatalf("readFrame: got %q, want %q", got, want)
		}
	}
}

func Test_readFrame_returns_EOF_on_clean_stream_end(t *testing.T) {
	// Given a stream with no bytes at all
	// When a frame is read
	// Then io.EOF is returned as-is, unmodified
	if _, err := readFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("readFrame: got %v, want io.EOF", err)
	}
}

func Test_readFrame_rejects_truncated_payload(t *testing.T) {
	// Given a header declaring 10 bytes but only 4 payload bytes delivered
	var buf bytes.Buffer
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, 10)
	buf.Write(hdr)
	buf.Write([]byte("abcd"))
	// When the frame is read
	// Then a clear truncated-frame error is reported
	if _, err := readFrame(&buf); err == nil {
		t.Fatal("readFrame: expected truncated-frame error, got nil")
	} else if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("readFrame: got %v, want a truncated-frame error", err)
	}
}

func Test_readFrame_rejects_truncated_header(t *testing.T) {
	// Given only 2 of the 4 header bytes delivered
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x00})
	// When the frame is read
	// Then an error is reported (not a hang and not io.EOF)
	if _, err := readFrame(&buf); err == nil {
		t.Fatal("readFrame: expected error for truncated header, got nil")
	} else if errors.Is(err, io.EOF) {
		t.Fatalf("readFrame: got io.EOF, want a truncated-header error")
	}
}

func Test_readFrame_rejects_oversized_length(t *testing.T) {
	// Given a length prefix beyond the frame cap
	var buf bytes.Buffer
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, maxFrameSize+1)
	buf.Write(hdr)
	// When the frame is read
	// Then it is rejected without allocating the declared payload
	if _, err := readFrame(&buf); err == nil {
		t.Fatal("readFrame: expected oversized-length error, got nil")
	} else if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readFrame: got %v, want an oversized-frame error", err)
	}
}

func Test_writeFrame_rejects_oversized_payload(t *testing.T) {
	// Given a payload larger than the frame cap
	// When it is written
	// Then writeFrame rejects it rather than emitting a frame the reader
	// would refuse
	if err := writeFrame(io.Discard, make([]byte, maxFrameSize+1)); err == nil {
		t.Fatal("writeFrame: expected oversized-payload error, got nil")
	}
}
