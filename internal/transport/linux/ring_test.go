package linux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/580132/caddy-openappsec/internal/protocol"
)

// testRing builds a ring buffer for the given segment size and segment count,
// initializing the header and management segment the way the owner does
// (createSharedRingQueue / resetRingQueue, shared_ring_queue.c:308-321).
func testRing(t *testing.T, segSize, numSegs uint32) *ring {
	t.Helper()
	if segSize != uint32(protocol.SharedMemSegmentSize) && segSize != uint32(protocol.SharedMemSegmentSizeBC) {
		t.Fatalf("testRing: unsupported segSize %d", segSize)
	}
	sizeOfMemory := uint32(protocol.SharedQueueMgmtOffset) + segSize*(1+numSegs)
	buf := make([]byte, sizeOfMemory)
	binary.LittleEndian.PutUint32(buf[protocol.SharedQueueSizeOffset:], sizeOfMemory)
	binary.LittleEndian.PutUint16(buf[protocol.SharedQueueNumSegOffset:], uint16(numSegs))
	binary.LittleEndian.PutUint16(buf[protocol.SharedQueueReadPosOffset:], 0)
	binary.LittleEndian.PutUint16(buf[protocol.SharedQueueWritePosOffset:], 0)
	for i := uint32(0); i < numSegs; i++ {
		off := protocol.SharedQueueMgmtOffset + int(i)*2
		binary.LittleEndian.PutUint16(buf[off:], protocol.MagicEmptySegment)
	}
	r, err := newRing(buf)
	if err != nil {
		t.Fatalf("testRing: newRing: %v", err)
	}
	return r
}

// seedRing writes a message of size n at segment start so tests can exercise
// peek/pop on a non-empty queue without going through push. writePos is set
// past the message so readPos != writePos (a message always leaves the writer
// ahead of the reader).
func seedRing(t *testing.T, r *ring, start uint32, size uint32) {
	t.Helper()
	numSegs := (size + r.segSize - 1) / r.segSize
	if numSegs == 0 {
		numSegs = 1 // the mgmt slot still counts
	}
	r.setWritePos(start + numSegs)
	if r.writePos() >= r.numSegs {
		r.setWritePos(0)
	}
	r.setReadPos(start)
	r.setMgmt(start, uint16(size))
	copy(r.dataSeg(start), bytes.Repeat([]byte{0xAA}, int(size)))
	for i := uint32(1); i < numSegs; i++ {
		r.setMgmt(start+i, protocol.MagicSkipSegment)
	}
}

func Test_DeriveGeometry_returns_segment_size_and_base_offset(t *testing.T) {
	tests := []struct {
		name         string
		sizeOfMemory uint32
		numSegs      uint32
		wantSegSize  uint32
		wantDataBase uint32
		wantErr      bool
	}{
		{
			name:         "full segments, 200 elements",
			sizeOfMemory: 82 + 4096*201,
			numSegs:      200,
			wantSegSize:  4096,
			wantDataBase: 4178,
		},
		{
			name:         "bc segments, 200 elements",
			sizeOfMemory: 82 + 1024*201,
			numSegs:      200,
			wantSegSize:  1024,
			wantDataBase: 1106,
		},
		{
			name:         "full segments, 2048 elements",
			sizeOfMemory: 82 + 4096*2049,
			numSegs:      2048,
			wantSegSize:  4096,
			wantDataBase: 4178,
		},
		{
			name:         "zero segments rejected",
			sizeOfMemory: 82 + 4096,
			numSegs:      0,
			wantErr:      true,
		},
		{
			name:         "segments beyond max rejected",
			sizeOfMemory: 82 + 4096*4097,
			numSegs:      4096,
			wantErr:      true,
		},
		{
			name:         "non-divisible size rejected",
			sizeOfMemory: 82 + 4096*201 + 1,
			numSegs:      200,
			wantErr:      true,
		},
		{
			name:         "unsupported segment size rejected",
			sizeOfMemory: 82 + 2048*201,
			numSegs:      200,
			wantErr:      true,
		},
		{
			name:         "size too small rejected",
			sizeOfMemory: 82,
			numSegs:      200,
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segSize, dataBase, err := deriveGeometry(tt.sizeOfMemory, tt.numSegs)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("deriveGeometry(%d, %d): want error, got nil", tt.sizeOfMemory, tt.numSegs)
				}
				return
			}
			if err != nil {
				t.Fatalf("deriveGeometry(%d, %d): unexpected error: %v", tt.sizeOfMemory, tt.numSegs, err)
			}
			if segSize != tt.wantSegSize || dataBase != tt.wantDataBase {
				t.Fatalf("deriveGeometry(%d, %d) = (%d, %d), want (%d, %d)",
					tt.sizeOfMemory, tt.numSegs, segSize, dataBase, tt.wantSegSize, tt.wantDataBase)
			}
		})
	}
}

func Test_ParseHeader_validates_shared_ring_queue_fields(t *testing.T) {
	mkBuf := func(numSegs uint16, size uint32, readPos, writePos uint16) []byte {
		buf := make([]byte, protocol.SharedQueueMgmtOffset)
		binary.LittleEndian.PutUint32(buf[protocol.SharedQueueSizeOffset:], size)
		binary.LittleEndian.PutUint16(buf[protocol.SharedQueueNumSegOffset:], numSegs)
		binary.LittleEndian.PutUint16(buf[protocol.SharedQueueReadPosOffset:], readPos)
		binary.LittleEndian.PutUint16(buf[protocol.SharedQueueWritePosOffset:], writePos)
		return buf
	}
	tests := []struct {
		name    string
		buf     []byte
		wantErr bool
	}{
		{name: "valid header", buf: mkBuf(200, 82+4096*201, 3, 7)},
		{name: "positions at num_segs are valid", buf: mkBuf(200, 82+4096*201, 200, 200)},
		{name: "zero segments rejected", buf: mkBuf(0, 82+4096*201, 0, 0), wantErr: true},
		{name: "num_segs beyond max rejected", buf: mkBuf(2049, 82+4096*2050, 0, 0), wantErr: true},
		{name: "read_pos beyond num_segs rejected", buf: mkBuf(200, 82+4096*201, 201, 0), wantErr: true},
		{name: "write_pos beyond num_segs rejected", buf: mkBuf(200, 82+4096*201, 0, 201), wantErr: true},
		{name: "short buffer rejected", buf: make([]byte, 10), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseHeader(tt.buf)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseHeader: want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseHeader: unexpected error: %v", err)
			}
		})
	}
}

func Test_QueueFileName_matches_shmem_ipc_format(t *testing.T) {
	tests := []struct {
		direction string
		name      string
		want      string
	}{
		{direction: "rx", name: "abc123_1", want: "__cp_nano_rx_shared_memory_abc123_1__"},
		{direction: "tx", name: "worker7", want: "__cp_nano_tx_shared_memory_worker7__"},
		{direction: "rx", name: "", want: "__cp_nano_rx_shared_memory___"},
	}
	for _, tt := range tests {
		if got := queueFileName(tt.direction, tt.name); got != tt.want {
			t.Fatalf("queueFileName(%q, %q) = %q, want %q", tt.direction, tt.name, got, tt.want)
		}
	}
}

func Test_EnoughMemory_mirrors_c_space_check(t *testing.T) {
	r := testRing(t, uint32(protocol.SharedMemSegmentSize), 4)
	tests := []struct {
		name       string
		writePos   uint32
		readPos    uint32
		segNeeded  uint32
		wantEnough bool
	}{
		{name: "empty queue fits small message", writePos: 0, readPos: 0, segNeeded: 1, wantEnough: true},
		{name: "tail room fits message", writePos: 1, readPos: 0, segNeeded: 2, wantEnough: true},
		// The C algorithm compares against the *adjusted* read_pos, so a
		// 2-segment message at write_pos=3 is rejected even though segments
		// 3 and 0 look free; we mirror it exactly (shared_ring_queue.c:168-173).
		{name: "wrap-around message rejected per c algorithm", writePos: 3, readPos: 1, segNeeded: 2, wantEnough: false},
		{name: "wrap-around from empty queue fits", writePos: 3, readPos: 3, segNeeded: 2, wantEnough: true},
		{name: "message spans whole queue rejected", writePos: 0, readPos: 0, segNeeded: 4, wantEnough: false},
		{name: "no room between positions rejected", writePos: 1, readPos: 3, segNeeded: 2, wantEnough: false},
		{name: "zero segments always fits", writePos: 0, readPos: 0, segNeeded: 0, wantEnough: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.enoughMemory(tt.writePos, tt.readPos, tt.segNeeded); got != tt.wantEnough {
				t.Fatalf("enoughMemory(%d, %d, %d) = %v, want %v",
					tt.writePos, tt.readPos, tt.segNeeded, got, tt.wantEnough)
			}
		})
	}
}

func Test_Push_then_Peek_then_Pop_roundtrips_one_message(t *testing.T) {
	for _, segSize := range []uint32{uint32(protocol.SharedMemSegmentSize), uint32(protocol.SharedMemSegmentSizeBC)} {
		name := fmt.Sprintf("seg_size_%d", segSize)
		t.Run(name, func(t *testing.T) {
			rr := testRing(t, segSize, 8)
			msg := []byte("hello ring queue")
			if err := rr.push([][]byte{msg}); err != nil {
				t.Fatalf("push: %v", err)
			}
			if got := rr.writePos(); got != 1 {
				t.Fatalf("writePos after push = %d, want 1", got)
			}
			size, off, err := rr.peek()
			if err != nil {
				t.Fatalf("peek: %v", err)
			}
			if size != uint32(len(msg)) {
				t.Fatalf("peek size = %d, want %d", size, len(msg))
			}
			if got := rr.buf[off : off+int(size)]; !bytes.Equal(got, msg) {
				t.Fatalf("peek data = %q, want %q", got, msg)
			}
			if err := rr.pop(); err != nil {
				t.Fatalf("pop: %v", err)
			}
			if rr.readPos() != 1 {
				t.Fatalf("readPos after pop = %d, want 1", rr.readPos())
			}
			if _, _, err := rr.peek(); !errors.Is(err, errRingEmpty) {
				t.Fatalf("peek after pop = %v, want errRingEmpty", err)
			}
		})
	}
}

func Test_Push_concatenates_multiple_buffers_into_one_message(t *testing.T) {
	r := testRing(t, uint32(protocol.SharedMemSegmentSize), 8)
	buffers := [][]byte{[]byte("frag-1"), []byte("frag-2"), []byte("frag-3")}
	want := bytes.Join(buffers, nil)
	if err := r.push(buffers); err != nil {
		t.Fatalf("push: %v", err)
	}
	size, off, err := r.peek()
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if size != uint32(len(want)) {
		t.Fatalf("peek size = %d, want %d", size, len(want))
	}
	if got := r.buf[off : off+int(size)]; !bytes.Equal(got, want) {
		t.Fatalf("peek data = %q, want %q", got, want)
	}
}

func Test_Push_messages_span_multiple_segments_with_skip_magic(t *testing.T) {
	r := testRing(t, uint32(protocol.SharedMemSegmentSize), 8)
	msg := bytes.Repeat([]byte{0x42}, int(r.segSize)+100) // spans two segments
	if err := r.push([][]byte{msg}); err != nil {
		t.Fatalf("push: %v", err)
	}
	// mgmt[0] holds the size, mgmt[1] is marked as continuation.
	if got := r.mgmt(0); got != uint16(len(msg)) {
		t.Fatalf("mgmt[0] = %d, want %d", got, len(msg))
	}
	if got := r.mgmt(1); got != protocol.MagicSkipSegment {
		t.Fatalf("mgmt[1] = %#x, want skip magic %#x", got, protocol.MagicSkipSegment)
	}
	size, off, err := r.peek()
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if size != uint32(len(msg)) {
		t.Fatalf("peek size = %d, want %d", size, len(msg))
	}
	if got := r.buf[off : off+int(size)]; !bytes.Equal(got, msg) {
		t.Fatalf("peek data mismatch (len %d)", len(got))
	}
}

func Test_Push_rejects_message_over_max_write_size(t *testing.T) {
	r := testRing(t, uint32(protocol.SharedMemSegmentSize), 16)
	over := int(protocol.MaxWriteSize) + 1
	if err := r.push([][]byte{make([]byte, over)}); !errors.Is(err, errRingTooLarge) {
		t.Fatalf("push over max = %v, want errRingTooLarge", err)
	}
	// The queue must be untouched: still empty.
	if _, _, err := r.peek(); !errors.Is(err, errRingEmpty) {
		t.Fatalf("peek after failed push = %v, want errRingEmpty", err)
	}
}

func Test_Push_returns_full_when_no_room(t *testing.T) {
	r := testRing(t, uint32(protocol.SharedMemSegmentSize), 4)
	// Reader consumed up to segment 3; writer at segment 2, needs 3 segments.
	r.setReadPos(3)
	r.setWritePos(2)
	err := r.push([][]byte{make([]byte, 3*int(r.segSize))})
	if !errors.Is(err, errRingFull) {
		t.Fatalf("push to full queue = %v, want errRingFull", err)
	}
	if r.writePos() != 2 {
		t.Fatalf("writePos changed on failed push: %d, want 2", r.writePos())
	}
}

func Test_Push_wraps_around_the_end_of_the_queue(t *testing.T) {
	r := testRing(t, uint32(protocol.SharedMemSegmentSize), 4)
	// Writer and reader both at the last segment: a two-segment message
	// cannot fit in the one-segment tail, so push marks the tail as skip and
	// starts the message at segment 0.
	r.setWritePos(3)
	r.setReadPos(3)
	msg := make([]byte, 2*int(r.segSize))
	if err := r.push([][]byte{msg}); err != nil {
		t.Fatalf("push wrapping: %v", err)
	}
	if got := r.mgmt(3); got != protocol.MagicSkipSegment {
		t.Fatalf("mgmt[3] after wrap = %#x, want skip magic", got)
	}
	if got := r.mgmt(0); got != uint16(len(msg)) {
		t.Fatalf("mgmt[0] after wrap = %#x, want %d", got, len(msg))
	}
	if got := r.mgmt(1); got != protocol.MagicSkipSegment {
		t.Fatalf("mgmt[1] after wrap = %#x, want skip magic", got)
	}
	if got := r.writePos(); got != 2 {
		t.Fatalf("writePos after wrap = %d, want 2", got)
	}
	// The wrapped message is readable from segment 0; the trailing skip at
	// segment 3 is consumed by peek's skip traversal.
	size, off, err := r.peek()
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if size != uint32(len(msg)) {
		t.Fatalf("peek size = %d, want %d", size, len(msg))
	}
	if off != int(r.dataBase) {
		t.Fatalf("peek dataOff = %d, want %d (segment 0)", off, r.dataBase)
	}
	if r.readPos() != 0 {
		t.Fatalf("readPos after peek = %d, want 0", r.readPos())
	}
}

func Test_Peek_skips_and_frees_leading_skip_segments(t *testing.T) {
	r := testRing(t, uint32(protocol.SharedMemSegmentSize), 8)
	// Reader points at a run of skip segments (2,3) left behind after a wrap,
	// followed by a real message at segment 4.
	r.setMgmt(2, protocol.MagicSkipSegment)
	r.setMgmt(3, protocol.MagicSkipSegment)
	r.setMgmt(4, uint16(5))
	copy(r.dataSeg(4), []byte("12345"))
	r.setReadPos(2)
	r.setWritePos(5)
	size, off, err := r.peek()
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if size != 5 {
		t.Fatalf("peek size = %d, want 5", size)
	}
	if got := r.buf[off : off+int(size)]; string(got) != "12345" {
		t.Fatalf("peek data = %q, want 12345", got)
	}
	// Skip segments were freed and read advanced past them.
	for _, i := range []uint32{2, 3} {
		if got := r.mgmt(i); got != protocol.MagicEmptySegment {
			t.Fatalf("mgmt[%d] = %#x, want empty magic after skip", i, got)
		}
	}
	if r.readPos() != 4 {
		t.Fatalf("readPos after skip = %d, want 4", r.readPos())
	}
}

func Test_Peek_reports_corruption_instead_of_panicking(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(r *ring)
	}{
		{
			name: "empty magic at read position",
			corrupt: func(r *ring) {
				r.setMgmt(0, protocol.MagicEmptySegment)
			},
		},
		{
			name: "skip magic at read position",
			corrupt: func(r *ring) {
				r.setMgmt(0, protocol.MagicSkipSegment)
			},
		},
		{
			name: "size beyond max write size",
			corrupt: func(r *ring) {
				r.setMgmt(0, uint16(protocol.MaxWriteSize)+1)
			},
		},
		{
			name: "read position beyond num segs",
			corrupt: func(r *ring) {
				r.setReadPos(9)
				r.setWritePos(1)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testRing(t, uint32(protocol.SharedMemSegmentSize), 8)
			seedRing(t, r, 0, 1)
			r.setReadPos(0)
			r.setWritePos(1)
			tt.corrupt(r)
			if _, _, err := r.peek(); !errors.Is(err, errRingCorrupt) {
				t.Fatalf("peek on corrupted queue = %v, want errRingCorrupt", err)
			}
		})
	}
}

func Test_Pop_frees_all_segments_of_a_multisegment_message(t *testing.T) {
	r := testRing(t, uint32(protocol.SharedMemSegmentSize), 8)
	seedRing(t, r, 0, 2*r.segSize+10) // three segments
	if err := r.pop(); err != nil {
		t.Fatalf("pop: %v", err)
	}
	for i := uint32(0); i < 3; i++ {
		if got := r.mgmt(i); got != protocol.MagicEmptySegment {
			t.Fatalf("mgmt[%d] after pop = %#x, want empty magic", i, got)
		}
	}
	if r.readPos() != 3 {
		t.Fatalf("readPos after pop = %d, want 3", r.readPos())
	}
}

func Test_Pop_wraps_when_message_ends_before_queue_end(t *testing.T) {
	r := testRing(t, uint32(protocol.SharedMemSegmentSize), 4)
	// Reader at the last segment; the message at segment 3 needs two segments
	// (3 and a wrap to 0). The C pop frees segment 3, wraps, then frees
	// segments 0..1, ending readPos at 2 (shared_ring_queue.c:660-691).
	r.setReadPos(3)
	r.setWritePos(1)
	r.setMgmt(3, uint16(r.segSize+10))
	if err := r.pop(); err != nil {
		t.Fatalf("pop: %v", err)
	}
	for _, i := range []uint32{3, 0, 1} {
		if got := r.mgmt(i); got != protocol.MagicEmptySegment {
			t.Fatalf("mgmt[%d] after pop = %#x, want empty magic", i, got)
		}
	}
	if r.readPos() != 2 {
		t.Fatalf("readPos after wrap pop = %d, want 2", r.readPos())
	}
}
