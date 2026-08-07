// Package linux implements the production transport between the Caddy
// attachment and the open-appsec engine: shared-memory ring queues for data
// (docs/attachment-protocol.md §D) and AF_UNIX sockets for registration and
// keep-alive (§G).
//
// This file holds the pure-logic core of the ring queue. It operates on a
// []byte that, on linux, is the mmap'd shared-memory file; the same code runs
// in unit tests on any platform with a plain byte slice. Every offset, magic
// and framing rule traces to core/shmem_ipc_2/shared_ring_queue.{h,c} and
// internal/protocol/const.go.
package linux

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/580132/caddy-openappsec/internal/protocol"
)

// Errors returned by the pure ring logic. Ring operations report errRingEmpty
// when no message is available and errRingFull when the queue has no room; a
// ring corruption or a too-large message is a permanent condition and is
// reported as an error rather than a panic or an infinite loop.
var (
	errRingEmpty    = errors.New("linux: ring queue empty")
	errRingFull     = errors.New("linux: ring queue full")
	errRingTooLarge = errors.New("linux: message exceeds max write size")
	errRingCorrupt  = errors.New("linux: ring queue corrupted")
)

// Directions of the one-way queues, from the attachment's (user, non-owner)
// point of view. The attachment writes requests into the service's rx queue
// and reads verdicts from the service's tx queue; the direction names come
// from isTowardsOwner (shmem_ipc.c:85-90, 107).
const (
	dirWrite = "rx" // attachment Send -> service rx queue
	dirRead  = "tx" // attachment Recv <- service tx queue
)

// ring is the pure-logic view of a shared ring queue. buf is the mapped
// memory (mmap on linux, a plain slice in tests); segSize, numSegs and
// dataBase are derived from the header via deriveGeometry. A ring is not safe
// for concurrent use by itself; the linux connection serializes access.
type ring struct {
	buf      []byte
	segSize  uint32
	numSegs  uint32
	dataBase uint32
}

// ringHeader is the parsed fixed part of the SharedRingQueue struct
// (shared_ring_queue.h:50-60).
type ringHeader struct {
	numSegs      uint32
	sizeOfMemory uint32
	readPos      uint32
	writePos     uint32
}

// parseHeader reads and validates the fixed header fields. It fails on a
// buffer too small to hold the header, a num_of_data_segments outside
// [1, MaxDataSegments], or read/write positions beyond num_of_data_segments
// (mirroring isGetPossitionSucceccful, shared_ring_queue.c:177-196).
func parseHeader(buf []byte) (ringHeader, error) {
	var h ringHeader
	if len(buf) < protocol.SharedQueueMgmtOffset {
		return h, fmt.Errorf("%w: buffer %d bytes < header %d", errRingCorrupt, len(buf), protocol.SharedQueueMgmtOffset)
	}
	h.numSegs = uint32(binary.LittleEndian.Uint16(buf[protocol.SharedQueueNumSegOffset:]))
	h.sizeOfMemory = binary.LittleEndian.Uint32(buf[protocol.SharedQueueSizeOffset:])
	h.readPos = uint32(binary.LittleEndian.Uint16(buf[protocol.SharedQueueReadPosOffset:]))
	h.writePos = uint32(binary.LittleEndian.Uint16(buf[protocol.SharedQueueWritePosOffset:]))
	if h.numSegs == 0 || h.numSegs > uint32(protocol.MaxDataSegments) {
		return h, fmt.Errorf("%w: num_of_data_segments=%d", errRingCorrupt, h.numSegs)
	}
	if h.readPos > h.numSegs || h.writePos > h.numSegs {
		return h, fmt.Errorf("%w: read_pos=%d write_pos=%d num_segs=%d", errRingCorrupt, h.readPos, h.writePos, h.numSegs)
	}
	return h, nil
}

// deriveGeometry computes the effective segment size and the byte offset of
// data_segment[0] from size_of_memory and num_of_data_segments, inverting the
// owner's size computation (shared_ring_queue.c:98-113):
//
//	size_of_memory = 82 + seg_size*(1 + num_segs)
//	data_base      = 82 + seg_size
//
// BC (1024) and full (4096) segment modes are both supported; any other
// derived segment size means the header is inconsistent and the queue is
// reported corrupted.
func deriveGeometry(sizeOfMemory, numSegs uint32) (segSize, dataBase uint32, err error) {
	if numSegs == 0 || numSegs > uint32(protocol.MaxDataSegments) {
		return 0, 0, fmt.Errorf("%w: num_of_data_segments=%d", errRingCorrupt, numSegs)
	}
	if sizeOfMemory <= uint32(protocol.SharedQueueMgmtOffset) {
		return 0, 0, fmt.Errorf("%w: size_of_memory=%d too small", errRingCorrupt, sizeOfMemory)
	}
	num := sizeOfMemory - uint32(protocol.SharedQueueMgmtOffset)
	if num%(1+numSegs) != 0 {
		return 0, 0, fmt.Errorf("%w: size_of_memory=%d not a multiple of 1+num_segs=%d", errRingCorrupt, sizeOfMemory, 1+numSegs)
	}
	segSize = num / (1 + numSegs)
	if segSize != uint32(protocol.SharedMemSegmentSize) && segSize != uint32(protocol.SharedMemSegmentSizeBC) {
		return 0, 0, fmt.Errorf("%w: unsupported segment size=%d", errRingCorrupt, segSize)
	}
	return segSize, uint32(protocol.SharedQueueMgmtOffset) + segSize, nil
}

// newRing validates buf's header and geometry and returns a ring view of it.
func newRing(buf []byte) (*ring, error) {
	h, err := parseHeader(buf)
	if err != nil {
		return nil, err
	}
	segSize, dataBase, err := deriveGeometry(h.sizeOfMemory, h.numSegs)
	if err != nil {
		return nil, err
	}
	if need := int(dataBase) + int(h.numSegs)*int(segSize); len(buf) < need {
		return nil, fmt.Errorf("%w: buffer %d bytes < needed %d", errRingCorrupt, len(buf), need)
	}
	return &ring{buf: buf, segSize: segSize, numSegs: h.numSegs, dataBase: dataBase}, nil
}

// queueFileName builds the shared-memory file name for one direction,
// mirroring shmem_ipc.c:108 ("__cp_nano_%s_shared_memory_%s__").
func queueFileName(direction, name string) string {
	return fmt.Sprintf("__cp_nano_%s_shared_memory_%s__", direction, name)
}

// readPos and writePos return the current ring positions.
func (r *ring) readPos() uint32 {
	return uint32(binary.LittleEndian.Uint16(r.buf[protocol.SharedQueueReadPosOffset:]))
}

func (r *ring) writePos() uint32 {
	return uint32(binary.LittleEndian.Uint16(r.buf[protocol.SharedQueueWritePosOffset:]))
}

func (r *ring) setReadPos(v uint32) {
	binary.LittleEndian.PutUint16(r.buf[protocol.SharedQueueReadPosOffset:], uint16(v))
}

func (r *ring) setWritePos(v uint32) {
	binary.LittleEndian.PutUint16(r.buf[protocol.SharedQueueWritePosOffset:], uint16(v))
}

// mgmt and setMgmt read and write one uint16 entry of the management segment,
// indexed by data-segment index (shared_ring_queue.c:29-33, 314-317).
func (r *ring) mgmt(i uint32) uint16 {
	off := protocol.SharedQueueMgmtOffset + int(i)*2
	return binary.LittleEndian.Uint16(r.buf[off:])
}

func (r *ring) setMgmt(i uint32, v uint16) {
	off := protocol.SharedQueueMgmtOffset + int(i)*2
	binary.LittleEndian.PutUint16(r.buf[off:], v)
}

// dataSeg returns the bytes of one data segment (shared_ring_queue.c:104-113).
func (r *ring) dataSeg(i uint32) []byte {
	off := int(r.dataBase) + int(i)*int(r.segSize)
	return r.buf[off : off+int(r.segSize)]
}

// enoughMemory mirrors isThereEnoughMemoryInQueue (shared_ring_queue.c:133-175).
func (r *ring) enoughMemory(writePos, readPos, numSegsNeeded uint32) bool {
	if numSegsNeeded >= r.numSegs {
		return false
	}
	if writePos+numSegsNeeded > r.numSegs {
		numSegsNeeded += r.numSegs - writePos
	}
	if writePos+numSegsNeeded >= r.numSegs {
		readPos += r.numSegs
	}
	return writePos+numSegsNeeded < readPos || writePos >= readPos
}

// push concatenates buffers into one message spanning consecutive segments,
// mirroring pushBuffersToQueue (shared_ring_queue.c:500-618). It returns
// errRingTooLarge when the total size exceeds max_write_size, errRingFull
// when the queue lacks space (no partial writes happen), or errRingCorrupt
// when the header positions are inconsistent.
func (r *ring) push(buffers [][]byte) error {
	var total uint32
	for _, b := range buffers {
		total += uint32(len(b))
		if total > uint32(protocol.MaxWriteSize) {
			return errRingTooLarge
		}
	}
	writePos := r.writePos()
	readPos := r.readPos()
	if readPos > r.numSegs || writePos > r.numSegs {
		return fmt.Errorf("%w: read_pos=%d write_pos=%d num_segs=%d", errRingCorrupt, readPos, writePos, r.numSegs)
	}
	numSegsNeeded := (total + r.segSize - 1) / r.segSize
	if !r.enoughMemory(writePos, readPos, numSegsNeeded) {
		return errRingFull
	}
	if writePos+numSegsNeeded > r.numSegs {
		// The message does not fit before the end of the queue: mark the
		// trailing segments as continuation of the previous (fake) message
		// and start the new message at segment 0.
		for ; writePos < r.numSegs; writePos++ {
			r.setMgmt(writePos, protocol.MagicSkipSegment)
		}
		writePos = 0
	}
	startPos := writePos
	r.setMgmt(startPos, uint16(total))
	// The message bytes are contiguous across segment boundaries (the C code
	// memcpy's into a flat char* spanning segments, shared_ring_queue.c:593-605),
	// so copy into the full contiguous range, not a single segment slice.
	dataStart := int(r.dataBase) + int(startPos)*int(r.segSize)
	dst := r.buf[dataStart : dataStart+int(total)]
	for _, b := range buffers {
		copy(dst, b)
		dst = dst[len(b):]
	}
	writePos++
	endPos := writePos + numSegsNeeded - 1
	for ; writePos < endPos; writePos++ {
		r.setMgmt(writePos, protocol.MagicSkipSegment)
	}
	if writePos >= r.numSegs {
		writePos = 0
	}
	r.setWritePos(writePos)
	return nil
}

// peek returns the size and byte offset of the next message without consuming
// it, mirroring peekToQueue (shared_ring_queue.c:433-498). It advances past
// and frees skip segments, returns errRingEmpty when the queue is empty, and
// errRingCorrupt when the management entry is a magic value or exceeds
// max_write_size (where the C code would silently hand back a bogus size).
func (r *ring) peek() (size uint32, dataOff int, err error) {
	readPos := r.readPos()
	writePos := r.writePos()
	if readPos == writePos {
		return 0, 0, errRingEmpty
	}
	if readPos > r.numSegs || writePos > r.numSegs {
		return 0, 0, fmt.Errorf("%w: read_pos=%d write_pos=%d num_segs=%d", errRingCorrupt, readPos, writePos, r.numSegs)
	}
	if r.mgmt(readPos) == protocol.MagicSkipSegment {
		for readPos < r.numSegs && r.mgmt(readPos) == protocol.MagicSkipSegment {
			r.setMgmt(readPos, protocol.MagicEmptySegment)
			readPos++
		}
	}
	if readPos == r.numSegs {
		readPos = 0
	}
	m := r.mgmt(readPos)
	switch m {
	case protocol.MagicEmptySegment, protocol.MagicSkipSegment:
		return 0, 0, fmt.Errorf("%w: mgmt[%d]=%#x at read position", errRingCorrupt, readPos, m)
	}
	if uint32(m) > uint32(protocol.MaxWriteSize) {
		return 0, 0, fmt.Errorf("%w: mgmt[%d]=%d exceeds max write size", errRingCorrupt, readPos, m)
	}
	size = uint32(m)
	dataOff = int(r.dataBase) + int(readPos)*int(r.segSize)
	if int(dataOff)+int(size) > len(r.buf) {
		return 0, 0, fmt.Errorf("%w: message at %d of %d bytes overflows buffer", errRingCorrupt, dataOff, size)
	}
	r.setReadPos(readPos)
	return size, dataOff, nil
}

// pop frees the segments of the message at the read position, mirroring
// popFromQueue (shared_ring_queue.c:633-695). It returns errRingEmpty when
// the queue is already empty.
func (r *ring) pop() error {
	readPos := r.readPos()
	writePos := r.writePos()
	if readPos == writePos {
		return errRingEmpty
	}
	if readPos > r.numSegs || writePos > r.numSegs {
		return fmt.Errorf("%w: read_pos=%d write_pos=%d num_segs=%d", errRingCorrupt, readPos, writePos, r.numSegs)
	}
	numReadSegs := (uint32(r.mgmt(readPos)) + r.segSize - 1) / r.segSize
	if readPos+numReadSegs > r.numSegs {
		for ; readPos < r.numSegs; readPos++ {
			r.setMgmt(readPos, protocol.MagicEmptySegment)
		}
		readPos = 0
	}
	endPos := readPos + numReadSegs
	for ; readPos < endPos; readPos++ {
		r.setMgmt(readPos, protocol.MagicEmptySegment)
	}
	if readPos < r.numSegs && r.mgmt(readPos) == protocol.MagicSkipSegment {
		for ; readPos < r.numSegs; readPos++ {
			r.setMgmt(readPos, protocol.MagicEmptySegment)
		}
	}
	if readPos == r.numSegs {
		readPos = 0
	}
	r.setReadPos(readPos)
	return nil
}
