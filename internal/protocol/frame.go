package protocol

import (
	"encoding/binary"
	"errors"
)

// ErrTruncated is returned when a message ends before all declared fields
// could be read.
var ErrTruncated = errors.New("protocol: truncated message")

// wire is a growable byte buffer for building a message from fragments. All
// multi-byte fields are little-endian unless the port method is used, which
// mirrors the C sender writing plain integers directly (host byte order on
// x86) and ports via htons.
type wire struct {
	buf []byte
}

func (w *wire) u8(v uint8) {
	w.buf = append(w.buf, v)
}

func (w *wire) u16(v uint16) {
	w.buf = binary.LittleEndian.AppendUint16(w.buf, v)
}

func (w *wire) u32(v uint32) {
	w.buf = binary.LittleEndian.AppendUint32(w.buf, v)
}

func (w *wire) u64(v uint64) {
	w.buf = binary.LittleEndian.AppendUint64(w.buf, v)
}

func (w *wire) i64(v int64) {
	w.buf = binary.LittleEndian.AppendUint64(w.buf, uint64(v))
}

// port writes a uint16 in network byte order, mirroring htons() in the nginx
// sender (ngx_cp_io.c:970,983).
func (w *wire) port(v uint16) {
	w.buf = binary.BigEndian.AppendUint16(w.buf, v)
}

// str writes a uint16 length prefix followed by the string bytes.
func (w *wire) str(s string) {
	w.u16(uint16(len(s)))
	w.buf = append(w.buf, s...)
}

// str8 writes a uint8 length prefix followed by the string bytes. It is used
// by the keep-alive frame, whose name length is a single byte (§G.3).
func (w *wire) str8(s string) {
	w.u8(uint8(len(s)))
	w.buf = append(w.buf, s...)
}

func (w *wire) bytes(b []byte) {
	w.buf = append(w.buf, b...)
}

// reader reads fields from a message, tracking the current offset.
type reader struct {
	buf []byte
	off int
}

func (r *reader) remaining() int {
	return len(r.buf) - r.off
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.remaining() < n {
		return nil, ErrTruncated
	}
	b := r.buf[r.off : r.off+n]
	r.off += n
	return b, nil
}

func (r *reader) u8() (uint8, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *reader) u16() (uint16, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (r *reader) u32() (uint32, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (r *reader) u64() (uint64, error) {
	b, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func (r *reader) i64() (int64, error) {
	b, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(b)), nil
}

// port reads a uint16 in network byte order.
func (r *reader) port() (uint16, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *reader) str() (string, error) {
	n, err := r.u16()
	if err != nil {
		return "", err
	}
	b, err := r.take(int(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// str8 reads a uint8 length prefix followed by the string bytes.
func (r *reader) str8() (string, error) {
	n, err := r.u8()
	if err != nil {
		return "", err
	}
	b, err := r.take(int(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
