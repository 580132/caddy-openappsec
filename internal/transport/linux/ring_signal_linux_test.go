//go:build linux

package linux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/580132/caddy-openappsec/internal/protocol"
	"github.com/580132/caddy-openappsec/internal/transport"
)

// fakeComm is an in-memory transport.EngineConn used to simulate the phase-2
// comm signal socket in ringConn tests. Recv returns the next queued message.
type fakeComm struct {
	mu   sync.Mutex
	msgs [][]byte
	recv []byte
	sent [][]byte
	// block, when set, makes Recv wait until released or the ctx is done.
	block  bool
	closed bool
}

func (f *fakeComm) Send(ctx context.Context, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return transport.ErrClosed
	}
	f.sent = append(f.sent, append([]byte(nil), payload...))
	return nil
}

func (f *fakeComm) Recv(ctx context.Context) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, transport.ErrClosed
	}
	if len(f.recv) > 0 {
		b := f.recv
		f.recv = nil
		return b, nil
	}
	if len(f.msgs) > 0 {
		b := f.msgs[0]
		f.msgs = f.msgs[1:]
		return b, nil
	}
	if f.block {
		timer := time.NewTimer(200 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, context.DeadlineExceeded
		}
	}
	return nil, context.DeadlineExceeded
}

func (f *fakeComm) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// Test_RingConn_Send_signals_session_id verifies Send writes the payload's
// 4-byte little-endian session id (offset 2, after data_type) to the comm
// socket after pushing the payload.
func Test_RingConn_Send_signals_session_id(t *testing.T) {
	// Given a ringConn with a fake comm and an empty ring
	fc := &fakeComm{}
	wq := &ringQueue{ring: testRing(t, uint32(protocol.SharedMemSegmentSize), 64)}
	rq := &ringQueue{ring: testRing(t, uint32(protocol.SharedMemSegmentSize), 64)}
	c := newRingConn(wq, rq, fc, time.Millisecond)

	// When a REQUEST_START frame with session id 7 is sent
	payload := []byte{0, 0, 7, 0, 0, 0, 'x'}
	if err := c.Send(context.Background(), payload); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Then the ring got the payload and the comm socket got the session id
	size, _, err := wq.ring.peek()
	if err != nil {
		t.Fatalf("ring write queue was not written: %v", err)
	}
	if size != uint32(len(payload)) {
		t.Fatalf("ring message size = %d, want %d", size, len(payload))
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if len(fc.sent) != 1 {
		t.Fatalf("comm signals = %d, want 1", len(fc.sent))
	}
	got := fc.sent[0]
	want := []byte{7, 0, 0, 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("signaled = %v, want %v", got, want)
	}
}

// Test_RingConn_Send_skips_signal_without_session_id verifies a payload too
// short to carry a session id is pushed but not signaled.
func Test_RingConn_Send_skips_signal_without_session_id(t *testing.T) {
	fc := &fakeComm{}
	wq := &ringQueue{ring: testRing(t, uint32(protocol.SharedMemSegmentSize), 64)}
	rq := &ringQueue{ring: testRing(t, uint32(protocol.SharedMemSegmentSize), 64)}
	c := newRingConn(wq, rq, fc, time.Millisecond)

	if err := c.Send(context.Background(), []byte{0, 1}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if len(fc.sent) != 0 {
		t.Fatalf("signals = %d, want 0 for short payload", len(fc.sent))
	}
}

// Test_RingConn_Recv_waits_for_echo verifies Recv consumes the 4-byte echo
// from the comm socket before returning the ring message.
func Test_RingConn_Recv_waits_for_echo(t *testing.T) {
	// Given a ring with one seeded verdict message and a comm carrying the echo
	fc := &fakeComm{recv: []byte{3, 0, 0, 0}}
	wq := &ringQueue{ring: testRing(t, uint32(protocol.SharedMemSegmentSize), 64)}
	rq := &ringQueue{ring: testRing(t, uint32(protocol.SharedMemSegmentSize), 64)}
	seedRing(t, rq.ring, 0, 6)
	c := newRingConn(wq, rq, fc, time.Millisecond)

	// When Recv is called
	msg, err := c.Recv(context.Background())

	// Then the echo was consumed and the ring message returned
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if len(msg) != 6 {
		t.Fatalf("Recv returned %d bytes, want 6", len(msg))
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if len(fc.recv) != 0 {
		t.Fatal("echo not fully consumed")
	}
}

// Test_RingConn_Recv_echo_buffer_replays_coalesced_bytes verifies Recv replays
// leftover bytes when a single comm Recv returned two echoes (the unix conn
// coalesces within readCoalesce).
func Test_RingConn_Recv_echo_buffer_replays_coalesced_bytes(t *testing.T) {
	// Two echoes coalesced into one 8-byte comm message.
	echoes := make([]byte, 8)
	binary.LittleEndian.PutUint32(echoes[0:], 3)
	binary.LittleEndian.PutUint32(echoes[4:], 5)
	fc := &fakeComm{recv: echoes}
	wq := &ringQueue{ring: testRing(t, uint32(protocol.SharedMemSegmentSize), 64)}
	rq := &ringQueue{ring: testRing(t, uint32(protocol.SharedMemSegmentSize), 64)}
	c := newRingConn(wq, rq, fc, time.Millisecond)

	// First Recv consumes echo[0:4] and returns ring message 1.
	seedRing(t, rq.ring, 0, 6)
	if _, err := c.Recv(context.Background()); err != nil {
		t.Fatalf("first Recv: %v", err)
	}
	// Seed ring message 2 before the second Recv: each echo pairs with one
	// ring message, so the second Recv must replay the buffered echo[4:8] and
	// return message 2 without issuing another comm Recv.
	seedRing(t, rq.ring, 1, 6)
	if _, err := c.Recv(context.Background()); err != nil {
		t.Fatalf("second Recv (buffered echo): %v", err)
	}
}

// Test_RingConn_Recv_blocks_until_echo verifies Recv does not return a ring
// message before the comm echo arrives.
func Test_RingConn_Recv_blocks_until_echo(t *testing.T) {
	fc := &fakeComm{block: true}
	wq := &ringQueue{ring: testRing(t, uint32(protocol.SharedMemSegmentSize), 64)}
	rq := &ringQueue{ring: testRing(t, uint32(protocol.SharedMemSegmentSize), 64)}
	seedRing(t, rq.ring, 0, 6)
	c := newRingConn(wq, rq, fc, time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := c.Recv(ctx)
	if err == nil {
		t.Fatal("Recv returned before echo arrived")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("Recv = %v, want ctx error", err)
	}
}
