package mock

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yourname/caddy-openappsec/internal/protocol"
	"github.com/yourname/caddy-openappsec/internal/transport"
)

// stubAccept is one connection handed from dial to Accept.
type stubAccept struct {
	conn transport.EngineConn
	err  error
}

// stubListener is a minimal transport.Listener implementation standing in
// for any real listener; it proves the engine serves whatever
// transport.Listener it is injected with, not only the in-memory one. dial
// hands a new connection to the next Accept.
type stubListener struct {
	addr     string
	acceptCh chan stubAccept
	mu       sync.Mutex
	closed   bool
}

// var guards the interface contract at compile time.
var _ transport.Listener = (*stubListener)(nil)

// newStubListener returns a stub listener at addr.
func newStubListener(addr string) *stubListener {
	return &stubListener{addr: addr, acceptCh: make(chan stubAccept, 1)}
}

// Addr returns the configured address.
func (l *stubListener) Addr() string { return l.addr }

// Accept returns the next dialed connection, blocking until one is
// available or the listener is closed.
func (l *stubListener) Accept() (transport.EngineConn, error) {
	a, ok := <-l.acceptCh
	if !ok {
		return nil, transport.ErrClosed
	}
	return a.conn, a.err
}

// Close closes the listener, unblocking a pending Accept with ErrClosed.
func (l *stubListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return transport.ErrClosed
	}
	l.closed = true
	close(l.acceptCh)
	return nil
}

// dial connects the attachment side of a new pair and returns it; the
// engine side is delivered by the next Accept. It fails if the listener is
// closed.
func (l *stubListener) dial() (transport.EngineConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, transport.ErrClosed
	}
	a, e := newPipePair()
	select {
	case l.acceptCh <- stubAccept{conn: e}:
		return a, nil
	default:
		// No Accept pending (only possible before the engine is started on
		// this listener); drop the pair rather than block.
		_ = a.Close()
		_ = e.Close()
		return nil, errors.New("stub: listener not accepting")
	}
}

// newPipePair returns the attachment and engine ends of a net.Pipe pair
// framed as a transport.EngineConn.
func newPipePair() (attachment, engine *pipeConn) {
	a, e := net.Pipe()
	return &pipeConn{conn: a}, &pipeConn{conn: e}
}

// pipeConn adapts a net.Conn byte stream to the message-framed
// transport.EngineConn contract: each Send is one 4-byte-length-prefixed
// write, and each Recv reads exactly one frame.
type pipeConn struct {
	conn   net.Conn
	closed atomic.Bool
}

// var guards the interface contract at compile time.
var _ transport.EngineConn = (*pipeConn)(nil)

// Send writes payload as one frame, honoring ctx's deadline.
func (c *pipeConn) Send(ctx context.Context, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetWriteDeadline(dl)
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	_, err := c.conn.Write(frame)
	_ = c.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return c.mapErr(err, ctx)
	}
	return nil
}

// Recv returns the next frame, honoring ctx's deadline.
func (c *pipeConn) Recv(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetReadDeadline(dl)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		return nil, c.mapErr(err, ctx)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return nil, c.mapErr(err, ctx)
	}
	_ = c.conn.SetReadDeadline(time.Time{})
	return payload, nil
}

// Close closes the connection; later calls return transport.ErrClosed.
func (c *pipeConn) Close() error {
	if c.closed.Swap(true) {
		return transport.ErrClosed
	}
	return c.conn.Close()
}

// mapErr translates a transport-level error into the EngineConn contract:
// a ctx deadline surfaces as ctx.Err(), a peer close as ErrClosed.
func (c *pipeConn) mapErr(err error, ctx context.Context) error {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return transport.ErrClosed
	}
	return err
}

// Test_Engine_NewWithListener_ServesInjectedListener proves the engine
// serves any injected transport.Listener: a stub listener over net.Pipe
// carries the full handshake and a scripted verdict, and the engine address
// comes from the listener itself, not from a memory registry key.
func Test_Engine_NewWithListener_ServesInjectedListener(t *testing.T) {
	// Given
	const addr = "stub://engine/1"
	l := newStubListener(addr)
	eng, err := NewWithListener(l)
	if err != nil {
		t.Fatalf("NewWithListener: %v", err)
	}
	defer eng.Close()
	eng.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})

	// Then — the address derives from the injected listener.
	if got := eng.Addr(); got != addr {
		t.Fatalf("Addr() = %q, want %q (from listener)", got, addr)
	}

	// When — dial through the stub transport.
	c, err := l.dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	send := func(b []byte) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.Send(ctx, b); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	recv := func() []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		b, err := c.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		return b
	}

	// Then — registration gets a path reply naming the listener address...
	send(protocol.Registration{AttachmentType: 0, WorkerID: 1, WorkersAmount: 1, FamilyName: "stub"}.Encode())
	mustEqualBytes(t, protocol.RegistrationReply{Path: addr}.Encode(), recv(), "registration reply")

	// ...and comm data gets an ack.
	send(protocol.CommData{UID: "stub"}.Encode())
	mustEqualBytes(t, protocol.Ack{Value: 1}.Encode(), recv(), "comm ack")

	// When — a REQUEST_START frame gets the scripted verdict with the echoed
	// session id.
	const sid = uint32(42)
	send(protocol.RequestStart{SessionID: sid, Method: "GET", UnparsedURI: "/"}.Encode())
	mustEqualBytes(t, (&protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: sid}).Encode(), recv(), "verdict")

	// When — the engine goes down, the injected listener is closed with it.
	if err := eng.SetEngineDown(); err != nil {
		t.Fatalf("SetEngineDown: %v", err)
	}
	if _, err := l.dial(); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("dial after SetEngineDown = %v, want transport.ErrClosed", err)
	}
}

// Test_Engine_NewWithListener_NilListener verifies a nil listener is
// rejected.
func Test_Engine_NewWithListener_NilListener(t *testing.T) {
	if _, err := NewWithListener(nil); err == nil {
		t.Fatal("NewWithListener(nil) succeeded, want error")
	}
}
