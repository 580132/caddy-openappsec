package socket

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/580132/caddy-openappsec/internal/transport"
)

// conn is a transport.EngineConn over a TCP byte stream framed with a 4-byte
// little-endian length prefix: one Send writes one frame, which the peer's
// Recv reads back as exactly one payload.
//
// Send and Recv are safe for concurrent use and proceed independently: Send
// serializes writes on sendMu while Recv serializes reads on recvMu, so
// frames never interleave on the wire. Close closes the underlying socket,
// which unblocks a blocked Send or Recv; those operations then observe the
// closed flag and report transport.ErrClosed.
type conn struct {
	netConn net.Conn

	sendMu sync.Mutex // serializes Send; also guards the write deadline
	recvMu sync.Mutex // serializes Recv; also guards the read deadline

	mu     sync.Mutex // guards closed
	closed bool
}

// var guards the interface contract at compile time.
var _ transport.EngineConn = (*conn)(nil)

// isClosed reports whether the connection has been closed.
func (c *conn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// ctxError converts a socket timeout error back into the context error that
// caused it. The only deadlines ever set on the socket come from ctx — either
// its own deadline or the watchdog tripped by its cancellation — so a timeout
// always means ctx finished. The context can lag the socket deadline by a
// moment, so when ctx has a deadline that has already passed the result is
// resolved directly instead of racing the context timer. It returns nil for
// errors that are not socket timeouts.
func ctxError(ctx context.Context, err error) error {
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		return nil
	}
	if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
		return context.DeadlineExceeded
	}
	return ctx.Err()
}

// Send writes payload to the peer as one length-prefixed frame. It blocks
// until the frame is accepted, ctx is done, or the connection is closed. The
// payload bytes are copied onto the wire as the frame is written and never
// retained, so the caller may reuse the slice as soon as Send returns.
//
// Send returns transport.ErrClosed when the connection is closed (including
// when it is closed while a write is blocked) and ctx.Err() when ctx finishes
// before the frame is accepted. A ctx deadline is mapped onto the socket
// write deadline; a ctx cancelled without a deadline also unblocks a blocked
// write, via a watchdog that trips the write deadline.
func (c *conn) Send(ctx context.Context, payload []byte) error {
	if c.isClosed() {
		return transport.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.sendMu.Lock()
	if c.isClosed() {
		c.sendMu.Unlock()
		return transport.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		c.sendMu.Unlock()
		return err
	}

	// A watchdog trips the write deadline when ctx is done, unblocking a
	// write stuck on a full send buffer. cbDone closes when the watchdog has
	// fully run; the teardown below waits for a started watchdog before
	// clearing the deadline and releasing the lock, so it can never touch
	// the shared write deadline after this Send has finished.
	cbDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		c.netConn.SetWriteDeadline(time.Now())
		close(cbDone)
	})
	// Teardown order (LIFO): wait for a started watchdog, clear the write
	// deadline, then release the lock.
	defer func() {
		if !stop() {
			<-cbDone
		}
	}()
	defer c.netConn.SetWriteDeadline(time.Time{})
	defer c.sendMu.Unlock()

	if dl, ok := ctx.Deadline(); ok {
		if err := c.netConn.SetWriteDeadline(dl); err != nil {
			if c.isClosed() {
				return transport.ErrClosed
			}
			return fmt.Errorf("socket: set write deadline: %w", err)
		}
	}
	if err := writeFrame(c.netConn, payload); err != nil {
		if c.isClosed() {
			return transport.ErrClosed
		}
		if cerr := ctxError(ctx, err); cerr != nil {
			return cerr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
}

// Recv returns the next complete payload from the peer, blocking until one
// is available, ctx is done, or the connection is closed — including when the
// peer closed it, which surfaces as an end-of-stream that is reported as
// transport.ErrClosed. The returned slice is freshly allocated and owned by
// the caller.
//
// transport.ErrClosed wins over a done context. A ctx deadline is mapped onto
// the socket read deadline; a ctx cancelled without a deadline also unblocks
// a blocked read, via a watchdog that trips the read deadline.
func (c *conn) Recv(ctx context.Context) ([]byte, error) {
	if c.isClosed() {
		return nil, transport.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.recvMu.Lock()
	if c.isClosed() {
		c.recvMu.Unlock()
		return nil, transport.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		c.recvMu.Unlock()
		return nil, err
	}

	cbDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		c.netConn.SetReadDeadline(time.Now())
		close(cbDone)
	})
	// Teardown order (LIFO): wait for a started watchdog, clear the read
	// deadline, then release the lock.
	defer func() {
		if !stop() {
			<-cbDone
		}
	}()
	defer c.netConn.SetReadDeadline(time.Time{})
	defer c.recvMu.Unlock()

	if dl, ok := ctx.Deadline(); ok {
		if err := c.netConn.SetReadDeadline(dl); err != nil {
			if c.isClosed() {
				return nil, transport.ErrClosed
			}
			return nil, fmt.Errorf("socket: set read deadline: %w", err)
		}
	}
	buf, err := readFrame(c.netConn)
	if err != nil {
		if c.isClosed() {
			return nil, transport.ErrClosed
		}
		if errors.Is(err, io.EOF) {
			return nil, transport.ErrClosed
		}
		if cerr := ctxError(ctx, err); cerr != nil {
			return nil, cerr
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return buf, nil
}

// Close closes the connection in both directions, unblocking a pending Send
// or Recv with transport.ErrClosed: closing the underlying socket makes the
// blocked read or write fail, and the operation then observes the closed flag
// and reports ErrClosed. It returns nil on the first call and ErrClosed on
// any later call.
func (c *conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return transport.ErrClosed
	}
	c.closed = true
	c.mu.Unlock()
	_ = c.netConn.Close()
	return nil
}
