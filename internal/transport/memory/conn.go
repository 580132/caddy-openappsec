package memory

import (
	"context"
	"slices"
	"sync"

	"github.com/yourname/caddy-openappsec/internal/transport"
)

// Conn is one end of an in-memory connection. Payloads sent on one end are
// queued on the peer and returned by its Recv. A Conn exists only as part of
// a connected pair, created via the package's Listen/Dial functions or a
// Listener; it implements transport.EngineConn.
type Conn struct {
	mu      sync.Mutex
	closed  bool
	closeCh chan struct{} // closed when the connection dies; wakes blocked Recv

	inbound  [][]byte
	notifyCh chan struct{} // 1-buffered: signals that inbound is non-empty
	peer     *Conn
}

// var guards the interface contract at compile time.
var _ transport.EngineConn = (*Conn)(nil)

// newPair returns the two ends of a connected connection.
func newPair() (*Conn, *Conn) {
	a := &Conn{closeCh: make(chan struct{}), notifyCh: make(chan struct{}, 1)}
	b := &Conn{closeCh: make(chan struct{}), notifyCh: make(chan struct{}, 1)}
	a.peer = b
	b.peer = a
	return a, b
}

// Send delivers a copy of payload to the peer's receive queue.
//
// The in-memory queue is unbounded, so Send never blocks: it returns
// ErrClosed if either end of the connection is closed, and ctx.Err() if ctx
// is already done when the call starts. A cancellation arriving mid-call
// cannot abort an already-completed delivery; the blocking linux
// implementation will honor it via the context.
func (c *Conn) Send(ctx context.Context, payload []byte) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return transport.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p := c.peer
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return transport.ErrClosed
	}
	p.inbound = append(p.inbound, slices.Clone(payload))
	select {
	case p.notifyCh <- struct{}{}:
	default:
	}
	return nil
}

// Recv returns the next payload queued by the peer, blocking until one is
// available, ctx is done, or the connection is closed. ErrClosed wins over a
// done context, so a cancelled Recv on a closed connection reports ErrClosed.
// The returned slice is owned by the caller.
func (c *Conn) Recv(ctx context.Context) ([]byte, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, transport.ErrClosed
		}
		if len(c.inbound) > 0 {
			p := c.inbound[0]
			c.inbound[0] = nil
			c.inbound = c.inbound[1:]
			c.mu.Unlock()
			return p, nil
		}
		c.mu.Unlock()

		select {
		case <-ctx.Done():
			c.mu.Lock()
			closed := c.closed
			c.mu.Unlock()
			if closed {
				return nil, transport.ErrClosed
			}
			return nil, ctx.Err()
		case <-c.closeCh:
			// Loop: the mutex check observes the closed flag.
		case <-c.notifyCh:
			// Loop: re-check the queue.
		}
	}
}

// Close closes both ends of the connection, unblocking pending operations
// with ErrClosed: closing one end also closes the peer, mirroring socket
// teardown. It returns nil on the first call that closes this end and
// ErrClosed afterwards — including when the peer closed it first.
func (c *Conn) Close() error {
	err := c.markClosed()
	_ = c.peer.markClosed()
	return err
}

// markClosed marks one end closed, returning ErrClosed if it already was.
func (c *Conn) markClosed() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return transport.ErrClosed
	}
	c.closed = true
	close(c.closeCh)
	return nil
}
