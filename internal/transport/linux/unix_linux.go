//go:build linux

package linux

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/580132/caddy-openappsec/internal/transport"
)

// readCoalesce is how long Recv waits for more bytes after the first read
// before returning what it has as one message. The handshake messages of §G
// are small and request-response, so one Send is normally delivered by a
// single write; this window absorbs fragmentation without ever waiting for a
// full round trip.
const readCoalesce = 10 * time.Millisecond

// DialSignal dials the AF_UNIX socket at path and returns a byte-oriented
// message-framed connection over it, wrapping net.Dial("unix", path). It is
// used for the registration socket (SHARED_REGISTRATION_SIGNAL_PATH, §G.1),
// the comm socket (shared_verdict_signal_path, §G.2) and the keep-alive
// socket (SHARED_KEEP_ALIVE_PATH, §G.3) — DialKeepAlive is the documented
// entry point for the last one. The transport does not interpret the bytes:
// the two-phase handshake frames are built and consumed by the app layer.
func DialSignal(ctx context.Context, path string) (transport.EngineConn, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	return &unixConn{conn: conn}, nil
}

// DialKeepAlive opens the keep-alive socket of §G.3. It is the same AF_UNIX
// byte connection as DialSignal; the keep-alive payload
// (worker_id + container_id_size + container_id) is app-layer framing that
// this transport moves verbatim.
func DialKeepAlive(ctx context.Context, path string) (transport.EngineConn, error) {
	return DialSignal(ctx, path)
}

// unixConn is a transport.EngineConn over a net.Conn byte stream. Send writes
// the whole payload; Recv accumulates one message by reading until a short
// quiet window, matching the request-response handshake of §G. Closing the
// connection closes the underlying socket, which unblocks a peer blocked in
// Read or Write with ErrClosed.
type unixConn struct {
	mu     sync.Mutex
	conn   net.Conn
	closed bool
}

// var guards the interface contract at compile time.
var _ transport.EngineConn = (*unixConn)(nil)

// isClosed reports whether the connection has been closed.
func (c *unixConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Send writes the entire payload to the socket. It returns ErrClosed when the
// connection is closed and ctx.Err() when ctx is already done. A ctx deadline
// is mapped onto the socket write deadline.
func (c *unixConn) Send(ctx context.Context, payload []byte) error {
	if c.isClosed() {
		return transport.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		c.conn.SetWriteDeadline(dl)
		defer c.conn.SetWriteDeadline(time.Time{})
	}
	for len(payload) > 0 {
		n, err := c.conn.Write(payload)
		if err != nil {
			if c.isClosed() {
				return transport.ErrClosed
			}
			return err
		}
		payload = payload[n:]
	}
	return nil
}

// Recv returns the next message read from the socket. It blocks until at
// least one byte is available, ctx is done, or the connection closes; once
// data arrives it keeps reading until the readCoalesce window expires so the
// whole handshake message is returned as one unit. ErrClosed wins over a done
// context. The returned slice is owned by the caller.
func (c *unixConn) Recv(ctx context.Context) ([]byte, error) {
	if c.isClosed() {
		return nil, transport.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		c.conn.SetReadDeadline(dl)
		defer c.conn.SetReadDeadline(time.Time{})
	}
	tmp := make([]byte, 4096)
	for {
		n, err := c.conn.Read(tmp)
		if n > 0 {
			return c.coalesce(ctx, append([]byte(nil), tmp[:n]...))
		}
		if err != nil {
			if c.isClosed() {
				return nil, transport.ErrClosed
			}
			if errors.Is(err, io.EOF) {
				return nil, transport.ErrClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				continue
			}
			return nil, err
		}
	}
}

// coalesce appends any bytes that arrive within readCoalesce to msg and
// returns the complete message. A quiet window, EOF or a closed connection
// ends the accumulation.
func (c *unixConn) coalesce(ctx context.Context, msg []byte) ([]byte, error) {
	c.conn.SetReadDeadline(time.Now().Add(readCoalesce))
	defer c.conn.SetReadDeadline(time.Time{})
	tmp := make([]byte, 4096)
	for {
		n, err := c.conn.Read(tmp)
		if n > 0 {
			msg = append(msg, tmp[:n]...)
			continue
		}
		if err == nil {
			continue
		}
		if c.isClosed() {
			return msg, nil
		}
		if errors.Is(err, io.EOF) {
			return msg, nil
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return msg, nil
		}
		return nil, err
	}
}

// Close closes the underlying socket, unblocking a blocked Send or Recv with
// ErrClosed. It returns nil on the first call and ErrClosed afterwards.
func (c *unixConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return transport.ErrClosed
	}
	c.closed = true
	c.mu.Unlock()
	return c.conn.Close()
}
