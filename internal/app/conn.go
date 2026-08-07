package app

import (
	"context"
	"sync"
	"time"

	"github.com/580132/caddy-openappsec/internal/config"
	"github.com/580132/caddy-openappsec/internal/protocol"
	"github.com/580132/caddy-openappsec/internal/transport"
)

// RequestData is the app-layer input for one engine inspection session. It
// carries the metadata needed to open a REQUEST_START block; header/body
// streaming and the HTTP handler glue belong to a later wave.
type RequestData struct {
	Start protocol.RequestStart
}

// backoffDelay returns the reconnect backoff for a failed attempt: it doubles
// from min each attempt and is capped at max. attempt 0 is the first retry.
func backoffDelay(min, max time.Duration, attempt int) time.Duration {
	d := min
	for i := 0; i < attempt && d < max; i++ {
		d *= 2
		if d <= 0 {
			return max // overflow guard
		}
	}
	if d > max {
		d = max
	}
	return d
}

// Conn is one live, continuously-maintained engine connection. It owns the
// underlying transport conn, a keep-alive goroutine, and the per-connection
// session allocator. The allocator and the keep-alive goroutine survive
// reconnects, so session ids stay continuous across an engine restart.
//
// Keep-alive (§G.3) runs on its own raw socket dialed via the Dialer's
// DialKeepAlive — never on the request/verdict conn, which on linux is the
// shared-memory ring and would be corrupted by foreign frames. The interval
// (cfg.KeepAliveIntervalMs, default 300s) stays under the 300s engine expiry.
//
// Concurrency-safe: Send/Recv paths and the keep-alive goroutine may run
// concurrently.
type Conn struct {
	mu     sync.Mutex // guards conn and closed
	cfg    config.EngineConfig
	dialer Dialer
	addr   string
	conn   transport.EngineConn
	closed bool

	kaMu   sync.Mutex // guards kaConn
	kaConn transport.EngineConn

	sMu      sync.Mutex // guards sessions
	sessions *protocol.SessionAllocator

	recvMu sync.Mutex // serializes Recv so frames are not stolen mid-session

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// newConn wraps a freshly-dialed conn and starts the keep-alive loop.
func newConn(cfg config.EngineConfig, d Dialer, addr string, conn transport.EngineConn) *Conn {
	c := &Conn{
		cfg:      cfg,
		dialer:   d,
		addr:     addr,
		conn:     conn,
		sessions: protocol.NewSessionAllocator(),
		stop:     make(chan struct{}),
	}
	c.wg.Add(1)
	go c.keepAliveLoop()
	return c
}

// Closed reports whether the conn has been torn down by Close.
func (c *Conn) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Close stops the keep-alive loop and closes the underlying conn and the
// keep-alive socket.
func (c *Conn) Close() error {
	c.stopOnce.Do(func() { close(c.stop) })
	c.wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.kaMu.Lock()
	if c.kaConn != nil {
		_ = c.kaConn.Close()
		c.kaConn = nil
	}
	c.kaMu.Unlock()
	return nil
}

// send delivers payload to the engine, redialing once if the current conn is
// dead. The caller keeps ownership of payload.
func (c *Conn) send(ctx context.Context, payload []byte) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return transport.ErrClosed
	}
	conn := c.conn
	c.mu.Unlock()

	if err := conn.Send(ctx, payload); err == nil {
		return nil
	}
	nc, err := c.reconnect(ctx)
	if err != nil {
		return err
	}
	return nc.Send(ctx, payload)
}

// reconnect replaces the underlying conn with a freshly dialed one. On
// success the old conn is closed and the session allocator is left untouched.
func (c *Conn) reconnect(ctx context.Context) (transport.EngineConn, error) {
	nc, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = nc.Close()
		return nil, transport.ErrClosed
	}
	old := c.conn
	c.conn = nc
	if old != nil {
		_ = old.Close()
	}
	return nc, nil
}

// recv reads the next frame from the engine, serialized against the
// keep-alive path and concurrent request waiters.
func (c *Conn) recv(ctx context.Context) ([]byte, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, transport.ErrClosed
	}
	conn := c.conn
	c.mu.Unlock()
	return conn.Recv(ctx)
}

// SendRequest opens an inspection session: it allocates a session id, sends
// the REQUEST_START block, and returns the id. The caller waits on
// AwaitVerdict and must call EndRequest to reclaim the id.
func (c *Conn) SendRequest(ctx context.Context, req RequestData) (uint32, error) {
	c.sMu.Lock()
	sid := c.sessions.Allocate()
	c.sMu.Unlock()

	start := req.Start
	start.SessionID = sid
	if err := c.send(ctx, start.Encode()); err != nil {
		c.sMu.Lock()
		c.sessions.Reclaim(sid)
		c.sMu.Unlock()
		return 0, err
	}
	return sid, nil
}

// AwaitVerdict blocks until the engine replies with a verdict for sid. Frames
// for other sessions (and non-verdict frames) are consumed and skipped.
func (c *Conn) AwaitVerdict(ctx context.Context, sid uint32) (*protocol.Verdict, error) {
	for {
		payload, err := c.recv(ctx)
		if err != nil {
			return nil, err
		}
		v, err := protocol.ParseVerdict(payload)
		if err != nil {
			continue // not a verdict frame
		}
		if v.SessionID != sid {
			continue
		}
		return v, nil
	}
}

// EndRequest reclaims sid so the allocator can reuse it.
func (c *Conn) EndRequest(sid uint32) {
	c.sMu.Lock()
	c.sessions.Reclaim(sid)
	c.sMu.Unlock()
}

// SendResponse opens a response inspection session on the same connection as
// the request traffic: it allocates a session id, submits the RESPONSE_CODE
// and CONTENT_LENGTH frames, and returns the id. The caller waits on
// AwaitVerdict and must call EndRequest to reclaim the id.
func (c *Conn) SendResponse(ctx context.Context, code int, contentLength int64) (uint32, error) {
	c.sMu.Lock()
	sid := c.sessions.Allocate()
	c.sMu.Unlock()

	if err := c.send(ctx, (protocol.ResponseCode{SessionID: sid, Code: uint16(code)}).Encode()); err != nil {
		c.sMu.Lock()
		c.sessions.Reclaim(sid)
		c.sMu.Unlock()
		return 0, err
	}
	if err := c.send(ctx, (protocol.ContentLength{SessionID: sid, Length: uint64(contentLength)}).Encode()); err != nil {
		c.sMu.Lock()
		c.sessions.Reclaim(sid)
		c.sMu.Unlock()
		return 0, err
	}
	return sid, nil
}

// SendResponseBody submits one RESPONSE_BODY chunk for a response inspection
// session opened by SendResponse.
func (c *Conn) SendResponseBody(ctx context.Context, sid uint32, chunk []byte, isLast bool) error {
	body := protocol.BodyChunk{
		DataType:    protocol.DataTypeResponseBody,
		SessionID:   sid,
		IsLastChunk: isLast,
		Data:        chunk,
	}
	return c.send(ctx, body.Encode())
}
