package app

import (
	"context"
	"sync"

	"github.com/580132/caddy-openappsec/internal/config"
)

// Pool is a registry of live engine connections keyed by the engine's
// registration address. It reference-counts users so a Caddy reload that
// re-registers the same engine address reuses the existing connection
// instead of dialing a second, split-brained one. The last Release closes the
// connection and removes the entry. Concurrency-safe.
type Pool struct {
	mu      sync.Mutex
	cfg     config.EngineConfig
	dialer  Dialer
	entries map[string]*poolEntry
}

// poolEntry tracks one address's references and its shared live connection.
type poolEntry struct {
	refs  int
	conn  *Conn
	err   error
	ready chan struct{} // closed once conn/err is set by the first acquirer
}

// NewPool returns an empty pool that dials with d.
func NewPool(cfg config.EngineConfig, d Dialer) *Pool {
	return &Pool{
		cfg:     cfg,
		dialer:  d,
		entries: make(map[string]*poolEntry),
	}
}

// Acquire returns the shared live connection for addr, dialing and
// handshaking on first use and incrementing the reference count. Concurrent
// acquirers share the same connection; only the first dials. The caller must
// call Release when done. If the engine is unreachable on first use, the dial
// error is returned and the entry is discarded so a later Acquire retries.
func (p *Pool) Acquire(ctx context.Context, addr string) (*Conn, error) {
	p.mu.Lock()
	e, ok := p.entries[addr]
	if !ok {
		e = &poolEntry{ready: make(chan struct{})}
		e.refs = 1
		p.entries[addr] = e
		p.mu.Unlock()

		conn, err := p.dialer.Dial(ctx)
		p.mu.Lock()
		if err != nil {
			e.err = err
			delete(p.entries, addr)
			p.mu.Unlock()
			close(e.ready)
			return nil, err
		}
		e.conn = newConn(p.cfg, p.dialer, addr, conn)
		close(e.ready)
		p.mu.Unlock()
		return e.conn, nil
	}

	e.refs++
	ready := e.ready
	p.mu.Unlock()

	select {
	case <-ready:
	case <-ctx.Done():
		p.mu.Lock()
		e.refs--
		p.mu.Unlock()
		return nil, ctx.Err()
	}

	p.mu.Lock()
	conn, err := e.conn, e.err
	p.mu.Unlock()
	return conn, err
}

// Release decrements the reference count for addr and, on the last release,
// closes the connection and removes the entry. Releasing an unknown address
// is a no-op.
func (p *Pool) Release(addr string) {
	p.mu.Lock()
	e, ok := p.entries[addr]
	if !ok {
		p.mu.Unlock()
		return
	}
	e.refs--
	if e.refs > 0 {
		p.mu.Unlock()
		return
	}
	delete(p.entries, addr)
	p.mu.Unlock()
	if e.conn != nil {
		_ = e.conn.Close()
	}
}

// Close tears down every entry, closing all live connections. Used on full
// teardown (process exit); a single app's Stop should Release instead so
// other users of the same address keep their connection.
func (p *Pool) Close() {
	p.mu.Lock()
	entries := p.entries
	p.entries = make(map[string]*poolEntry)
	p.mu.Unlock()
	for _, e := range entries {
		if e.conn != nil {
			_ = e.conn.Close()
		}
	}
}

// globalPool is the process-global engine connection registry that makes a
// Caddy reload re-registering the same engine address share one connection.
var globalPool struct {
	mu   sync.Mutex
	pool *Pool
}

// GlobalPool returns the process-global pool, creating it on first use with
// the given configuration and dialer. The first caller's dialer is used for
// every subsequent acquisition.
func GlobalPool(cfg config.EngineConfig, d Dialer) *Pool {
	globalPool.mu.Lock()
	defer globalPool.mu.Unlock()
	if globalPool.pool == nil {
		globalPool.pool = NewPool(cfg, d)
	}
	return globalPool.pool
}
