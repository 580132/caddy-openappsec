// Package memory implements the transport interfaces with in-process pipes,
// addressed by a string that stands in for the engine socket path of the
// future linux implementation. It is safe for concurrent use and serves the
// mock engine and unit tests.
package memory

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/yourname/caddy-openappsec/internal/transport"
)

// registry maps addresses to live listeners. The address string stands in
// for the engine socket path the linux implementation will bind.
var (
	registryMu sync.Mutex
	registry   = make(map[string]*Listener)
)

// Listen registers a listener at addr and returns it. The engine side of the
// mock uses Listen to serve a path, mirroring the engine binding its
// registration socket (docs/attachment-protocol.md §G.1).
//
// Listen fails if addr is empty or already in use. A closed listener is
// unregistered, so its address can be reused.
func Listen(addr string) (*Listener, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, errors.New("memory: address must be non-empty")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, ok := registry[addr]; ok {
		return nil, fmt.Errorf("memory: address %q already in use", addr)
	}
	l := &Listener{
		addr:     addr,
		closeCh:  make(chan struct{}),
		notifyCh: make(chan struct{}, 1),
	}
	registry[addr] = l
	return l, nil
}

// Dial connects to the listener registered at addr and returns the
// attachment-side end of a new connection; the listener's next Accept
// returns the engine-side end of the same pair. Dial fails if no listener is
// registered at addr (for example because it was closed), mirroring a
// connection to a path that does not exist.
func Dial(addr string) (transport.EngineConn, error) {
	registryMu.Lock()
	l := registry[addr]
	registryMu.Unlock()
	if l == nil {
		return nil, fmt.Errorf("memory: no listener at address %q", addr)
	}
	return l.dial()
}

// Listener is an in-memory listener addressed by a string. It implements
// transport.Listener. Connections dialed before they are accepted wait in an
// unbounded queue, so Dial never blocks while the listener is open.
type Listener struct {
	mu       sync.Mutex
	addr     string
	closed   bool
	closeCh  chan struct{} // closed when the listener dies; wakes blocked Accept
	notifyCh chan struct{} // 1-buffered: signals that pending is non-empty

	pending []*pendingPair
}

// pendingPair is one dialed-but-maybe-not-accepted connection.
type pendingPair struct {
	attachment *Conn // returned by Dial
	engine     *Conn // returned by Accept
}

// var guards the interface contract at compile time.
var _ transport.Listener = (*Listener)(nil)

// Addr returns the address the listener was registered at.
func (l *Listener) Addr() string { return l.addr }

// dial creates a new connection pair and queues it for Accept.
func (l *Listener) dial() (*Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, transport.ErrClosed
	}
	a, e := newPair()
	l.pending = append(l.pending, &pendingPair{attachment: a, engine: e})
	select {
	case l.notifyCh <- struct{}{}:
	default:
	}
	return a, nil
}

// Accept returns the engine-side end of the next dialed connection, blocking
// until one is available or the listener is closed. A closed listener makes
// Accept return nil, transport.ErrClosed.
func (l *Listener) Accept() (transport.EngineConn, error) {
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return nil, transport.ErrClosed
		}
		if len(l.pending) > 0 {
			p := l.pending[0]
			l.pending[0] = nil
			l.pending = l.pending[1:]
			l.mu.Unlock()
			return p.engine, nil
		}
		l.mu.Unlock()

		select {
		case <-l.closeCh:
			// Loop: the mutex check observes the closed flag.
		case <-l.notifyCh:
			// Loop: re-check the queue.
		}
	}
}

// Close closes the listener, unblocking a pending Accept with ErrClosed, and
// unregisters its address. Connections already established by Dial are
// unaffected. It returns nil on the first call and ErrClosed afterwards.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return transport.ErrClosed
	}
	l.closed = true
	close(l.closeCh)
	l.mu.Unlock()

	registryMu.Lock()
	if registry[l.addr] == l {
		delete(registry, l.addr)
	}
	registryMu.Unlock()
	return nil
}
