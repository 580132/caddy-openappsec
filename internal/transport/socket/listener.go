package socket

import (
	"errors"
	"fmt"
	"net"

	"github.com/yourname/caddy-openappsec/internal/transport"
)

// Listener accepts TCP connections at a local address. It implements
// transport.Listener. Each accepted connection is wrapped as a *conn, so the
// peer end of the connection is a transport.EngineConn.
type Listener struct {
	ln net.Listener
}

// var guards the interface contract at compile time.
var _ transport.Listener = (*Listener)(nil)

// Addr returns the address the listener is bound to, in the canonical
// "tcp://host:port" form used by Dial. For a listener bound to an ephemeral
// port it reports the actual port that was allocated.
func (l *Listener) Addr() string {
	return "tcp://" + l.ln.Addr().String()
}

// Accept returns the next connection, blocking until one is available or the
// listener is closed. If the listener is closed, Accept returns nil,
// transport.ErrClosed.
func (l *Listener) Accept() (transport.EngineConn, error) {
	nc, err := l.ln.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil, transport.ErrClosed
		}
		return nil, fmt.Errorf("socket: accept: %w", err)
	}
	return &conn{netConn: nc}, nil
}

// Close closes the listener, unblocking a pending Accept with
// transport.ErrClosed. Connections already accepted are unaffected. It
// returns nil on the first call and transport.ErrClosed on any later call.
func (l *Listener) Close() error {
	err := l.ln.Close()
	if errors.Is(err, net.ErrClosed) {
		return transport.ErrClosed
	}
	return err
}
