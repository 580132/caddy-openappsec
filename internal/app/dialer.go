package app

import (
	"context"

	"github.com/yourname/caddy-openappsec/internal/config"
	"github.com/yourname/caddy-openappsec/internal/transport"
	"github.com/yourname/caddy-openappsec/internal/transport/memory"
)

// Dialer establishes a live, handshaked connection to the open-appsec engine.
// The returned connection has completed the two-phase registration handshake
// and is ready for request/verdict traffic. On error Dial returns a nil conn;
// the engine is unreachable and the fail-open policy degrades requests to
// allow-through.
type Dialer interface {
	// Dial connects to the engine's registration socket, completes the
	// two-phase handshake, and returns the request/verdict connection.
	Dial(ctx context.Context) (transport.EngineConn, error)
	// DialKeepAlive opens the raw keep-alive socket (§G.3) without any
	// handshake. The keep-alive frames are app-layer framing moved verbatim.
	DialKeepAlive(ctx context.Context) (transport.EngineConn, error)
}

// memoryDialer dials the in-process transport and runs the registration
// handshake over the connection. It backs unit tests and local E2E against
// the mock engine. The address is the engine's registration socket path.
type memoryDialer struct {
	cfg config.EngineConfig
}

// Dial connects to the in-memory listener at the registration socket and
// completes the two-phase handshake over the connection.
func (d *memoryDialer) Dial(ctx context.Context) (transport.EngineConn, error) {
	conn, err := memory.Dial(d.cfg.RegistrationSocket)
	if err != nil {
		return nil, err
	}
	if _, err := handshake(ctx, conn, d.cfg); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// DialKeepAlive opens the raw keep-alive socket (§G.3) without a handshake.
func (d *memoryDialer) DialKeepAlive(ctx context.Context) (transport.EngineConn, error) {
	return memory.Dial(d.cfg.KeepAlivePath)
}
