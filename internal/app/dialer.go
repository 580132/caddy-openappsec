package app

import (
	"context"

	"github.com/580132/caddy-openappsec/internal/config"
	"github.com/580132/caddy-openappsec/internal/transport"
	"github.com/580132/caddy-openappsec/internal/transport/memory"
	"github.com/580132/caddy-openappsec/internal/transport/socket"
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

// NewDialer returns the dialer selected by cfg.Transport. The transport knob
// is resolved here, at the seam between config and connection: "memory" dials
// the in-process transport, "socket" dials cross-process TCP, and "shm" (or
// the empty platform default) resolves to the tagged shared-memory dialer —
// the linux shm transport where it exists, a fail-open stub elsewhere.
func NewDialer(cfg config.EngineConfig) Dialer {
	switch cfg.Transport {
	case config.TransportMemory:
		return &memoryDialer{cfg: cfg}
	case config.TransportSocket:
		return &socketDialer{cfg: cfg}
	default:
		// TransportSHM and the empty value both mean the platform default.
		return newShmDialer(cfg)
	}
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

// socketDialer dials the cross-process TCP transport and runs the registration
// handshake over the connection. It backs local E2E against the mock engine.
// The addresses are the engine's registration and keep-alive TCP endpoints.
type socketDialer struct {
	cfg config.EngineConfig
}

// Dial connects to the TCP listener at the registration socket and completes
// the two-phase handshake over the connection.
func (d *socketDialer) Dial(ctx context.Context) (transport.EngineConn, error) {
	conn, err := socket.Dial(d.cfg.RegistrationSocket)
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
func (d *socketDialer) DialKeepAlive(ctx context.Context) (transport.EngineConn, error) {
	return socket.Dial(d.cfg.KeepAlivePath)
}
