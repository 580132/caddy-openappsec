//go:build linux

package app

import (
	"context"

	"github.com/yourname/caddy-openappsec/internal/config"
	"github.com/yourname/caddy-openappsec/internal/transport"
	"github.com/yourname/caddy-openappsec/internal/transport/linux"
)

// newShmDialer returns the shared-memory linux dialer for the engine transport.
// It is the platform default: NewDialer resolves an empty Transport (and an
// explicit TransportSHM) on linux to this dialer.
func newShmDialer(cfg config.EngineConfig) Dialer {
	return &shmDialer{cfg: cfg}
}

// shmDialer dials the engine's registration signal socket, performs the
// two-phase registration handshake (docs/attachment-protocol.md §G.1, §G.2),
// then opens the shared-memory ring queues for request/verdict traffic (§D).
// The keep-alive channel (§G.3) is a separate raw AF_UNIX socket.
type shmDialer struct {
	cfg config.EngineConfig
}

// Dial connects to the registration signal socket, completes the handshake to
// learn the verdict signal path, then opens the ring data connection.
func (d *shmDialer) Dial(ctx context.Context) (transport.EngineConn, error) {
	sig, err := linux.DialSignal(ctx, d.cfg.RegistrationSocket)
	if err != nil {
		return nil, err
	}
	verdictPath, err := handshake(ctx, sig, d.cfg)
	if err != nil {
		_ = sig.Close()
		return nil, err
	}
	if err := sig.Close(); err != nil {
		return nil, err
	}
	return linux.OpenRing(ctx, verdictPath, d.cfg)
}

// DialKeepAlive opens the raw keep-alive socket (§G.3) without a handshake.
func (d *shmDialer) DialKeepAlive(ctx context.Context) (transport.EngineConn, error) {
	return linux.DialKeepAlive(ctx, d.cfg.KeepAlivePath)
}
