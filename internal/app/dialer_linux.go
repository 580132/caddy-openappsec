//go:build linux

package app

import (
	"context"

	"github.com/580132/caddy-openappsec/internal/config"
	"github.com/580132/caddy-openappsec/internal/transport"
	"github.com/580132/caddy-openappsec/internal/transport/linux"
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
// The phase-2 comm socket stays open as the per-request signal/echo channel
// (§G.2) — the engine only drains the ring after being signaled with the
// session id on that socket. The keep-alive channel (§G.3) is a separate raw
// AF_UNIX socket.
type shmDialer struct {
	cfg config.EngineConfig
}

// Dial connects to the registration signal socket, completes phase 1 of the
// handshake to learn the verdict signal path, closes the one-shot
// registration socket, connects to the verdict path for phase 2, then opens
// the ring data connection. The phase-2 comm socket is passed into OpenRing
// (not closed): the C reference keeps it open for the attachment's lifetime
// (isIpcReady requires comm_socket > 0, ngx_cp_initializer.c:1067-1069) and
// uses it to signal every new session and to receive the verdict-ready echo.
func (d *shmDialer) Dial(ctx context.Context) (transport.EngineConn, error) {
	sig, err := linux.DialSignal(ctx, d.cfg.RegistrationSocket)
	if err != nil {
		return nil, err
	}
	verdictPath, err := register(ctx, sig, d.cfg)
	_ = sig.Close() // registration socket is one-shot (§G.1)
	if err != nil {
		return nil, err
	}
	comm, err := linux.DialSignal(ctx, verdictPath)
	if err != nil {
		return nil, err
	}
	if err := sendComm(ctx, comm, d.cfg); err != nil {
		_ = comm.Close()
		return nil, err
	}
	return linux.OpenRing(ctx, verdictPath, d.cfg, comm)
}

// DialKeepAlive opens the raw keep-alive socket (§G.3) without a handshake.
func (d *shmDialer) DialKeepAlive(ctx context.Context) (transport.EngineConn, error) {
	return linux.DialKeepAlive(ctx, d.cfg.KeepAlivePath)
}
