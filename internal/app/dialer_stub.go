//go:build !linux

package app

import (
	"context"
	"fmt"
	"runtime"

	"github.com/yourname/caddy-openappsec/internal/config"
	"github.com/yourname/caddy-openappsec/internal/transport"
)

// NewDialer returns a dialer that reports the shared-memory engine transport
// is unavailable on this platform. Fail-open still applies: the engine is
// unreachable, so requests pass through.
func NewDialer(cfg config.EngineConfig) Dialer {
	return &stubDialer{cfg: cfg}
}

// stubDialer describes the linux-only engine transport without dialing it.
// It exists so the caddy app wiring compiles and behaves correctly on
// non-linux hosts (the engine is unreachable → fail-open allows requests).
type stubDialer struct {
	cfg config.EngineConfig
}

func (d *stubDialer) Dial(ctx context.Context) (transport.EngineConn, error) {
	return nil, fmt.Errorf(
		"app: engine shared-memory transport is only available on linux, running on %s",
		runtime.GOOS,
	)
}

func (d *stubDialer) DialKeepAlive(ctx context.Context) (transport.EngineConn, error) {
	return nil, fmt.Errorf(
		"app: engine keep-alive socket is only available on linux, running on %s",
		runtime.GOOS,
	)
}
