//go:build linux

package app

import (
	"testing"

	"github.com/yourname/caddy-openappsec/internal/config"
)

// Test_NewDialer_shm_transport_returns_shm_dialer verifies the platform
// default dispatch on linux: an explicit TransportSHM and the empty Transport
// both resolve to the shared-memory dialer.
func Test_NewDialer_shm_transport_returns_shm_dialer(t *testing.T) {
	for _, transport := range []string{config.TransportSHM, ""} {
		d := NewDialer(config.EngineConfig{Transport: transport})
		if _, ok := d.(*shmDialer); !ok {
			t.Fatalf("NewDialer(%q) = %T, want *shmDialer", transport, d)
		}
	}
}
