//go:build !linux

package app

import (
	"testing"

	"github.com/580132/caddy-openappsec/internal/config"
)

// Test_NewDialer_shm_transport_returns_stub_dialer verifies the platform
// default dispatch on non-linux: an explicit TransportSHM and the empty
// Transport both resolve to the fail-open stub dialer.
func Test_NewDialer_shm_transport_returns_stub_dialer(t *testing.T) {
	for _, transport := range []string{config.TransportSHM, ""} {
		d := NewDialer(config.EngineConfig{Transport: transport})
		if _, ok := d.(*stubDialer); !ok {
			t.Fatalf("NewDialer(%q) = %T, want *stubDialer", transport, d)
		}
	}
}
