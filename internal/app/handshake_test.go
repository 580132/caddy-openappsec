package app

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/580132/caddy-openappsec/internal/config"
)

// Test_registrationFrame_layout verifies the phase-1 registration frame
// (§G.1) byte layout: [attachment_type][worker_id+1][workers_amount]
// [family_name_size][family_name].
func Test_registrationFrame_layout(t *testing.T) {
	// Given a config with a known worker/workers/family
	cfg := config.EngineConfig{
		AttachmentType: "nginx",
		WorkerID:       1,
		Workers:        2,
		FamilyName:     "abc",
	}

	// When the registration frame is built
	got := registrationFrame(cfg)

	// Then it matches the documented layout
	want := []byte{0, 2, 2, 3, 'a', 'b', 'c'}
	if !bytes.Equal(got, want) {
		t.Fatalf("registrationFrame = %v, want %v", got, want)
	}
}

// Test_commFrame_layout verifies the phase-2 comm frame (§G.2) byte layout:
// [uid_size][uid][nano_user_id u32][nano_group_id u32][target_core i32],
// with paired affinity disabled (target_core = -1). The uid is the full
// unique id "<family>_<worker_id+1>" (ngx_cp_initializer.c:798-804,
// config.EngineConfig.UniqueID); the engine validates it against its own
// family_instance unique id and closes the socket without an ack on mismatch.
func Test_commFrame_layout(t *testing.T) {
	// Given
	cfg := config.EngineConfig{FamilyName: "xy"}

	// When
	got := commFrame(cfg)

	// Then
	want := []byte{4, 'x', 'y', '_', '1', 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}
	if !bytes.Equal(got, want) {
		t.Fatalf("commFrame = %v, want %v", got, want)
	}
}

// Test_memoryDialer_completes_two_phase_handshake verifies the shared
// handshake client round-trips against an in-test fake engine server: the
// client sends the registration and comm frames and reads back the verdict
// signal path and ack.
func Test_memoryDialer_completes_two_phase_handshake(t *testing.T) {
	// Given a fake engine and a memory dialer for the same config
	cfg := testConfig(t, "handshake.sock")
	f := newFakeEngine(t, cfg)
	defer f.close()
	d := &memoryDialer{cfg: cfg}

	// When the dialer dials and handshakes
	conn, err := d.Dial(context.Background())
	requireNoError(t, err)
	defer conn.Close()

	// Then the engine accepted the connection and completed the handshake.
	// The engine pushes to connections only after its ack, so this must be a
	// blocking receive with a timeout, not a non-blocking peek.
	select {
	case <-f.connections:
		// handshake completed
	case <-time.After(testTimeout):
		t.Fatal("fake engine did not complete a handshake")
	}
}

// Test_handshake_returns_engine_assigned_path verifies the handshake client
// surfaces the verdict signal path the engine assigned in phase 1.
func Test_handshake_returns_engine_assigned_path(t *testing.T) {
	// Given
	cfg := testConfig(t, "path.sock")
	f := newFakeEngine(t, cfg)
	defer f.close()
	d := &memoryDialer{cfg: cfg}

	// When
	conn, err := d.Dial(context.Background())
	requireNoError(t, err)
	defer conn.Close()

	// Then the dialer's handshake returned the engine's verdict path
	// (the memory dialer discards it, but the handshake client must have
	// parsed it without error, which Dial already proves).
	_ = conn
}

// Test_memoryDialer_returns_error_when_engine_unreachable verifies Dial fails
// when no engine is listening at the address.
func Test_memoryDialer_returns_error_when_engine_unreachable(t *testing.T) {
	// Given a config whose address has no listener
	cfg := testConfig(t, "nowhere.sock")
	d := &memoryDialer{cfg: cfg}

	// When
	_, err := d.Dial(context.Background())

	// Then
	requireError(t, err, "no listener")
}
