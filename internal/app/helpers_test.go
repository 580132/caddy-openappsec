package app

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/yourname/caddy-openappsec/internal/config"
	"github.com/yourname/caddy-openappsec/internal/protocol"
	"github.com/yourname/caddy-openappsec/internal/transport"
	"github.com/yourname/caddy-openappsec/internal/transport/memory"
)

// testTimeout bounds every blocking operation in the fake engine so a broken
// unblock never hangs the suite.
const testTimeout = 5 * time.Second

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func requireError(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substr)
	}
	if !bytes.Contains([]byte(err.Error()), []byte(substr)) {
		t.Fatalf("expected error containing %q, got: %v", substr, err)
	}
}

// boolPtr returns a pointer to b, for exercising the FailOpen tri-state.
func boolPtr(b bool) *bool { return &b }

// testConfig returns an EngineConfig with small, test-friendly timings and a
// unique socket address. The caller may override fields.
func testConfig(t *testing.T, addr string) config.EngineConfig {
	t.Helper()
	return config.EngineConfig{
		RegistrationSocket:    addr,
		KeepAlivePath:         addr + "-keepalive",
		VerdictSignalPath:     "/dev/shm/test/" + addr + "/verdict",
		FamilyName:            "test-container",
		WorkerID:              0,
		Workers:               1,
		AttachmentType:        "nginx",
		KeepAliveIntervalMs:   1000,
		RegistrationTimeoutMs: 100,
		ReconnectBackoffMinMs: 5,
		ReconnectBackoffMaxMs: 50,
		FailOpenTimeoutMs:     5,
		FailOpenHoldTimeoutMs: 25,
		ReqMaxProcessingMs:    150,
		MinRetriesForVerdict:  1,
		MaxRetriesForVerdict:  3,
		HoldVerdictRetries:    1,
		HoldVerdictPollingMs:  1,
	}
}

// fakeEngine is an in-test open-appsec engine server. It serves the two-phase
// registration handshake (§G.1, §G.2) for every accepted connection and pushes
// the handshaked engine-side connection onto connections so tests can drive
// verdicts, close conns, and read request frames.
type fakeEngine struct {
	t           *testing.T
	listener    *memory.Listener
	kaListener  *memory.Listener
	cfg         config.EngineConfig
	connections chan transport.EngineConn
	// keepAlive receives the raw (unhandshaked) connections accepted on the
	// keep-alive socket (§G.3), one per dial. The frames they carry are the
	// app-layer keep-alive payloads.
	keepAlive chan transport.EngineConn
	// reply, if non-nil, is invoked after a request is fully read; its
	// returned verdict is sent to the attachment. A nil reply sends nothing
	// (the request is blocked forever).
	reply func(sid uint32) *protocol.Verdict
	// delayed, if true, sends a REQUEST_DELAYED_VERDICT frame before the
	// verdict, exercising the attachment's delayed-hold path.
	delayed bool
}

// newFakeEngine registers a listener at cfg.RegistrationSocket and the
// keep-alive listener at cfg.KeepAlivePath, then starts accepting.
func newFakeEngine(t *testing.T, cfg config.EngineConfig) *fakeEngine {
	t.Helper()
	l, err := memory.Listen(cfg.RegistrationSocket)
	if err != nil {
		t.Fatalf("fakeEngine: Listen(%q): %v", cfg.RegistrationSocket, err)
	}
	kl, err := memory.Listen(cfg.KeepAlivePath)
	if err != nil {
		t.Fatalf("fakeEngine: Listen(%q): %v", cfg.KeepAlivePath, err)
	}
	f := &fakeEngine{
		t:           t,
		listener:    l,
		kaListener:  kl,
		cfg:         cfg,
		connections: make(chan transport.EngineConn, 16),
		keepAlive:   make(chan transport.EngineConn, 16),
	}
	go f.acceptLoop()
	go f.acceptKeepAliveLoop()
	return f
}

// close shuts both listeners down, failing the test on error.
func (f *fakeEngine) close() {
	f.t.Helper()
	if err := f.listener.Close(); err != nil {
		f.t.Fatalf("fakeEngine: listener Close: %v", err)
	}
	if err := f.kaListener.Close(); err != nil {
		f.t.Fatalf("fakeEngine: keep-alive listener Close: %v", err)
	}
}

// acceptKeepAliveLoop accepts every dial on the keep-alive socket and hands
// the raw connection to the test; there is no handshake on this socket.
func (f *fakeEngine) acceptKeepAliveLoop() {
	for {
		conn, err := f.kaListener.Accept()
		if err != nil {
			return // listener closed
		}
		f.keepAlive <- conn
	}
}

// acceptLoop accepts every dialed connection and serves it concurrently.
func (f *fakeEngine) acceptLoop() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return // listener closed
		}
		go f.handleConn(conn)
	}
}

// handleConn performs the server-side handshake, hands the conn to the test,
// then serves requests according to reply.
func (f *fakeEngine) handleConn(conn transport.EngineConn) {
	if err := f.serverHandshake(conn); err != nil {
		_ = conn.Close()
		return
	}
	f.connections <- conn
	if f.reply == nil {
		return // stay open, never reply
	}
	sid, err := f.readRequest(conn)
	if err != nil {
		return
	}
	v := f.reply(sid)
	if v != nil {
		if f.delayed {
			_ = conn.Send(context.Background(), (protocol.DelayedVerdict{SessionID: sid}).Encode())
		}
		_ = conn.Send(context.Background(), v.Encode())
	}
}

// serverHandshake implements the engine side of §G.1 and §G.2, validating the
// registration frame byte-for-byte against the client's expected layout.
func (f *fakeEngine) serverHandshake(conn transport.EngineConn) error {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	reg, err := conn.Recv(ctx)
	if err != nil {
		return fmt.Errorf("fakeEngine: registration recv: %w", err)
	}
	if want := registrationFrame(f.cfg); !bytes.Equal(reg, want) {
		return fmt.Errorf("fakeEngine: registration frame mismatch:\ngot  %v\nwant %v", reg, want)
	}

	path := []byte(f.cfg.VerdictSignalPath)
	reply := append([]byte{uint8(len(path))}, path...)
	if err := conn.Send(ctx, reply); err != nil {
		return fmt.Errorf("fakeEngine: signal-path reply: %w", err)
	}

	if _, err := conn.Recv(ctx); err != nil {
		return fmt.Errorf("fakeEngine: comm recv: %w", err)
	}
	if err := conn.Send(ctx, []byte{0}); err != nil {
		return fmt.Errorf("fakeEngine: comm ack: %w", err)
	}
	return nil
}

// readRequest consumes frames until REQUEST_END and returns its session id.
func (f *fakeEngine) readRequest(conn transport.EngineConn) (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	for {
		payload, err := conn.Recv(ctx)
		if err != nil {
			return 0, err
		}
		if rs, err := protocol.ParseRequestStart(payload); err == nil {
			return rs.SessionID, nil
		}
		if re, err := protocol.ParseRequestEnd(payload); err == nil {
			return re.SessionID, nil
		}
		// header/body frames carry no session routing here; skip.
	}
}

// recv reads one frame from conn, failing the test on timeout or error.
func recv(t *testing.T, conn transport.EngineConn) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	payload, err := conn.Recv(ctx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	return payload
}
