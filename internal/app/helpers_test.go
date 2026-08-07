package app

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/580132/caddy-openappsec/internal/config"
	"github.com/580132/caddy-openappsec/internal/protocol"
	"github.com/580132/caddy-openappsec/internal/transport"
	"github.com/580132/caddy-openappsec/internal/transport/memory"
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
// registration handshake over two sockets exactly like the C reference:
// a phase-1 registration listener at cfg.RegistrationSocket (§G.1) replies
// with the verdict signal path and is one-shot, and a phase-2 listener at
// cfg.VerdictSignalPath (§G.2) completes the comm handshake and carries the
// request/verdict traffic. The handshaked phase-2 connection is pushed onto
// connections so tests can drive verdicts, close conns, and read request
// frames.
type fakeEngine struct {
	t           *testing.T
	listener    *memory.Listener // cfg.RegistrationSocket — phase-1 registration
	verdict     *memory.Listener // cfg.VerdictSignalPath — phase-2 comm + requests
	kaListener  *memory.Listener // cfg.KeepAlivePath — §G.3 keep-alive
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
	// responseReply, if non-nil, is invoked after a response is fully read;
	// its returned verdict is sent to the attachment. A nil reply sends
	// nothing (the response is blocked forever, exercising the fail-open
	// budget).
	responseReply func(sid uint32) *protocol.Verdict
	// delayed, if true, sends a REQUEST_DELAYED_VERDICT frame before the
	// verdict, exercising the attachment's delayed-hold path.
	delayed bool
}

// newFakeEngine registers the phase-1 listener at cfg.RegistrationSocket, the
// phase-2 listener at cfg.VerdictSignalPath, and the keep-alive listener at
// cfg.KeepAlivePath, then starts accepting on all three.
func newFakeEngine(t *testing.T, cfg config.EngineConfig) *fakeEngine {
	t.Helper()
	l, err := memory.Listen(cfg.RegistrationSocket)
	if err != nil {
		t.Fatalf("fakeEngine: Listen(%q): %v", cfg.RegistrationSocket, err)
	}
	vl, err := memory.Listen(cfg.VerdictSignalPath)
	if err != nil {
		t.Fatalf("fakeEngine: Listen(%q): %v", cfg.VerdictSignalPath, err)
	}
	kl, err := memory.Listen(cfg.KeepAlivePath)
	if err != nil {
		t.Fatalf("fakeEngine: Listen(%q): %v", cfg.KeepAlivePath, err)
	}
	f := &fakeEngine{
		t:           t,
		listener:    l,
		verdict:     vl,
		kaListener:  kl,
		cfg:         cfg,
		connections: make(chan transport.EngineConn, 16),
		keepAlive:   make(chan transport.EngineConn, 16),
	}
	go f.acceptRegistrationLoop()
	go f.acceptVerdictLoop()
	go f.acceptKeepAliveLoop()
	return f
}

// close shuts all three listeners down, failing the test on error.
func (f *fakeEngine) close() {
	f.t.Helper()
	if err := f.listener.Close(); err != nil {
		f.t.Fatalf("fakeEngine: listener Close: %v", err)
	}
	if err := f.verdict.Close(); err != nil {
		f.t.Fatalf("fakeEngine: verdict listener Close: %v", err)
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

// acceptRegistrationLoop accepts every dial on the phase-1 registration
// socket and serves it concurrently. The registration socket is one-shot
// (§G.1): after the path reply the connection is closed by the client.
func (f *fakeEngine) acceptRegistrationLoop() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return // listener closed
		}
		go f.serveRegistration(conn)
	}
}

// acceptVerdictLoop accepts every dial on the phase-2 verdict signal socket
// and serves it concurrently.
func (f *fakeEngine) acceptVerdictLoop() {
	for {
		conn, err := f.verdict.Accept()
		if err != nil {
			return // listener closed
		}
		go f.serveVerdict(conn)
	}
}

// serveRegistration implements the engine side of §G.1 on the one-shot
// registration connection: it validates the registration frame byte-for-byte
// against the client's expected layout and replies with the verdict signal
// path. The connection is then left for the client to close (§G.1); no
// further frames arrive on it.
func (f *fakeEngine) serveRegistration(conn transport.EngineConn) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	reg, err := conn.Recv(ctx)
	if err != nil {
		_ = conn.Close()
		return
	}
	if want := registrationFrame(f.cfg); !bytes.Equal(reg, want) {
		_ = conn.Close()
		return
	}

	path := []byte(f.cfg.VerdictSignalPath)
	reply := append([]byte{uint8(len(path))}, path...)
	if err := conn.Send(ctx, reply); err != nil {
		_ = conn.Close()
	}
}

// serveVerdict implements the engine side of §G.2 on the live phase-2
// connection: it validates the comm frame, sends the ack, hands the conn to
// the test, then serves requests according to reply.
func (f *fakeEngine) serveVerdict(conn transport.EngineConn) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	comm, err := conn.Recv(ctx)
	if err != nil {
		_ = conn.Close()
		return
	}
	if want := commFrame(f.cfg); !bytes.Equal(comm, want) {
		_ = conn.Close()
		return
	}
	if err := conn.Send(ctx, []byte{0}); err != nil {
		_ = conn.Close()
		return
	}

	f.connections <- conn
	if f.reply != nil {
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
	if f.responseReply != nil {
		sid, err := f.readResponse(conn)
		if err != nil {
			return
		}
		v := f.responseReply(sid)
		if v != nil {
			_ = conn.Send(context.Background(), v.Encode())
		}
	}
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

// readResponse consumes frames until the RESPONSE_BODY chunk and returns its
// session id.
func (f *fakeEngine) readResponse(conn transport.EngineConn) (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	for {
		payload, err := conn.Recv(ctx)
		if err != nil {
			return 0, err
		}
		if bc, err := protocol.ParseBodyChunk(payload); err == nil && bc.DataType == protocol.DataTypeResponseBody {
			return bc.SessionID, nil
		}
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
