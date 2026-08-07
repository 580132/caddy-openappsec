package app

import (
	"context"
	"testing"

	"github.com/580132/caddy-openappsec/internal/config"
	"github.com/580132/caddy-openappsec/internal/mock"
	"github.com/580132/caddy-openappsec/internal/protocol"
	"github.com/580132/caddy-openappsec/internal/transport/socket"
)

// Test_NewDialer_dispatches_memory_transport verifies Transport=memory selects
// the in-process memory dialer.
func Test_NewDialer_dispatches_memory_transport(t *testing.T) {
	d := NewDialer(config.EngineConfig{Transport: config.TransportMemory})
	if _, ok := d.(*memoryDialer); !ok {
		t.Fatalf("NewDialer(memory) = %T, want *memoryDialer", d)
	}
}

// Test_NewDialer_dispatches_socket_transport verifies Transport=socket selects
// the cross-process TCP socket dialer.
func Test_NewDialer_dispatches_socket_transport(t *testing.T) {
	d := NewDialer(config.EngineConfig{Transport: config.TransportSocket})
	if _, ok := d.(*socketDialer); !ok {
		t.Fatalf("NewDialer(socket) = %T, want *socketDialer", d)
	}
}

// Test_socketDialer_roundtrips_request_and_verdict verifies the socket dialer
// completes the two-phase registration handshake over a real TCP connection to
// the mock engine (socket.Listen + mock.NewWithListener) and that a full
// request/verdict round trip completes over the handshaked connection.
func Test_socketDialer_roundtrips_request_and_verdict(t *testing.T) {
	// Given a mock engine listening over the TCP socket transport
	ln, err := socket.Listen("127.0.0.1:0")
	requireNoError(t, err)
	e, err := mock.NewWithListener(ln)
	requireNoError(t, err)
	defer e.Close()

	cfg := testConfig(t, "socket-verdict")
	cfg.Transport = config.TransportSocket
	cfg.RegistrationSocket = ln.Addr()
	cfg.KeepAlivePath = ln.Addr()

	// When the socket dialer dials and completes the two-phase handshake
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	conn, err := NewDialer(cfg).Dial(ctx)
	requireNoError(t, err)
	defer conn.Close()

	// Then a request/verdict round trip completes over the connection
	const sid = uint32(7)
	requireNoError(t, conn.Send(ctx, protocol.RequestStart{
		SessionID:    sid,
		HTTPProtocol: "HTTP/1.1",
		Method:       "GET",
		Host:         "example.com",
	}.Encode()))

	var verdict *protocol.Verdict
	for {
		payload, err := conn.Recv(ctx)
		requireNoError(t, err)
		if v, err := protocol.ParseVerdict(payload); err == nil {
			verdict = v
			break
		}
	}
	if verdict.SessionID != sid {
		t.Fatalf("verdict session id = %d, want %d", verdict.SessionID, sid)
	}
	if verdict.Kind != protocol.VerdictAccept {
		t.Fatalf("verdict kind = %v, want ACCEPT", verdict.Kind)
	}
}

// Test_socketDialer_returns_error_when_engine_unreachable verifies Dial fails
// when nothing is listening at the TCP address, mirroring the memory dialer's
// unreachable-engine behavior.
func Test_socketDialer_returns_error_when_engine_unreachable(t *testing.T) {
	// Given a config whose address has no listener (bound then closed)
	ln, err := socket.Listen("127.0.0.1:0")
	requireNoError(t, err)
	addr := ln.Addr()
	requireNoError(t, ln.Close())

	cfg := testConfig(t, "socket-nowhere")
	cfg.Transport = config.TransportSocket
	cfg.RegistrationSocket = addr

	// When
	_, err = (&socketDialer{cfg: cfg}).Dial(context.Background())

	// Then
	requireError(t, err, "socket: dial")
}
