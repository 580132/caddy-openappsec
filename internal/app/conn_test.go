package app

import (
	"context"
	"testing"
	"time"

	"github.com/580132/caddy-openappsec/internal/protocol"
)

// Test_backoffDelay_grows_exponentially_bounded verifies the reconnect backoff
// sequence doubles from the minimum and is capped at the maximum.
func Test_backoffDelay_grows_exponentially_bounded(t *testing.T) {
	// Given
	min := 10 * time.Millisecond
	max := 100 * time.Millisecond

	// When/Then
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 10 * time.Millisecond},
		{1, 20 * time.Millisecond},
		{2, 40 * time.Millisecond},
		{3, 80 * time.Millisecond},
		{4, 100 * time.Millisecond}, // capped
		{10, 100 * time.Millisecond},
	}
	for _, c := range cases {
		if got := backoffDelay(min, max, c.attempt); got != c.want {
			t.Errorf("backoffDelay(%v, %v, %d) = %v, want %v", min, max, c.attempt, got, c.want)
		}
	}
}

// Test_Conn_reconnects_after_ErrClosed verifies a send on a dead connection
// redials with the same dialer and delivers the payload on the fresh
// connection, preserving the connection's identity.
func Test_Conn_reconnects_after_ErrClosed(t *testing.T) {
	// Given a fake engine and a pool-connected conn
	cfg := testConfig(t, "reconnect.sock")
	f := newFakeEngine(t, cfg)
	defer f.close()
	p := NewPool(cfg, &memoryDialer{cfg: cfg})
	c, err := p.Acquire(context.Background(), cfg.RegistrationSocket)
	requireNoError(t, err)
	defer func() { p.Release(cfg.RegistrationSocket) }()

	// The engine-side end of the first connection
	first := <-f.connections
	// The engine dies: it closes the first connection
	_ = first.Close()

	// When a frame is sent
	requireNoError(t, c.send(context.Background(), []byte("ping")))

	// Then the connection was re-established and the frame arrived
	second := <-f.connections // engine-side end of the fresh connection
	if payload := recv(t, second); string(payload) != "ping" {
		t.Fatalf("recv on reconnected conn = %q, want %q", payload, "ping")
	}
}

// Test_Conn_reconnect_keeps_session_allocator verifies the SessionAllocator
// survives a reconnect without resetting: session ids keep advancing instead
// of restarting at the first id. The first session is left in flight (not
// reclaimed) when the engine dies, mirroring a request interrupted mid-flight;
// a recreated allocator would hand out 3 again, a surviving one continues.
func Test_Conn_reconnect_keeps_session_allocator(t *testing.T) {
	// Given
	cfg := testConfig(t, "session.sock")
	f := newFakeEngine(t, cfg)
	f.reply = func(sid uint32) *protocol.Verdict {
		return &protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: sid}
	}
	defer f.close()
	p := NewPool(cfg, &memoryDialer{cfg: cfg})
	c, err := p.Acquire(context.Background(), cfg.RegistrationSocket)
	requireNoError(t, err)
	defer func() { p.Release(cfg.RegistrationSocket) }()

	// A first request allocates the first session id (3)
	sid1, err := c.SendRequest(context.Background(), RequestData{
		Start: protocol.RequestStart{HTTPProtocol: "HTTP/1.1"},
	})
	requireNoError(t, err)
	if sid1 != 3 {
		t.Fatalf("first session id = %d, want 3", sid1)
	}

	// The engine dies and the connection is redialed
	_ = (<-f.connections).Close()
	requireNoError(t, c.send(context.Background(), []byte("x")))
	<-f.connections // fresh conn

	// A second request must continue the sequence, not restart at 3
	sid2, err := c.SendRequest(context.Background(), RequestData{
		Start: protocol.RequestStart{HTTPProtocol: "HTTP/1.1"},
	})
	requireNoError(t, err)
	if sid2 != sid1+2 {
		t.Fatalf("session id after reconnect = %d, want %d (allocator was reset)", sid2, sid1+2)
	}
	v, err := c.AwaitVerdict(context.Background(), sid2)
	requireNoError(t, err)
	if v.SessionID != sid2 {
		t.Fatalf("verdict session id = %d, want %d", v.SessionID, sid2)
	}
	c.EndRequest(sid2)
}

// Test_Conn_keepAlive_sends_frames_at_interval verifies the keep-alive
// goroutine emits protocol.KeepAlive frames over the dedicated keep-alive
// socket (§G.3) with the configured worker id and family name.
func Test_Conn_keepAlive_sends_frames_at_interval(t *testing.T) {
	// Given a short keep-alive interval
	cfg := testConfig(t, "keepalive.sock")
	cfg.KeepAliveIntervalMs = 20
	cfg.WorkerID = 1
	f := newFakeEngine(t, cfg)
	defer f.close()
	p := NewPool(cfg, &memoryDialer{cfg: cfg})
	_, err := p.Acquire(context.Background(), cfg.RegistrationSocket)
	requireNoError(t, err)
	defer func() { p.Release(cfg.RegistrationSocket) }()
	e := <-f.keepAlive

	// When the engine reads the next frame on the keep-alive socket
	payload := recv(t, e)

	// Then it is a keep-alive with the configured identity
	ka, err := protocol.ParseKeepAlive(payload)
	requireNoError(t, err)
	if ka.WorkerID != 1 {
		t.Errorf("keep-alive worker id = %d, want 1", ka.WorkerID)
	}
	if ka.FamilyName != cfg.FamilyName {
		t.Errorf("keep-alive family name = %q, want %q", ka.FamilyName, cfg.FamilyName)
	}
}

// Test_Conn_keepAlive_failure_triggers_reconnect verifies a keep-alive send
// failure re-establishes the keep-alive socket.
func Test_Conn_keepAlive_failure_triggers_reconnect(t *testing.T) {
	// Given a conn whose keep-alive socket is closed
	cfg := testConfig(t, "ka-reconnect.sock")
	cfg.KeepAliveIntervalMs = 20
	f := newFakeEngine(t, cfg)
	defer f.close()
	p := NewPool(cfg, &memoryDialer{cfg: cfg})
	_, err := p.Acquire(context.Background(), cfg.RegistrationSocket)
	requireNoError(t, err)
	defer func() { p.Release(cfg.RegistrationSocket) }()
	_ = (<-f.keepAlive).Close()

	// When the keep-alive goroutine fires and fails
	// Then it redials the keep-alive socket
	select {
	case <-f.keepAlive:
		// reconnected
	case <-time.After(2 * time.Second):
		t.Fatal("keep-alive failure did not trigger a redial")
	}
}

// Test_Conn_SendRequest_AwaitVerdict_roundtrips verifies a request sent to
// the engine returns its verdict and the session id is reclaimed afterwards.
func Test_Conn_SendRequest_AwaitVerdict_roundtrips(t *testing.T) {
	// Given a fake engine that replies DROP
	cfg := testConfig(t, "verdict.sock")
	f := newFakeEngine(t, cfg)
	f.reply = func(sid uint32) *protocol.Verdict {
		return &protocol.Verdict{
			Kind:      protocol.VerdictDrop,
			SessionID: sid,
			WebResponse: &protocol.WebResponse{
				Type:       protocol.WebResponseCustom,
				StatusCode: 403,
				Title:      "Blocked",
				Body:       "denied",
			},
		}
	}
	defer f.close()
	p := NewPool(cfg, &memoryDialer{cfg: cfg})
	c, err := p.Acquire(context.Background(), cfg.RegistrationSocket)
	requireNoError(t, err)
	defer func() { p.Release(cfg.RegistrationSocket) }()

	// When a request is sent and awaited
	sid, err := c.SendRequest(context.Background(), RequestData{
		Start: protocol.RequestStart{HTTPProtocol: "HTTP/1.1", Method: "GET", Host: "example.com"},
	})
	requireNoError(t, err)
	v, err := c.AwaitVerdict(context.Background(), sid)
	requireNoError(t, err)

	// Then the DROP verdict is returned with the same session id
	if v.Kind != protocol.VerdictDrop {
		t.Fatalf("verdict kind = %v, want DROP", v.Kind)
	}
	if v.SessionID != sid {
		t.Fatalf("verdict session id = %d, want %d", v.SessionID, sid)
	}
	c.EndRequest(sid)
}

// Test_Conn_SendRequest_sends_full_transaction verifies SendRequest streams the
// complete request transaction to the engine: REQUEST_START, REQUEST_HEADER
// bulk, REQUEST_BODY chunk, then REQUEST_END — the sequence the real engine
// needs to produce its terminal verdict (waap end_request).
func Test_Conn_SendRequest_sends_full_transaction(t *testing.T) {
	// Given a fake engine that records every received frame
	cfg := testConfig(t, "txn.sock")
	var frames [][]byte
	f := newFakeEngine(t, cfg)
	defer f.close()

	// When a request with headers and body is sent
	p := NewPool(cfg, &memoryDialer{cfg: cfg})
	c, err := p.Acquire(context.Background(), cfg.RegistrationSocket)
	requireNoError(t, err)
	defer func() { p.Release(cfg.RegistrationSocket) }()
	sid, err := c.SendRequest(context.Background(), RequestData{
		Start: protocol.RequestStart{HTTPProtocol: "HTTP/1.1", Method: "POST", Host: "example.com"},
		Headers: []protocol.Header{
			{Key: "Host", Value: "example.com"},
			{Key: "Content-Type", Value: "application/x-www-form-urlencoded"},
		},
		Body: []byte("a=1' OR '1'='1"),
	})
	requireNoError(t, err)

	// Then the fake engine's request handler consumed the transaction; the
	// frames are readable back off the connection the handler pushed.
	select {
	case conn := <-f.connections:
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()
		for i := 0; i < 4; i++ {
			payload, err := conn.Recv(ctx)
			requireNoError(t, err)
			frames = append(frames, payload)
		}
		_ = conn.Close()
	case <-time.After(testTimeout):
		t.Fatal("fake engine did not complete the handshake")
	}

	// Then the transaction has the expected shape: START, HEADER, BODY, END.
	if len(frames) != 4 {
		t.Fatalf("transaction frames = %d, want 4 (START, HEADER, BODY, END)", len(frames))
	}
	if rs, err := protocol.ParseRequestStart(frames[0]); err != nil {
		t.Fatalf("frame 0 = %x, want REQUEST_START", frames[0])
	} else if rs.SessionID != sid {
		t.Fatalf("frame 0 session = %d, want %d", rs.SessionID, sid)
	}
	if hb, err := protocol.ParseHeaderBulk(frames[1]); err != nil {
		t.Fatalf("frame 1 = %x, want REQUEST_HEADER bulk: %v", frames[1], err)
	} else if hb.SessionID != sid || len(hb.Headers) != 2 {
		t.Fatalf("frame 1 headers = %d, want 2; sid %d", len(hb.Headers), hb.SessionID)
	}
	if bc, err := protocol.ParseBodyChunk(frames[2]); err != nil {
		t.Fatalf("frame 2 = %x, want REQUEST_BODY chunk: %v", frames[2], err)
	} else if bc.SessionID != sid || string(bc.Data) != "a=1' OR '1'='1" {
		t.Fatalf("frame 2 body = %q, want the request body", bc.Data)
	}
	if re, err := protocol.ParseRequestEnd(frames[3]); err != nil {
		t.Fatalf("frame 3 = %x, want REQUEST_END: %v", frames[3], err)
	} else if re.SessionID != sid {
		t.Fatalf("frame 3 session = %d, want %d", re.SessionID, sid)
	}
	c.EndRequest(sid)
}
