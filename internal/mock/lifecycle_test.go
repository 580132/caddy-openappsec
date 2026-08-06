package mock

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yourname/caddy-openappsec/internal/protocol"
	"github.com/yourname/caddy-openappsec/internal/transport"
	"github.com/yourname/caddy-openappsec/internal/transport/memory"
)

// Test_Engine_Handshake_Then_Requests_SameConn verifies the app's real flow:
// registration, comm, then request frames on the one connection, with
// REQUEST_END receiving no reply (next Recv times out).
func Test_Engine_Handshake_Then_Requests_SameConn(t *testing.T) {
	// Given
	const addr = "mock-sameconn"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()
	eng.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})
	c := dial(t, addr)

	// When
	path := c.handshake("caddy")

	// Then
	if path != addr {
		t.Fatalf("path = %q, want engine address %q", path, addr)
	}

	// When (request traffic on the same connection)
	const sid = uint32(9)
	c.send(protocol.RequestStart{SessionID: sid, Method: "GET", UnparsedURI: "/"}.Encode())
	mustEqualBytes(t, (&protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: sid}).Encode(), c.recv(), "verdict")
	c.send(protocol.RequestEnd{DataType: protocol.DataTypeRequestEnd, SessionID: sid}.Encode())
	c.send(protocol.BodyChunk{DataType: protocol.DataTypeRequestBody, SessionID: sid, IsLastChunk: true, Data: []byte("hello")}.Encode())

	// Then (no reply for non-start frames; Recv times out)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := c.conn.Recv(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Recv after REQUEST_END = %v, want deadline", err)
	}
}

// Test_Engine_SetEngineDown_ClosesConns verifies engine-down closes live
// connections with transport.ErrClosed, stops accepting (Dial fails), and a
// fresh engine can rebind the address.
func Test_Engine_SetEngineDown_ClosesConns(t *testing.T) {
	// Given
	const addr = "mock-down"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	c := dial(t, addr)
	c.handshake("caddy")

	// When
	if err := eng.SetEngineDown(); err != nil {
		t.Fatalf("SetEngineDown: %v", err)
	}

	// Then (live conn closed)
	if err := c.recvErr(); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("Recv = %v, want %v", err, transport.ErrClosed)
	}

	// Then (address unregistered: Dial fails)
	if _, err := memory.Dial(addr); err == nil {
		t.Fatal("Dial after down succeeded, want failure")
	}

	// Then (idempotent: second call reports ErrClosed)
	if err := eng.SetEngineDown(); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("second SetEngineDown = %v, want %v", err, transport.ErrClosed)
	}

	// When (fresh engine rebinds)
	eng2, err := New(addr)
	if err != nil {
		t.Fatalf("New after down: %v", err)
	}
	defer eng2.Close()
	c2 := dial(t, addr)
	c2.handshake("caddy")
}

// Test_Engine_Counters_Tally verifies frame records, the REQUEST_START
// counter and the total frame counter across multiple connections.
func Test_Engine_Counters_Tally(t *testing.T) {
	// Given
	const addr = "mock-counters"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()
	eng.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})

	c1 := dial(t, addr)
	c1.handshake("caddy")
	c1.send(protocol.RequestStart{SessionID: 3, Method: "GET", UnparsedURI: "/a"}.Encode())
	_ = c1.recv()
	c1.send(protocol.RequestEnd{DataType: protocol.DataTypeRequestEnd, SessionID: 3}.Encode())

	c2 := dial(t, addr)
	c2.send(protocol.KeepAlive{WorkerID: 1, FamilyName: "caddy"}.Encode())
	_ = c2.recv()

	// When
	waitFor(t, "5 frames", func() bool { return eng.FrameCount() == 5 })
	got := eng.ReceivedFrames()

	// Then. Frames on one connection arrive in order, but the two
	// connections are served concurrently, so only the multiset is stable.
	want := map[string]int{
		"REGISTRATION type=0 worker=1 workers=1 family=\"caddy\"":     1,
		"COMM_DATA uid=\"caddy\" user=0 group=0":                      1,
		"REQUEST_START session=3 method=\"GET\" uri=\"/a\" host=\"\"": 1,
		"REQUEST_END session=3":                                       1,
		"KEEP_ALIVE worker=1 family=\"caddy\"":                        1,
	}
	if len(got) != 5 {
		t.Fatalf("got %d frames %v, want 5", len(got), got)
	}
	seen := map[string]int{}
	for _, f := range got {
		seen[f.Meaning]++
	}
	for meaning, n := range want {
		if seen[meaning] != n {
			t.Errorf("meaning %q seen %d times, want %d (got %v)", meaning, seen[meaning], n, got)
		}
	}
	if eng.Requests() != 1 {
		t.Errorf("Requests() = %d, want 1", eng.Requests())
	}
	if eng.FrameCount() != 5 {
		t.Errorf("FrameCount() = %d, want 5", eng.FrameCount())
	}
}

// Test_Engine_ManySequentialConns verifies the accept loop serves many
// sequential connections, each with a full handshake and a verdict.
func Test_Engine_ManySequentialConns(t *testing.T) {
	// Given
	const addr = "mock-sequential"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()

	// When/Then
	for i := 0; i < 10; i++ {
		eng.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})
		c := dial(t, addr)
		c.handshake("caddy")
		sid := uint32(3 + 2*i)
		c.send(protocol.RequestStart{SessionID: sid, Method: "GET"}.Encode())
		mustEqualBytes(t, (&protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: sid}).Encode(), c.recv(), "sequential verdict")
		_ = c.conn.Close()
	}
}

// Test_Engine_Flaky_ClosesConn_AfterNRequests verifies SetFlakyAfter: the
// nth REQUEST_START is consumed without a reply and the connection is closed,
// while the listener keeps accepting new connections.
func Test_Engine_Flaky_ClosesConn_AfterNRequests(t *testing.T) {
	// Given
	const addr = "mock-flaky"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()
	eng.SetFlakyAfter(2)
	eng.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})
	c := dial(t, addr)
	c.handshake("caddy")

	// When (request 1 is served normally)
	c.send(protocol.RequestStart{SessionID: 3, Method: "GET"}.Encode())
	mustEqualBytes(t, (&protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: 3}).Encode(), c.recv(), "first verdict")

	// When (request 2 closes the conn without a reply)
	c.send(protocol.RequestStart{SessionID: 5, Method: "GET"}.Encode())

	// Then
	if err := c.recvErr(); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("Recv = %v, want %v", err, transport.ErrClosed)
	}

	// Then (listener still accepts; a fresh conn starts a new budget)
	c2 := dial(t, addr)
	c2.handshake("caddy")
	c2.send(protocol.RequestStart{SessionID: 7, Method: "GET"}.Encode())
	mustEqualBytes(t, (&protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: 7}).Encode(), c2.recv(), "fresh conn verdict")
}

// Test_Engine_Down_NoVerdictReplies verifies SetVerdictsEnabled(false): the
// handshake is still answered but request frames never receive verdicts.
func Test_Engine_Down_NoVerdictReplies(t *testing.T) {
	// Given
	const addr = "mock-respondoff"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()
	eng.SetVerdictsEnabled(false)
	c := dial(t, addr)

	// When (handshake still completes)
	c.handshake("caddy")
	c.send(protocol.RequestStart{SessionID: 3, Method: "GET"}.Encode())

	// Then (no verdict: Recv times out)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := c.conn.Recv(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Recv = %v, want deadline", err)
	}
	if eng.Requests() != 1 {
		t.Errorf("Requests() = %d, want 1", eng.Requests())
	}
}
