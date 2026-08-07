package mock

import (
	"context"
	"testing"
	"time"

	"github.com/580132/caddy-openappsec/internal/protocol"
	"github.com/580132/caddy-openappsec/internal/transport"
	"github.com/580132/caddy-openappsec/internal/transport/memory"
)

// testClient is the attachment side of a connection to the mock engine,
// driving the client endpoints of a memory.Dial pair.
type testClient struct {
	t    *testing.T
	conn transport.EngineConn
}

// dial connects a fresh client to the engine at addr.
func dial(t *testing.T, addr string) *testClient {
	t.Helper()
	conn, err := memory.Dial(addr)
	if err != nil {
		t.Fatalf("Dial(%q): %v", addr, err)
	}
	return &testClient{t: t, conn: conn}
}

// send delivers one frame to the engine.
func (c *testClient) send(b []byte) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.conn.Send(ctx, b); err != nil {
		c.t.Fatalf("Send: %v", err)
	}
}

// recv returns the next reply from the engine, failing on a closed conn.
func (c *testClient) recv() []byte {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, err := c.conn.Recv(ctx)
	if err != nil {
		c.t.Fatalf("Recv: %v", err)
	}
	return b
}

// recvErr returns the error from the next Recv, which must be non-nil.
func (c *testClient) recvErr() error {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.conn.Recv(ctx)
	if err == nil {
		c.t.Fatal("Recv succeeded; want error")
	}
	return err
}

// mustEqualBytes fails unless got matches want byte-for-byte.
func mustEqualBytes(t *testing.T, want, got []byte, what string) {
	t.Helper()
	if string(want) != string(got) {
		t.Fatalf("%s mismatch\nwant: %x\ngot:  %x", what, want, got)
	}
}

// waitFor polls cond until it holds or 5s elapse, failing the test.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// handshake drives the two-phase registration exactly like the app's client
// (internal/app/handshake.go): registration frame, path reply, comm frame, ack.
func (c *testClient) handshake(family string) string {
	c.t.Helper()
	c.send(protocol.Registration{WorkerID: 1, WorkersAmount: 1, FamilyName: family}.Encode())
	reply := c.recv()
	path, err := protocol.ParseRegistrationReply(reply)
	if err != nil {
		c.t.Fatalf("bad registration reply: %v", err)
	}
	c.send(protocol.CommData{UID: family}.Encode())
	mustEqualBytes(c.t, protocol.Ack{Value: 1}.Encode(), c.recv(), "comm ack")
	return path.Path
}

// Test_Engine_RegistrationHandshake verifies the full two-phase handshake on
// one connection, byte-exact against the protocol codecs: registration gets a
// path reply naming the engine address, comm data gets a one-byte ack.
func Test_Engine_RegistrationHandshake(t *testing.T) {
	// Given
	const addr = "mock-handshake"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()
	c := dial(t, addr)

	// When
	c.send(protocol.Registration{AttachmentType: 0, WorkerID: 1, WorkersAmount: 1, FamilyName: "caddy"}.Encode())
	got := c.recv()

	// Then
	want := protocol.RegistrationReply{Path: addr}.Encode()
	mustEqualBytes(t, want, got, "registration reply")

	// When (phase 2, same connection)
	c.send(protocol.CommData{UID: "caddy"}.Encode())
	got = c.recv()

	// Then
	mustEqualBytes(t, protocol.Ack{Value: 1}.Encode(), got, "comm ack")
}

// Test_Engine_KeepAlive_GetsReply verifies a keep-alive frame (§G.3) is
// acknowledged with the one-byte ack.
func Test_Engine_KeepAlive_GetsReply(t *testing.T) {
	// Given
	const addr = "mock-keepalive"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()
	c := dial(t, addr)

	// When
	c.send(protocol.KeepAlive{WorkerID: 1, FamilyName: "caddy"}.Encode())
	got := c.recv()

	// Then
	mustEqualBytes(t, protocol.Ack{Value: 1}.Encode(), got, "keep-alive ack")
}
