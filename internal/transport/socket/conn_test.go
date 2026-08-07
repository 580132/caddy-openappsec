package socket

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/yourname/caddy-openappsec/internal/transport"
)

// newPair returns the two ends of a connected TCP pair: the dial side
// (attachment) and the accepted side (engine). The test listener is closed at
// cleanup.
func newPair(t *testing.T) (client, server transport.EngineConn) {
	t.Helper()
	l, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: unexpected error: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	c, err := Dial(l.Addr())
	if err != nil {
		t.Fatalf("Dial: unexpected error: %v", err)
	}
	s, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: unexpected error: %v", err)
	}
	return c, s
}

// requireClose closes c, failing the test on any error.
func requireClose(t *testing.T, c interface{ Close() error }) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Fatalf("Close: unexpected error: %v", err)
	}
}

// requireSend sends payload, failing the test on error.
func requireSend(t *testing.T, c transport.EngineConn, payload []byte) {
	t.Helper()
	if err := c.Send(context.Background(), payload); err != nil {
		t.Fatalf("Send: unexpected error: %v", err)
	}
}

// requireRecv receives one payload, failing the test on error or timeout.
func requireRecv(t *testing.T, c transport.EngineConn) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := c.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: unexpected error: %v", err)
	}
	return b
}

// waitErr waits up to 5s for an operation result, failing the test on
// timeout so a broken unblock never hangs the suite.
func waitErr(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not unblock within 5s")
		return nil
	}
}

func Test_Conn_roundtrips_payloads_between_peers(t *testing.T) {
	// Given a connected pair and payloads of varying size
	client, server := newPair(t)
	payloads := [][]byte{
		{},
		[]byte("hello"),
		bytes.Repeat([]byte{0xab}, 4096),
	}
	for _, p := range payloads {
		// When client sends and server receives
		requireSend(t, client, p)
		got := requireRecv(t, server)
		// Then the payload arrives intact
		if !bytes.Equal(got, p) {
			t.Fatalf("Recv: got %d bytes, want %d", len(got), len(p))
		}
		// And the opposite direction works too
		requireSend(t, server, p)
		if got := requireRecv(t, client); !bytes.Equal(got, p) {
			t.Fatalf("Recv (reverse): got %d bytes, want %d", len(got), len(p))
		}
	}
}

func Test_Conn_Recv_preserves_send_order(t *testing.T) {
	// Given many small payloads sent before any receive
	client, server := newPair(t)
	const n = 64
	for i := 0; i < n; i++ {
		requireSend(t, client, []byte(fmt.Sprintf("msg-%03d", i)))
	}
	// When they are received one by one
	for i := 0; i < n; i++ {
		// Then order and contents are preserved
		if got := requireRecv(t, server); string(got) != fmt.Sprintf("msg-%03d", i) {
			t.Fatalf("Recv: got %q, want %q", got, fmt.Sprintf("msg-%03d", i))
		}
	}
}

func Test_Conn_Send_copies_payload(t *testing.T) {
	// Given a payload sent and then mutated by the caller
	client, server := newPair(t)
	payload := []byte("original")
	requireSend(t, client, payload)
	payload[0] = 'X'
	// When the peer receives it
	got := requireRecv(t, server)
	// Then the delivered copy is unaffected
	if string(got) != "original" {
		t.Fatalf("Recv: got %q, want %q (Send must copy)", got, "original")
	}
}

func Test_Conn_ops_return_ErrClosed_when_conn_closed(t *testing.T) {
	// Given a closed connection
	client, _ := newPair(t)
	requireClose(t, client)
	// When any operation is attempted on it
	// Then it returns ErrClosed
	if _, err := client.Recv(context.Background()); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("Recv: got %v, want ErrClosed", err)
	}
	if err := client.Send(context.Background(), []byte("x")); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("Send: got %v, want ErrClosed", err)
	}
	if err := client.Close(); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("second Close: got %v, want ErrClosed", err)
	}
}

func Test_Conn_Recv_unblocks_with_ErrClosed_when_peer_closes(t *testing.T) {
	// Given a Recv blocked on an idle connection
	client, server := newPair(t)
	recvErr := make(chan error, 1)
	go func() {
		_, err := server.Recv(context.Background())
		recvErr <- err
	}()
	time.Sleep(50 * time.Millisecond)
	// When the peer closes the connection
	requireClose(t, client)
	// Then the blocked Recv unblocks with ErrClosed
	if err := waitErr(t, recvErr); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("Recv: got %v, want ErrClosed", err)
	}
}

func Test_Conn_local_Close_unblocks_blocked_Recv(t *testing.T) {
	// Given a Recv blocked on an idle connection
	client, _ := newPair(t)
	recvErr := make(chan error, 1)
	go func() {
		_, err := client.Recv(context.Background())
		recvErr <- err
	}()
	time.Sleep(50 * time.Millisecond)
	// When the connection is closed locally
	requireClose(t, client)
	// Then the blocked Recv unblocks with ErrClosed
	if err := waitErr(t, recvErr); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("Recv: got %v, want ErrClosed", err)
	}
}

func Test_Conn_Recv_aborts_when_context_cancelled(t *testing.T) {
	// Given a Recv blocked with a cancellable context
	client, server := newPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	recvErr := make(chan error, 1)
	go func() {
		_, err := server.Recv(ctx)
		recvErr <- err
	}()
	time.Sleep(50 * time.Millisecond)
	// When the context is cancelled
	cancel()
	// Then the blocked Recv returns ctx.Err()
	if err := waitErr(t, recvErr); !errors.Is(err, context.Canceled) {
		t.Fatalf("Recv: got %v, want context.Canceled", err)
	}
	// And the connection stays usable afterwards
	requireSend(t, client, []byte("after-cancel"))
	if got := requireRecv(t, server); string(got) != "after-cancel" {
		t.Fatalf("Recv after cancel: got %q, want %q", got, "after-cancel")
	}
}

func Test_Conn_Recv_aborts_when_context_deadline_passes(t *testing.T) {
	// Given a Recv blocked with a short deadline
	_, server := newPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	recvErr := make(chan error, 1)
	go func() {
		_, err := server.Recv(ctx)
		recvErr <- err
	}()
	// When the deadline passes
	// Then the blocked Recv returns ctx.Err()
	if err := waitErr(t, recvErr); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Recv: got %v, want context.DeadlineExceeded", err)
	}
}

func Test_Conn_Send_returns_ctx_error_when_ctx_already_cancelled(t *testing.T) {
	// Given an already-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client, _ := newPair(t)
	// When Send is attempted with it
	// Then it returns ctx.Err()
	if err := client.Send(ctx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send: got %v, want context.Canceled", err)
	}
}

func Test_Conn_Send_aborts_when_context_cancelled_while_blocked(t *testing.T) {
	// Given a payload too large for the socket buffer, so the write blocks
	// with the peer not reading
	client, _ := newPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- client.Send(ctx, bytes.Repeat([]byte{0xaa}, 200<<20))
	}()
	time.Sleep(100 * time.Millisecond)
	// When the context is cancelled
	cancel()
	// Then the blocked Send unblocks with ctx.Err()
	if err := waitErr(t, sendErr); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send: got %v, want context.Canceled", err)
	}
}

func Test_Conn_Recv_prefers_ErrClosed_over_cancelled_ctx(t *testing.T) {
	// Given a connection closed while a cancelled context is in hand
	client, _ := newPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireClose(t, client)
	// When Recv is attempted
	// Then ErrClosed wins over ctx.Err()
	if _, err := client.Recv(ctx); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("Recv: got %v, want ErrClosed", err)
	}
}

func Test_Conn_Close_is_idempotent(t *testing.T) {
	// Given a closed connection
	client, _ := newPair(t)
	requireClose(t, client)
	// When Close is called again
	// Then it returns ErrClosed
	if err := client.Close(); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("second Close: got %v, want ErrClosed", err)
	}
}

func Test_Conn_one_send_delivers_exactly_one_recv(t *testing.T) {
	// Given a connected pair and payloads chosen so their bytes could fake a
	// length prefix if framing ever misaligned
	client, server := newPair(t)
	payloads := [][]byte{
		[]byte{0x00, 0x00, 0x00, 0x00, 0xff}, // a payload that begins like a zero-length prefix
		[]byte{0x12, 0x34, 0x56, 0x78},
		bytes.Repeat([]byte{0xaa}, 1<<20), // 1 MiB: spans many TCP segments
	}
	// When each is sent one at a time, in both directions
	// Then each Recv returns exactly that payload, whole and unmixed
	for _, p := range payloads {
		requireSend(t, client, p)
		if got := requireRecv(t, server); !bytes.Equal(got, p) {
			t.Fatalf("Recv: got %d bytes, want %d", len(got), len(p))
		}
		requireSend(t, server, p)
		if got := requireRecv(t, client); !bytes.Equal(got, p) {
			t.Fatalf("Recv (reverse): got %d bytes, want %d", len(got), len(p))
		}
	}
	// And back-to-back frames stay separate and ordered
	for i := 0; i < 8; i++ {
		requireSend(t, client, []byte(fmt.Sprintf("msg-%03d", i)))
	}
	for i := 0; i < 8; i++ {
		if got := requireRecv(t, server); string(got) != fmt.Sprintf("msg-%03d", i) {
			t.Fatalf("Recv: got %q, want %q", got, fmt.Sprintf("msg-%03d", i))
		}
	}
}

func Test_Conn_handles_concurrent_bidirectional_traffic(t *testing.T) {
	// Given two connected ends
	client, server := newPair(t)
	const sendersPerEnd = 4
	const msgsPerSender = 64
	total := sendersPerEnd * msgsPerSender

	// collect drains end until every expected payload has arrived, then
	// reports what was received.
	collect := func(end transport.EngineConn) func() (map[string]int, error) {
		got := make(map[string]int)
		var mu sync.Mutex
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			for {
				b, err := end.Recv(ctx)
				if err != nil {
					return
				}
				mu.Lock()
				got[string(b)]++
				complete := len(got) == total
				mu.Unlock()
				if complete {
					return
				}
			}
		}()
		return func() (map[string]int, error) {
			wg.Wait()
			mu.Lock()
			defer mu.Unlock()
			if len(got) != total {
				return got, fmt.Errorf("received %d distinct payloads, want %d", len(got), total)
			}
			return got, nil
		}
	}

	// And a receiver draining each end
	clientGot := collect(client) // what the server side sent
	serverGot := collect(server) // what the client side sent

	// When concurrent senders on both ends emit unique payloads
	var senders sync.WaitGroup
	for end, prefix := range map[transport.EngineConn]string{client: "c", server: "s"} {
		for i := 0; i < sendersPerEnd; i++ {
			senders.Add(1)
			go func(end transport.EngineConn, prefix string, i int) {
				defer senders.Done()
				for j := 0; j < msgsPerSender; j++ {
					if err := end.Send(context.Background(), []byte(fmt.Sprintf("%s-%d-%d", prefix, i, j))); err != nil {
						t.Errorf("Send: unexpected error: %v", err)
						return
					}
				}
			}(end, prefix, i)
		}
	}
	senders.Wait()

	gotServer, err := serverGot()
	if err != nil {
		t.Fatalf("server receiver: %v", err)
	}
	gotClient, err := clientGot()
	if err != nil {
		t.Fatalf("client receiver: %v", err)
	}

	// Then every payload arrives intact and exactly once on the peer
	expected := func(prefix string) map[string]int {
		exp := make(map[string]int)
		for i := 0; i < sendersPerEnd; i++ {
			for j := 0; j < msgsPerSender; j++ {
				exp[fmt.Sprintf("%s-%d-%d", prefix, i, j)] = 1
			}
		}
		return exp
	}
	if !maps.Equal(gotServer, expected("c")) {
		t.Fatalf("server received %d distinct payloads, want %d", len(gotServer), len(expected("c")))
	}
	if !maps.Equal(gotClient, expected("s")) {
		t.Fatalf("client received %d distinct payloads, want %d", len(gotClient), len(expected("s")))
	}
}
