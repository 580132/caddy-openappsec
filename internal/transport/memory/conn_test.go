package memory

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

// requireRecv receives one payload, failing the test on error.
func requireRecv(t *testing.T, c transport.EngineConn) []byte {
	t.Helper()
	b, err := c.Recv(context.Background())
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
	client, server := newPair()
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
	// Given many payloads sent before any receive
	client, server := newPair()
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
	client, server := newPair()
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
	client, _ := newPair()
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

func Test_Conn_closing_one_end_closes_the_peer(t *testing.T) {
	// Given a connected pair
	client, server := newPair()
	// When only one end is closed
	requireClose(t, client)
	// Then the peer reports ErrClosed on every operation
	if _, err := server.Recv(context.Background()); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("peer Recv: got %v, want ErrClosed", err)
	}
	if err := server.Send(context.Background(), []byte("x")); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("peer Send: got %v, want ErrClosed", err)
	}
}

func Test_Conn_Recv_unblocks_with_ErrClosed_when_peer_closes(t *testing.T) {
	// Given a Recv blocked on an idle connection
	client, server := newPair()
	recvErr := make(chan error, 1)
	go func() {
		_, err := server.Recv(context.Background())
		recvErr <- err
	}()
	// When the peer closes the connection
	requireClose(t, client)
	// Then the blocked Recv unblocks with ErrClosed
	if err := waitErr(t, recvErr); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("Recv: got %v, want ErrClosed", err)
	}
}

func Test_Conn_Recv_aborts_when_context_cancelled(t *testing.T) {
	// Given a Recv blocked with a cancellable context
	client, server := newPair()
	ctx, cancel := context.WithCancel(context.Background())
	recvErr := make(chan error, 1)
	go func() {
		_, err := server.Recv(ctx)
		recvErr <- err
	}()
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
	_, server := newPair()
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
	client, _ := newPair()
	// When Send is attempted with it
	// Then it returns ctx.Err()
	if err := client.Send(ctx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send: got %v, want context.Canceled", err)
	}
}

func Test_Conn_Recv_prefers_ErrClosed_over_cancelled_ctx(t *testing.T) {
	// Given a connection closed while a cancelled context is in hand
	client, server := newPair()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireClose(t, client)
	// When Recv is attempted
	// Then ErrClosed wins over ctx.Err()
	if _, err := server.Recv(ctx); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("Recv: got %v, want ErrClosed", err)
	}
}

func Test_Conn_handles_concurrent_bidirectional_traffic(t *testing.T) {
	// Given two connected ends
	client, server := newPair()
	const sendersPerEnd = 4
	const msgsPerSender = 64

	// And a receiver draining each end until told to stop
	newReceiver := func(end *Conn) func() map[string]int {
		got := make(map[string]int)
		var mu sync.Mutex
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				b, err := end.Recv(ctx)
				if err != nil {
					return // only reached after cancel
				}
				mu.Lock()
				got[string(b)]++
				mu.Unlock()
			}
		}()
		return func() map[string]int {
			cancel()
			wg.Wait()
			return got
		}
	}
	clientGot := newReceiver(client) // what server sent
	serverGot := newReceiver(server) // what client sent

	// When concurrent senders on both ends emit unique payloads
	var senders sync.WaitGroup
	for end, prefix := range map[*Conn]string{client: "c", server: "s"} {
		for i := 0; i < sendersPerEnd; i++ {
			senders.Add(1)
			go func(end *Conn, prefix string, i int) {
				defer senders.Done()
				for j := 0; j < msgsPerSender; j++ {
					payload := []byte(fmt.Sprintf("%s-%d-%d", prefix, i, j))
					if err := end.Send(context.Background(), payload); err != nil {
						t.Errorf("Send: unexpected error: %v", err)
						return
					}
				}
			}(end, prefix, i)
		}
	}
	senders.Wait()

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
	if got, want := serverGot(), expected("c"); !maps.Equal(got, want) {
		t.Fatalf("server received %d distinct payloads, want %d", len(got), len(want))
	}
	if got, want := clientGot(), expected("s"); !maps.Equal(got, want) {
		t.Fatalf("client received %d distinct payloads, want %d", len(got), len(want))
	}
}
