package memory

import (
	"errors"
	"fmt"
	"testing"

	"github.com/yourname/caddy-openappsec/internal/transport"
)

// requireListen registers a listener at addr, failing the test on error.
func requireListen(t *testing.T, addr string) *Listener {
	t.Helper()
	l, err := Listen(addr)
	if err != nil {
		t.Fatalf("Listen(%q): unexpected error: %v", addr, err)
	}
	return l
}

func Test_Listen_and_Dial_return_connected_pair(t *testing.T) {
	// Given a registered listener
	l := requireListen(t, "engine.sock")
	// When a connection is dialed and accepted
	client, err := Dial("engine.sock")
	if err != nil {
		t.Fatalf("Dial: unexpected error: %v", err)
	}
	server, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: unexpected error: %v", err)
	}
	// Then the pair round-trips payloads in both directions
	requireSend(t, client, []byte("ping"))
	if got := requireRecv(t, server); string(got) != "ping" {
		t.Fatalf("Recv: got %q, want %q", got, "ping")
	}
	requireSend(t, server, []byte("pong"))
	if got := requireRecv(t, client); string(got) != "pong" {
		t.Fatalf("Recv: got %q, want %q", got, "pong")
	}
}

func Test_Listen_rejects_empty_and_duplicate_addresses(t *testing.T) {
	// Given a registered listener
	requireListen(t, "dup.sock")
	// When Listen is called with an empty, blank, or duplicate address
	// Then it fails
	for _, addr := range []string{"", "   ", "dup.sock"} {
		if l, err := Listen(addr); err == nil {
			t.Fatalf("Listen(%q): expected error, got %v", addr, l)
		}
	}
}

func Test_Dial_errors_when_address_not_listening(t *testing.T) {
	// When Dial targets an address with no listener
	// Then it fails
	if _, err := Dial("nowhere.sock"); err == nil {
		t.Fatal("Dial: expected error for unknown address")
	}
}

func Test_Listener_Close_unregisters_address(t *testing.T) {
	// Given a listener that is closed
	l := requireListen(t, "reuse.sock")
	requireClose(t, l)
	// When the same address is listened on again
	// Then it succeeds
	requireListen(t, "reuse.sock")
}

func Test_Listener_Accept_unblocks_with_ErrClosed_when_closed(t *testing.T) {
	// Given an Accept blocked on an idle listener
	l := requireListen(t, "idle.sock")
	acceptErr := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		acceptErr <- err
	}()
	// When the listener is closed
	requireClose(t, l)
	// Then the blocked Accept unblocks with ErrClosed
	if err := waitErr(t, acceptErr); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("Accept: got %v, want ErrClosed", err)
	}
}

func Test_Listener_Close_is_idempotent_and_blocks_accept(t *testing.T) {
	// Given a closed listener
	l := requireListen(t, "closed.sock")
	requireClose(t, l)
	// When Close is called again or a connection is accepted
	// Then Close returns ErrClosed and Accept returns ErrClosed
	if err := l.Close(); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("second Close: got %v, want ErrClosed", err)
	}
	if _, err := l.Accept(); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("Accept: got %v, want ErrClosed", err)
	}
}

func Test_Listener_Dial_returns_error_when_closed(t *testing.T) {
	// Given a closed listener
	l := requireListen(t, "gone.sock")
	requireClose(t, l)
	// When Dial targets its address
	// Then it fails (the address is no longer registered)
	if _, err := Dial("gone.sock"); err == nil {
		t.Fatal("Dial: expected error for closed listener")
	}
}

func Test_Listener_accepts_dialed_connections_in_order(t *testing.T) {
	// Given three connections dialed before any Accept
	l := requireListen(t, "order.sock")
	dialed := make([]transport.EngineConn, 3)
	for i := range dialed {
		c, err := Dial("order.sock")
		if err != nil {
			t.Fatalf("Dial %d: unexpected error: %v", i, err)
		}
		dialed[i] = c
	}
	// When each is accepted in turn
	for i := 0; i < 3; i++ {
		accepted, err := l.Accept()
		if err != nil {
			t.Fatalf("Accept %d: unexpected error: %v", i, err)
		}
		// Then the i-th dialed end pairs with the i-th accepted end
		requireSend(t, dialed[i], []byte(fmt.Sprintf("conn-%d", i)))
		if got := requireRecv(t, accepted); string(got) != fmt.Sprintf("conn-%d", i) {
			t.Fatalf("Accept %d: got %q, want %q", i, got, fmt.Sprintf("conn-%d", i))
		}
	}
}
