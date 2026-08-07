package socket

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/yourname/caddy-openappsec/internal/transport"
)

// requireListen binds a listener at addr, failing the test on error. The
// listener is closed at cleanup.
func requireListen(t *testing.T, addr string) *Listener {
	t.Helper()
	l, err := Listen(addr)
	if err != nil {
		t.Fatalf("Listen(%q): unexpected error: %v", addr, err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func Test_Listen_Dial_Accept_full_round_trip(t *testing.T) {
	// Given a listening socket
	l := requireListen(t, "127.0.0.1:0")
	// When a connection is dialed and accepted
	client, err := Dial(l.Addr())
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

func Test_Listener_Addr_reports_bound_address(t *testing.T) {
	// Given a listener bound to an ephemeral port
	l := requireListen(t, "127.0.0.1:0")
	addr := l.Addr()
	// Then Addr reports the canonical tcp:// form with the allocated port
	if !strings.HasPrefix(addr, "tcp://") {
		t.Fatalf("Addr: got %q, want a tcp:// prefix", addr)
	}
	host, port, err := net.SplitHostPort(strings.TrimPrefix(addr, "tcp://"))
	if err != nil {
		t.Fatalf("Addr %q: SplitHostPort: %v", addr, err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("Addr: got host %q, want 127.0.0.1", host)
	}
	if port == "0" {
		t.Fatal("Addr: port is still 0, want the allocated ephemeral port")
	}
}

func Test_Dial_after_listener_close_fails(t *testing.T) {
	// Given a listener that is closed
	l := requireListen(t, "127.0.0.1:0")
	addr := l.Addr()
	requireClose(t, l)
	// When Dial targets its address
	// Then it fails (nothing is listening there anymore)
	if _, err := Dial(addr); err == nil {
		t.Fatal("Dial: expected error after listener closed")
	}
}

func Test_Dial_accepts_bare_hostport(t *testing.T) {
	// Given a listener and its address with the scheme prefix stripped
	l := requireListen(t, "127.0.0.1:0")
	bare := strings.TrimPrefix(l.Addr(), "tcp://")
	// When Dial is called with the bare host:port form
	client, err := Dial(bare)
	if err != nil {
		t.Fatalf("Dial(%q): unexpected error: %v", bare, err)
	}
	server, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: unexpected error: %v", err)
	}
	// Then the pair round-trips payloads
	requireSend(t, client, []byte("hi"))
	if got := requireRecv(t, server); string(got) != "hi" {
		t.Fatalf("Recv: got %q, want %q", got, "hi")
	}
}

func Test_Listener_Close_unblocks_pending_Accept(t *testing.T) {
	// Given an Accept blocked on an idle listener
	l := requireListen(t, "127.0.0.1:0")
	acceptErr := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		acceptErr <- err
	}()
	time.Sleep(50 * time.Millisecond)
	// When the listener is closed
	requireClose(t, l)
	// Then the blocked Accept unblocks with ErrClosed
	if err := waitErr(t, acceptErr); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("Accept: got %v, want ErrClosed", err)
	}
}

func Test_Listener_Close_is_idempotent_and_blocks_accept(t *testing.T) {
	// Given a closed listener
	l := requireListen(t, "127.0.0.1:0")
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

func Test_unix_scheme_is_rejected(t *testing.T) {
	// Given a unix:// address
	// When Listen or Dial is called with it
	// Then it is rejected with an explicit error, never silently falling
	// back to TCP
	if _, err := Listen("unix:///tmp/engine.sock"); err == nil {
		t.Fatal("Listen: expected error for unix:// address")
	} else if !strings.Contains(err.Error(), "unix") {
		t.Fatalf("Listen: got %v, want an error mentioning unix://", err)
	}
	if _, err := Dial("unix:///tmp/engine.sock"); err == nil {
		t.Fatal("Dial: expected error for unix:// address")
	} else if !strings.Contains(err.Error(), "unix") {
		t.Fatalf("Dial: got %v, want an error mentioning unix://", err)
	}
}

func Test_Listen_rejects_empty_address(t *testing.T) {
	// Given an empty address
	// When Listen is called with it
	// Then it fails
	for _, addr := range []string{"", "tcp://"} {
		if l, err := Listen(addr); err == nil {
			t.Fatalf("Listen(%q): expected error, got %v", addr, l)
		}
	}
}
