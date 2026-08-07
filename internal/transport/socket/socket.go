package socket

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/yourname/caddy-openappsec/internal/transport"
)

// dialTimeout bounds how long Dial waits to establish a connection. A
// connection that cannot be established within this window is abandoned and
// reported as an error rather than blocking a caller indefinitely.
const dialTimeout = 30 * time.Second

// Listen binds a TCP listener at addr and returns it. addr may be a bare
// "host:port" or prefixed with "tcp://"; both name a TCP endpoint. A
// "unix://" address is rejected with an error: the scheme is reserved for a
// future Unix-socket variant and never silently falls back to TCP.
//
// A port of 0 requests an ephemeral port; the address actually bound is
// reported by the listener's Addr method.
func Listen(addr string) (*Listener, error) {
	hostport, err := parseAddr(addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", hostport)
	if err != nil {
		return nil, fmt.Errorf("socket: listen on %q: %w", addr, err)
	}
	return &Listener{ln: ln}, nil
}

// Dial connects to the TCP listener at addr and returns the attachment-side
// end of a new connection; the listener's next Accept returns the
// engine-side end of the same pair. addr is parsed like Listen's: a bare
// "host:port" or a "tcp://"-prefixed address; "unix://" is rejected.
//
// Dial fails if nothing is listening at addr (for example because the
// listener was closed), mirroring a connection to an engine that is not up.
// The connection attempt is bounded by dialTimeout and uses a context-based
// net.Dialer, so a slow or unresponsive peer cannot stall the caller.
func Dial(addr string) (transport.EngineConn, error) {
	hostport, err := parseAddr(addr)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: dialTimeout}
	nc, err := d.DialContext(context.Background(), "tcp", hostport)
	if err != nil {
		return nil, fmt.Errorf("socket: dial %q: %w", addr, err)
	}
	return &conn{netConn: nc}, nil
}

// parseAddr normalizes an address into the "host:port" form net.Listen and
// net.Dial accept. A "tcp://" prefix is stripped; "unix://" is rejected with
// a descriptive error (the scheme is reserved for a future Unix-socket
// transport and must not silently fall back to TCP); anything else is passed
// through as a bare host:port.
func parseAddr(addr string) (string, error) {
	if strings.HasPrefix(addr, "unix://") {
		return "", fmt.Errorf("socket: %q: unix:// addresses are reserved for a future Unix-socket transport; use a TCP address", addr)
	}
	hostport := strings.TrimPrefix(addr, "tcp://")
	if hostport == "" {
		return "", fmt.Errorf("socket: address must not be empty")
	}
	return hostport, nil
}
