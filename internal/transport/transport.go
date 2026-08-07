package transport

import (
	"context"
	"errors"
)

// ErrClosed is the sentinel error returned by any operation performed on a
// connection or listener that has been closed: Send, Recv, Close and Accept
// all report it. Test with errors.Is(err, ErrClosed); a connection that
// returns ErrClosed is permanently unusable and must be re-established.
var ErrClosed = errors.New("transport: connection closed")

// FlowSerial is implemented by EngineConns that permit only one in-flight
// inspection session at a time. The linux shm transport is one: its
// comm-socket signaling protocol is per-session, and the agent discards ring
// data for sessions other than the one it was signaled for
// (nginx_attachment.cc handleRequestFromQueue), so concurrent sessions on a
// shared conn would have their frames dropped. The app layer serializes a
// request's send→verdict window with LockFlow/UnlockFlow.
type FlowSerial interface {
	LockFlow()
	UnlockFlow()
}

// RingDrainer is implemented by EngineConns whose peer may write several
// messages to the ring per comm echo. The linux shm engine writes one verdict
// frame per request chunk (INSPECT for START/HEADER/BODY, terminal for END)
// but signals the comm socket only when it finishes draining, so after the
// echo-driven Recv the waiter drains the queued frames with RecvQueued.
type RingDrainer interface {
	RecvQueued() ([]byte, error)
}

// TransactionSignaler is implemented by EngineConns that require an explicit
// comm-socket signal after a transaction's frames are queued, instead of one
// signal per Send. The linux shm transport needs exactly one signal per
// transaction (the engine drains the whole ring on one signal); per-frame
// signals leave spurious traffic that destabilizes the connection.
type TransactionSignaler interface {
	Signal(ctx context.Context, sid uint32) error
}

// EngineConn is a byte-oriented, message-framed connection to the
// open-appsec engine. It moves opaque []byte payloads: one Send is delivered
// to the peer as exactly one Recv. The payload bytes carry protocol messages,
// but the transport never interprets them — encoding is the codec package's
// job.
type EngineConn interface {
	// Send delivers one complete payload to the peer. It blocks until the
	// payload is accepted, ctx is done, or the connection is closed; on
	// success it returns nil. Send copies payload and does not retain it:
	// the caller may reuse the slice as soon as Send returns.
	//
	// If the connection is closed, Send returns ErrClosed. Otherwise, if ctx
	// is done before the payload is accepted, Send returns ctx.Err().
	// ctx must not be nil.
	Send(ctx context.Context, payload []byte) error

	// Recv returns the next complete payload received from the peer,
	// blocking until one is available, ctx is done, or the connection is
	// closed. The returned slice is owned by the caller.
	//
	// If the connection is closed, Recv returns nil, ErrClosed — including
	// when the peer closed it. Otherwise, if ctx is done before a payload
	// arrives, Recv returns nil, ctx.Err(). ctx must not be nil.
	Recv(ctx context.Context) ([]byte, error)

	// Close closes the connection in both directions, unblocking any pending
	// Send or Recv with ErrClosed. It returns nil on the first call and
	// ErrClosed on any later call.
	Close() error
}

// Listener accepts connections at a local address. The address is an opaque
// string: the linux implementation will treat it as the engine socket path,
// and the in-memory implementation treats it as a registration key.
type Listener interface {
	// Addr returns the address the listener is bound to, in the same opaque
	// string form used by Dial. For a listener bound to an ephemeral port
	// it reports the actual port that was allocated.
	Addr() string

	// Accept returns the next connection, blocking until one is available
	// or the listener is closed. If the listener is closed, Accept returns
	// nil, ErrClosed.
	Accept() (EngineConn, error)

	// Close closes the listener, unblocking a pending Accept with ErrClosed.
	// It returns nil on the first call and ErrClosed on any later call.
	Close() error
}
