// Package transport defines the byte-oriented channel between the Caddy
// attachment and the open-appsec engine, plus an in-process implementation
// used by unit tests and the mock engine.
//
// # Abstraction
//
// A transport moves opaque payloads. EngineConn.Send delivers one complete
// []byte to the peer and EngineConn.Recv returns the next complete payload;
// nothing in this package interprets the bytes. Encoding protocol messages
// is the codec package's job, and transport never imports it.
//
// # Semantics
//
// Operations are message-framed rather than a raw stream: one Send is
// exactly one Recv unit. This matches the engine's shared-memory ring queue,
// which frames messages in its management segment
// (docs/attachment-protocol.md §D.3): the linux implementation can preserve
// the one-Send-one-Recv contract without any protocol knowledge, bounded by
// the ring's per-message cap (max_write_size, §D.3).
//
// Send and Recv take a context.Context so callers can impose deadlines and
// cancellation. Closing a connection tears down both directions and unblocks
// every pending operation with ErrClosed; callers should test with
// errors.Is(err, ErrClosed). A closed connection is permanently unusable and
// must be re-established.
//
// # Implementations
//
// The memory subpackage implements both interfaces with in-process pipes
// addressed by a string, standing in for the engine socket path; the mock
// engine and tests use it. The linux implementation (later wave) will back
// the same interfaces with the shared-memory ring queues and AF_UNIX
// registration/keep-alive sockets of docs/attachment-protocol.md §D and §G:
// the listener address will be the engine socket path
// (SHARED_REGISTRATION_SIGNAL_PATH, §G.1) and the attachment's dial will be
// the connect to it. The codec package plugs in on top, decoding the
// payloads into protocol messages.
package transport
