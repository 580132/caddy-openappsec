// Package socket implements the transport interfaces over real TCP sockets,
// so the Caddy process and a mock engine process can talk cross-process. It
// moves the same byte-level protocol messages as the in-memory transport:
// nothing here interprets the bytes, and the one-Send-is-one-Recv contract of
// transport.EngineConn is preserved by the framing below.
//
// # Framing
//
// Each payload is delivered as one frame: a 4-byte little-endian length
// prefix followed by the payload bytes. One Send writes exactly one frame,
// which the peer reads back as exactly one Recv. Frames are bounded at
// 256 MiB; a length prefix beyond that cap is rejected with an error rather
// than allocated, and a frame that declares more bytes than the stream
// delivers is reported as truncated.
//
// # Addresses
//
// Addresses are "tcp://host:port"; a bare "host:port" is treated as TCP. The
// "unix://" scheme is reserved for a future Unix-socket variant and is
// rejected with an explicit error on every platform — never silently falling
// back to TCP.
//
// Listener.Addr always reports the canonical "tcp://host:port" form of the
// bound address, including the actual port when one was allocated
// ephemerally, so Dial can be handed a listener's address directly.
package socket
