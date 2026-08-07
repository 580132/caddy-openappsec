// Package mock implements a scriptable stand-in for the open-appsec engine,
// served over any transport.Listener. The in-memory transport
// (internal/transport/memory) provides the in-process listener used by unit
// tests; a socket-based listener serves cross-process end-to-end tests. The
// engine runs the server side of the registration handshake
// (docs/attachment-protocol.md §G), parses attachment request frames with
// internal/protocol, and answers each request with a scripted verdict.
//
// Address model: the engine listens on a single address — an in-memory
// registry key in tests, a socket path in cross-process setups — and
// collapses the three sockets of the real protocol onto it — §G.1
// registration, §G.2 comm and §G.3 keep-alive all arrive at the same
// listener. The phase-1 registration reply always names the engine's own
// address as the verdict-signal path, so a client can dial the same address
// again for comm and request traffic.
//
// Handshake (server side): a connection in phase 0 accepts exactly one
// registration frame, which gets a RegistrationReply naming the engine
// address; the connection is then closed by the client (§G.1 one-shot).
// A fresh connection in phase 0 receives the comm frame (with target_core)
// and gets a one-byte Ack; that connection then carries keep-alive and
// request traffic. Every other frame is classified deterministically:
// request frames (data types 0–10) are recognized first; registration
// (only on a fresh connection), comm data, keep-alive, then unknown. Frames
// whose second byte is zero are request frames (the data_type is a
// little-endian uint16 below 256); registration frames carry worker_id+1 in
// that byte and are never requests. This matches the app's client
// (internal/app/handshake.go), which sends REGISTRATION on a one-shot
// connection, closes it, and dials the returned path for COMM_DATA and
// request traffic.
//
// Verdicts: SetNextVerdict queues scripted verdicts in FIFO order; each
// REQUEST_START pops one and the engine replies on the same connection,
// echoing the session id from the frame (a scripted verdict's SessionID
// field is ignored). An empty queue yields ACCEPT. SetResponder installs a
// steady-state verdict function that wins over the queue. SetVerdictsEnabled
// (false) makes the engine consume request frames without replying, and
// SetFlakyAfter closes each connection after N REQUEST_START frames — both
// exercise the app's fail-open and reconnect paths.
//
// The engine is safe for concurrent use: all mutable state is guarded by a
// single mutex. SetEngineDown/Close close the listener — unregistering the
// address so a fresh engine can bind it again — and close every live
// connection; clients observe transport.ErrClosed.
package mock
