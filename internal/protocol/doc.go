// Package protocol encodes and decodes the open-appsec attachment wire
// protocol. It lets a Caddy handler build the frames the engine consumes —
// REQUEST_START metadata, keep-alive, headers, bodies, and session lifecycle
// messages — and parse the verdict replies the engine returns.
//
// The byte-level contract is docs/attachment-protocol.md, which was derived
// from the pinned C reference (github.com/openappsec/attachment at
// 2f46293b32c58d5be250aa6d3bac0e4ba9260738). Every encoder in this package
// reproduces the C sender's byte ordering: plain integer fields are
// little-endian (host byte order on x86), listening/client ports are written
// in network byte order via htons (ngx_cp_io.c:970,983), and strings are
// uint16 length prefixes followed by raw bytes. The shared-memory ring queue
// header layout and its management-segment magic values (0xfffe / 0xfffd /
// 0xfffc) are exposed as constants in const.go.
//
// Usage: build a RequestStart with SessionID from a SessionAllocator and call
// Encode; the resulting bytes are one message pushed onto the tx ring queue.
// On the reply side, ParseVerdict decodes an HttpReplyFromService frame,
// mapping DROP to a WebResponse (status code, title, body) and INJECT to a
// list of Injection modifications. The package uses only the standard library
// and mirrors the packed C structs without cgo or reflection.
package protocol
