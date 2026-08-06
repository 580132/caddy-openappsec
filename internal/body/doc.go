// Package body provides body-handling primitives for the openappsec Caddy
// attachment: request-body decompression for inspection, chunking of the
// decompressed stream into protocol BODY_CHUNK payloads, response-side
// buffering with a passthrough policy, and response re-compression.
//
// The HTTP handler wave (not this package) orchestrates the primitives:
//
//	decompress -> chunk -> submit via app -> buffer response -> recompress -> write
//
// Every type here is a pure, goroutine-free state machine: a single caller
// owns each instance. No caddy.Context and no http.ResponseWriter appears in
// this package by design.
package body
