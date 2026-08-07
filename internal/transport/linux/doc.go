// Package linux is the production transport between the Caddy attachment and
// the open-appsec engine, for linux builds. It implements
// transport.EngineConn over two channels that mirror
// docs/attachment-protocol.md §D and §G:
//
//   - Data: shared-memory ring queues. OpenRing maps the engine's
//     "__cp_nano_%s_shared_memory_%s__" files (§D.1) and moves messages
//     through the management-segment framing (§D.3) — one Send is exactly one
//     Recv unit on the peer, capped at max_write_size (0xfffc). Send signals
//     each chunk's 4-byte session id on the comm socket and Recv waits for the
//     engine's echo before popping the ring (§G.2b).
//   - Control: AF_UNIX sockets. DialSignal connects to the registration,
//     comm and keep-alive sockets (§G.1-§G.3) as an opaque byte channel; the
//     two-phase handshake frames are built and parsed by the app layer, never
//     by this package. The phase-2 comm socket is retained by the ring conn as
//     the per-request signal/echo doorbell.
//
// Ring framing logic (offset math, magic traversal, header parsing, size
// validation) lives in the non-build-tagged files ring.go/ring_test.go and is
// covered by table-driven unit tests that run on any platform; the linux-only
// pieces (mmap, unix dial, comm signaling) are the thin wrappers in
// ring_linux.go and unix_linux.go. Everything traces to
// core/shmem_ipc_2/shared_ring_queue.{h,c} and core/shmem_ipc_2/shmem_ipc.c
// from the pinned C source; where the doc and the C disagree, the C source
// wins.
package linux
