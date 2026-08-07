//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/580132/caddy-openappsec/internal/config"
	"github.com/580132/caddy-openappsec/internal/protocol"
	"github.com/580132/caddy-openappsec/internal/transport"
)

// defaultPollInterval is how long Send and Recv sleep between polling the
// shared-memory ring when it is full or empty.
const defaultPollInterval = 5 * time.Millisecond

// OpenRing opens the attachment's two one-way shared-memory ring queues and
// returns a single message-framed connection over them, keeping comm open as
// the per-request signaling channel (§G.2). The queue name is the attachment's
// unique id — cfg.UniqueID(), the same value the app sends in the phase-2 comm
// frame (internal/app/handshake.go commFrame) — because the engine creates its
// queues under that id: initIpc(curr_instance_unique_id) (nginx_attachment.cc:537-538)
// names the files "__cp_nano_%s_shared_memory_<unique_id>__" (shmem_ipc.c:78,108).
// The C reference passes the same unique id to initIpc (ngx_cp_initializer.c:886-887,
// 999). The service files live in /dev/shm (shmem_ipc.c:98) and follow the
// pattern "__cp_nano_%s_shared_memory_%s__" (shmem_ipc.c:78). The attachment
// writes requests into the service's rx queue and reads verdicts from the
// service's tx queue (shmem_ipc.c:85-90), so Send and Recv on the returned
// connection each target a different file.
//
// The engine does not poll the ring: its inspection file routine fires only
// when data arrives on the comm socket, reads the 4-byte signaled session id,
// then drains the ring for that session (nginx_attachment.cc:594-658) and
// writes the handled session id back on the socket as the verdict-ready echo
// (nginx_attachment.cc:664-695). Send therefore pushes to the ring and then
// writes the payload's 4-byte little-endian session id to comm; Recv first
// reads the 4-byte echo from comm and then pops the ring. The C reference
// implements the same exchange (ngx_cp_io.c:72-114 signal_to_service,
// 128-221 wait_for_service). The comm socket stays open for the attachment's
// lifetime (isIpcReady requires comm_socket > 0, ngx_cp_initializer.c:1067-1069).
//
// verdictPath is the comm socket path the engine assigned in phase 1 (§G.2);
// it is accepted for signature compatibility with the app layer, but the queue
// name is derived from cfg.UniqueID(). The app layer calls OpenRing only after
// the registration/comm handshake (§G) completes, because the service must have
// created and sized the queues first; the queue geometry (segment size
// 1024/4096, segment count) is read from the shared header rather than passed
// in. comm must be the live phase-2 connection that completed the handshake
// ack; its socket stays open as the signal channel.
func OpenRing(ctx context.Context, verdictPath string, cfg config.EngineConfig, comm transport.EngineConn) (transport.EngineConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name := cfg.UniqueID()
	if name == "" {
		return nil, fmt.Errorf("linux: OpenRing: empty unique id (queue name)")
	}
	writePath := filepath.Join("/dev/shm", queueFileName(dirWrite, name))
	readPath := filepath.Join("/dev/shm", queueFileName(dirRead, name))
	writeQ, err := openRingQueue(writePath)
	if err != nil {
		return nil, fmt.Errorf("linux: open write queue %q: %w", writePath, err)
	}
	readQ, err := openRingQueue(readPath)
	if err != nil {
		writeQ.close()
		return nil, fmt.Errorf("linux: open read queue %q: %w", readPath, err)
	}
	return newRingConn(writeQ, readQ, comm, defaultPollInterval), nil
}

// ringQueue is one mapped shared-memory ring queue file.
type ringQueue struct {
	fd   int
	mmap []byte
	ring *ring
}

// openRingQueue opens and mmaps one queue file and validates its header. The
// user (attachment) side opens with O_RDWR and does not create or size the
// file — the owner (service) already did (shared_ring_queue.c:245, 268-321).
func openRingQueue(path string) (*ringQueue, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("fstat: %w", err)
	}
	if st.Size <= 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("shared-memory file is empty (%d bytes)", st.Size)
	}
	length := int(st.Size)
	data, err := syscall.Mmap(fd, 0, length, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("mmap: %w", err)
	}
	r, err := newRing(data)
	if err != nil {
		syscall.Munmap(data)
		syscall.Close(fd)
		return nil, err
	}
	return &ringQueue{fd: fd, mmap: data, ring: r}, nil
}

func (q *ringQueue) close() {
	if q.fd >= 0 {
		syscall.Munmap(q.mmap)
		syscall.Close(q.fd)
		q.fd = -1
	}
}

// ringConn is a transport.EngineConn backed by two shared-memory ring queues
// and the comm signal socket: Send pushes into the write queue and then writes
// the payload's 4-byte session id to comm; Recv reads the 4-byte verdict-ready
// echo from comm and then pulls from the read queue. One Send becomes exactly
// one Recv unit on the peer via the management-segment framing. It is safe for
// concurrent use; operations serialize on mu.
type ringConn struct {
	mu      sync.Mutex
	closed  bool
	closeCh chan struct{}
	writeQ  *ringQueue
	readQ   *ringQueue
	comm    transport.EngineConn // phase-2 comm socket, kept open (§G.2)
	poll    time.Duration
	// echoBuf buffers bytes read from comm beyond one 4-byte echo. The
	// coalescing unixConn may merge two echoes into one Recv when the agent
	// processes back-to-back signals within the readCoalesce window; leftover
	// bytes are replayed on the next Recv so each echo is consumed exactly.
	echoBuf []byte
	// flowMu serializes inspection sessions so only one is in flight per
	// socket, matching the engine's per-session signaling (it discards ring
	// data for sessions other than the signaled one).
	flowMu sync.Mutex
}

// var guards the interface contract at compile time.
var (
	_ transport.EngineConn  = (*ringConn)(nil)
	_ transport.FlowSerial  = (*ringConn)(nil)
	_ transport.RingDrainer = (*ringConn)(nil)
)

func newRingConn(writeQ, readQ *ringQueue, comm transport.EngineConn, poll time.Duration) *ringConn {
	return &ringConn{closeCh: make(chan struct{}), writeQ: writeQ, readQ: readQ, comm: comm, poll: poll}
}

// LockFlow serializes inspection sessions on this connection: the caller holds
// it across one send→verdict window so the engine never sees a second session
// before the first is resolved.
func (c *ringConn) LockFlow() { c.flowMu.Lock() }

// UnlockFlow releases the session lock held by LockFlow.
func (c *ringConn) UnlockFlow() { c.flowMu.Unlock() }

// Send copies payload into the write ring queue and then writes the payload's
// 4-byte little-endian session id (offset 2, after data_type) to the comm
// socket, signaling the engine that a new chunk for that session is ready to
// drain (ngx_cp_io.c:72-114). It returns ErrClosed when the connection is
// closed, ctx.Err() when ctx completes first, and errRingTooLarge (wrapped)
// when payload exceeds the engine's max_write_size cap of 0xfffc bytes
// (shared_ring_queue.c:33). While the ring is full it blocks, polling until
// space appears, ctx is done, or the conn closes.
func (c *ringConn) Send(ctx context.Context, payload []byte) error {
	if uint32(len(payload)) > uint32(protocol.MaxWriteSize) {
		return fmt.Errorf("%w: %d bytes", errRingTooLarge, len(payload))
	}
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return transport.ErrClosed
		}
		err := c.writeQ.ring.push([][]byte{payload})
		c.mu.Unlock()
		if err == nil {
			break
		}
		if err != errRingFull {
			return err
		}
		if werr := c.wait(ctx); werr != nil {
			return werr
		}
	}
	if len(payload) < 6 {
		return nil // no session id (e.g. empty frame); nothing to signal
	}
	var sig [4]byte
	binary.LittleEndian.PutUint32(sig[:], binary.LittleEndian.Uint32(payload[2:6]))
	if err := c.comm.Send(ctx, sig[:]); err != nil {
		return fmt.Errorf("linux: signal session: %w", err)
	}
	return nil
}

// Recv returns the next complete message from the read ring queue, blocking
// until one is available, ctx is done, or the connection is closed. Before
// reading the ring it consumes the 4-byte verdict-ready echo the engine writes
// to the comm socket after handling a signaled session (nginx_attachment.cc:664-695,
// ngx_cp_io.c:128-221), so the returned ring message is always the response to
// a completed exchange, never a premature poll. ErrClosed wins over a done
// context. The returned slice is owned by the caller; the ring copy is freed
// immediately after.
func (c *ringConn) Recv(ctx context.Context) ([]byte, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, transport.ErrClosed
		}
		if err := c.recvEcho(ctx); err != nil {
			c.mu.Unlock()
			return nil, err
		}
		size, off, err := c.readQ.ring.peek()
		if err == nil {
			msg := make([]byte, size)
			copy(msg, c.readQ.ring.buf[off:off+int(size)])
			_ = c.readQ.ring.pop()
			c.mu.Unlock()
			return msg, nil
		}
		c.mu.Unlock()
		if err != errRingEmpty {
			return nil, err
		}
		if werr := c.wait(ctx); werr != nil {
			return nil, werr
		}
	}
}

// RecvQueued returns the next ring message without waiting for a new comm echo.
// The engine writes one verdict frame per chunk to the ring (INSPECT for
// REQUEST_START/HEADER/BODY, the terminal verdict for REQUEST_END) but signals
// the comm socket only when it finishes draining — so a single echo may be
// followed by several queued verdict frames. The verdict waiter drains them
// with RecvQueued after the first echo-driven Recv. It returns errRingEmpty
// (via the ring) when nothing is queued.
func (c *ringConn) RecvQueued() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, transport.ErrClosed
	}
	size, off, err := c.readQ.ring.peek()
	if err != nil {
		return nil, err
	}
	msg := make([]byte, size)
	copy(msg, c.readQ.ring.buf[off:off+int(size)])
	_ = c.readQ.ring.pop()
	return msg, nil
}

// queued reports whether the read ring holds at least one message, without
// consuming it. Used by the verdict waiter to know when to stop draining.
func (c *ringConn) queued() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _, err := c.readQ.ring.peek()
	return err == nil
}

// recvEcho consumes exactly 4 bytes of echo from the comm socket, replaying
// any leftover buffered bytes first. ctx must be valid. Caller holds c.mu.
func (c *ringConn) recvEcho(ctx context.Context) error {
	for len(c.echoBuf) < 4 {
		if c.comm == nil {
			return nil // no comm socket (tests): no echo to wait for
		}
		b, err := c.comm.Recv(ctx)
		if err != nil {
			return fmt.Errorf("linux: comm echo: %w", err)
		}
		c.echoBuf = append(c.echoBuf, b...)
	}
	c.echoBuf = c.echoBuf[4:]
	return nil
}

// wait blocks until it is time to poll again, ctx is done, or the connection
// closes. ErrClosed deterministically wins over a done context.
func (c *ringConn) wait(ctx context.Context) error {
	timer := time.NewTimer(c.poll)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return transport.ErrClosed
		}
		return ctx.Err()
	case <-c.closeCh:
		return transport.ErrClosed
	case <-timer.C:
		return nil
	}
}

// Close tears down the connection, unblocking pending Send/Recv with
// ErrClosed, unmaps both ring queues, and closes the comm signal socket. It
// returns nil on the first call and ErrClosed afterwards.
func (c *ringConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return transport.ErrClosed
	}
	c.closed = true
	close(c.closeCh)
	comm := c.comm
	c.comm = nil
	c.mu.Unlock()
	if comm != nil {
		_ = comm.Close()
	}
	c.writeQ.close()
	c.readQ.close()
	return nil
}
