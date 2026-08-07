//go:build linux

package linux

import (
	"context"
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
// returns a single message-framed connection over them. The queue name is the
// attachment's unique id — cfg.UniqueID(), the same value the app sends in the
// phase-2 comm frame (internal/app/handshake.go commFrame) — because the
// engine creates its queues under that id: initIpc(curr_instance_unique_id)
// (nginx_attachment.cc:537-538) names the files
// "__cp_nano_%s_shared_memory_<unique_id>__" (shmem_ipc.c:78,108). The C
// reference passes the same unique id to initIpc (ngx_cp_initializer.c:886-887,
// 999). The service files live in /dev/shm (shmem_ipc.c:98) and follow the
// pattern "__cp_nano_%s_shared_memory_%s__" (shmem_ipc.c:78). The attachment
// writes requests into the service's rx queue and reads verdicts from the
// service's tx queue (shmem_ipc.c:85-90), so Send and Recv on the returned
// connection each target a different file.
//
// verdictPath is the comm socket path the engine assigned in phase 1 (§G.2);
// it is accepted for signature compatibility with the app layer, but the queue
// name is derived from cfg.UniqueID(). The app layer calls OpenRing only after
// the registration/comm handshake (§G) completes, because the service must have
// created and sized the queues first; the queue geometry (segment size
// 1024/4096, segment count) is read from the shared header rather than passed
// in.
func OpenRing(ctx context.Context, verdictPath string, cfg config.EngineConfig) (transport.EngineConn, error) {
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
	return newRingConn(writeQ, readQ, defaultPollInterval), nil
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

// ringConn is a transport.EngineConn backed by two shared-memory ring queues:
// Send pushes into the write queue and Recv pulls from the read queue. One
// Send becomes exactly one Recv unit on the peer via the management-segment
// framing. It is safe for concurrent use; operations serialize on mu.
type ringConn struct {
	mu      sync.Mutex
	closed  bool
	closeCh chan struct{}
	writeQ  *ringQueue
	readQ   *ringQueue
	poll    time.Duration
}

// var guards the interface contract at compile time.
var _ transport.EngineConn = (*ringConn)(nil)

func newRingConn(writeQ, readQ *ringQueue, poll time.Duration) *ringConn {
	return &ringConn{closeCh: make(chan struct{}), writeQ: writeQ, readQ: readQ, poll: poll}
}

// Send copies payload into the write ring queue. It returns ErrClosed when
// the connection is closed, ctx.Err() when ctx completes first, and
// errRingTooLarge (wrapped) when payload exceeds the engine's max_write_size
// cap of 0xfffc bytes (shared_ring_queue.c:33). While the ring is full it
// blocks, polling until space appears, ctx is done, or the conn closes.
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
			return nil
		}
		if err != errRingFull {
			return err
		}
		if werr := c.wait(ctx); werr != nil {
			return werr
		}
	}
}

// Recv returns the next complete message from the read ring queue, blocking
// until one is available, ctx is done, or the connection is closed. ErrClosed
// wins over a done context. The returned slice is owned by the caller; the
// ring copy is freed immediately after.
func (c *ringConn) Recv(ctx context.Context) ([]byte, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, transport.ErrClosed
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
// ErrClosed, and unmaps both ring queues. It returns nil on the first call
// and ErrClosed afterwards.
func (c *ringConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return transport.ErrClosed
	}
	c.closed = true
	close(c.closeCh)
	c.mu.Unlock()
	c.writeQ.close()
	c.readQ.close()
	return nil
}
