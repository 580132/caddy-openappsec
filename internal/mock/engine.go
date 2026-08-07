package mock

import (
	"encoding/hex"
	"slices"
	"sync"

	"github.com/yourname/caddy-openappsec/internal/protocol"
	"github.com/yourname/caddy-openappsec/internal/transport"
	"github.com/yourname/caddy-openappsec/internal/transport/memory"
)

// Responder computes the verdict for a request session. It is invoked for
// every REQUEST_START frame while installed; the returned verdict's
// SessionID is replaced with the frame's session id.
type Responder func(session uint32) protocol.Verdict

// Frame is one frame received by the engine, as recorded for tests and the
// CLI hex dump.
type Frame struct {
	// Hex is the lowercase hex dump of the frame bytes.
	Hex string
	// Meaning is the one-line parsed meaning, see DescribeFrame.
	Meaning string
}

// Engine is a scriptable open-appsec engine over the in-memory transport.
// See the package documentation for the wire behavior.
type Engine struct {
	addr string
	l    *memory.Listener

	mu           sync.Mutex
	closed       bool
	verdicts     []protocol.Verdict
	respond      Responder
	replyEnabled bool
	flaky        int // >0: close each conn after this many REQUEST_START frames
	conns        map[transport.EngineConn]struct{}
	frames       []Frame
	requests     int
	total        int

	// responseVerdicts is the FIFO queue of scripted verdicts for response
	// inspections; each RESPONSE_CODE pops the queue in order.
	responseVerdicts []protocol.Verdict
	// responses counts RESPONSE_CODE frames received (response sessions).
	responses int
}

// New starts an engine listening at addr, which is a plain registry key for
// the in-memory transport. It fails if the address is already in use.
func New(addr string) (*Engine, error) {
	l, err := memory.Listen(addr)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		addr:         addr,
		l:            l,
		replyEnabled: true,
		conns:        make(map[transport.EngineConn]struct{}),
	}
	go e.acceptLoop()
	return e, nil
}

// Addr returns the address the engine listens on.
func (e *Engine) Addr() string { return e.addr }

// SetNextVerdict appends a scripted verdict to the FIFO queue. Each
// REQUEST_START pops the queue in order.
func (e *Engine) SetNextVerdict(v protocol.Verdict) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.verdicts = append(e.verdicts, v)
}

// SetNextResponseVerdict appends a scripted response verdict to the FIFO
// queue. Each RESPONSE_CODE frame pops the queue in order.
func (e *Engine) SetNextResponseVerdict(v protocol.Verdict) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.responseVerdicts = append(e.responseVerdicts, v)
}

// SetResponder installs fn as the steady-state verdict function. A non-nil
// responder wins over the verdict queue; nil restores queue + default ACCEPT.
func (e *Engine) SetResponder(fn Responder) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.respond = fn
}

// SetVerdictsEnabled controls whether request frames receive verdict
// replies. Disabling it makes the engine consume and record request frames
// without replying — the "down" scenario, which exercises the app's fail-open
// timeout budget.
func (e *Engine) SetVerdictsEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.replyEnabled = enabled
}

// SetFlakyAfter makes each connection die after n REQUEST_START frames have
// been received on it: the nth request is consumed without a reply and the
// connection is closed, exercising the app's reconnect path. The listener
// keeps accepting new connections, each with a fresh budget. n <= 0 disables
// flaky behavior.
func (e *Engine) SetFlakyAfter(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.flaky = n
}

// SetEngineDown stops accepting connections and closes every live
// connection. The address is unregistered, so subsequent Dials fail with
// transport.ErrClosed until a fresh engine binds it again. It returns nil on
// the first call and transport.ErrClosed afterwards.
func (e *Engine) SetEngineDown() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return transport.ErrClosed
	}
	e.closed = true
	conns := make([]transport.EngineConn, 0, len(e.conns))
	for c := range e.conns {
		conns = append(conns, c)
	}
	e.mu.Unlock()

	_ = e.l.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	return nil
}

// Close stops the engine; it is equivalent to SetEngineDown.
func (e *Engine) Close() error { return e.SetEngineDown() }

// ReceivedFrames returns a snapshot of the frames received so far, in
// arrival order across all connections.
func (e *Engine) ReceivedFrames() []Frame {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.frames)
}

// Requests returns the number of REQUEST_START frames received.
func (e *Engine) Requests() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.requests
}

// ResponseCount returns the number of RESPONSE_CODE frames received (response
// inspection sessions opened).
func (e *Engine) ResponseCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.responses
}

// FrameCount returns the total number of frames received across all
// connections, including handshake frames.
func (e *Engine) FrameCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.total
}

// acceptLoop accepts connections until the listener closes and hands each
// connection to a handler goroutine.
func (e *Engine) acceptLoop() {
	for {
		c, err := e.l.Accept()
		if err != nil {
			return // listener closed by SetEngineDown/Close
		}
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			_ = c.Close()
			return
		}
		e.conns[c] = struct{}{}
		e.mu.Unlock()
		go e.handleConn(c)
	}
}

// record appends a frame record and tallies counters. Requests counts
// REQUEST_START frames specifically; total counts every frame.
func (e *Engine) record(b []byte, meaning string, isRequest bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.frames = append(e.frames, Frame{Hex: hex.EncodeToString(b), Meaning: meaning})
	e.total++
	if isRequest {
		e.requests++
	}
}

// verdictFor returns the verdict to send for session sid: the responder's,
// the next queued verdict, or ACCEPT. The session id is always echoed from
// the request.
func (e *Engine) verdictFor(sid uint32) protocol.Verdict {
	e.mu.Lock()
	defer e.mu.Unlock()
	v := protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: sid}
	if e.respond != nil {
		v = e.respond(sid)
	} else if len(e.verdicts) > 0 {
		v = e.verdicts[0]
		e.verdicts = e.verdicts[1:]
	}
	v.SessionID = sid
	return v
}

// responseVerdictFor returns the response verdict to send for session sid: the
// next queued response verdict, or ACCEPT. The session id is always echoed from
// the RESPONSE_CODE frame.
func (e *Engine) responseVerdictFor(sid uint32) protocol.Verdict {
	e.mu.Lock()
	defer e.mu.Unlock()
	v := protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: sid}
	if len(e.responseVerdicts) > 0 {
		v = e.responseVerdicts[0]
		e.responseVerdicts = e.responseVerdicts[1:]
	}
	v.SessionID = sid
	return v
}
