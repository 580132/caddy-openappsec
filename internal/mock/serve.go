package mock

import (
	"context"

	"github.com/yourname/caddy-openappsec/internal/protocol"
	"github.com/yourname/caddy-openappsec/internal/transport"
)

// connState is the per-connection handler state. phase tracks the handshake
// progress: 0 = fresh, 1 = registration answered (comm expected next),
// 2 = handshaked (request traffic).
type connState struct {
	phase  int
	flakyN int // REQUEST_START frames seen on this connection
}

// handleConn serves one connection until it closes. Every frame is
// classified by classify; handshake frames are answered, request frames are
// recorded and (for REQUEST_START) answered with a scripted verdict.
func (e *Engine) handleConn(c transport.EngineConn) {
	defer func() {
		e.mu.Lock()
		delete(e.conns, c)
		e.mu.Unlock()
	}()

	st := &connState{}
	ctx := context.Background()
	for {
		b, err := c.Recv(ctx)
		if err != nil {
			return // closed by the peer or by SetEngineDown
		}
		e.dispatch(c, b, st)
	}
}

// dispatch classifies one frame and acts on it: handshake frames get their
// replies, request frames flow to requestFrame.
func (e *Engine) dispatch(c transport.EngineConn, b []byte, st *connState) {
	kind, desc := classify(b, st.phase)
	switch kind {
	case frameRegistration:
		st.phase = 1
		e.record(b, desc, false)
		e.send(c, protocol.RegistrationReply{Path: e.addr}.Encode())
	case frameComm:
		st.phase = 2
		e.record(b, desc, false)
		e.send(c, protocol.Ack{Value: 1}.Encode())
	case frameKeepAlive:
		st.phase = 2
		e.record(b, desc, false)
		e.send(c, protocol.Ack{Value: 1}.Encode())
	case frameRequest:
		st.phase = 2
		e.requestFrame(c, b, st, desc)
	default:
		e.record(b, desc, false)
	}
}

// requestFrame records a request-family frame. REQUEST_START additionally
// applies the flaky budget, then replies with the scripted verdict unless
// verdict replies are disabled.
func (e *Engine) requestFrame(c transport.EngineConn, b []byte, st *connState, desc string) {
	_, sid, isStart, _ := parseRequest(b)
	e.record(b, desc, isStart)
	if !isStart {
		return
	}

	e.mu.Lock()
	flaky := e.flaky
	reply := e.replyEnabled
	e.mu.Unlock()

	if flaky > 0 {
		st.flakyN++
		if st.flakyN >= flaky {
			_ = c.Close()
			return
		}
	}
	if reply {
		v := e.verdictFor(sid)
		e.send(c, v.Encode())
	}
}

// send delivers a reply, ignoring errors: a closed connection ends the
// handler loop on the next Recv.
func (e *Engine) send(c transport.EngineConn, b []byte) {
	_ = c.Send(context.Background(), b)
}

// frameKind identifies the classification of a received frame.
type frameKind int

const (
	frameUnknown frameKind = iota
	frameRegistration
	frameComm
	frameKeepAlive
	frameRequest
)
