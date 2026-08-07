package mock

import (
	"context"

	"github.com/580132/caddy-openappsec/internal/protocol"
	"github.com/580132/caddy-openappsec/internal/transport"
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
	case frameResponse:
		st.phase = 2
		e.responseFrame(c, b, st, desc)
	default:
		e.record(b, desc, false)
	}
}

// requestFrame records a request-family frame. REQUEST_START applies the
// flaky budget and replies with the scripted verdict; REQUEST_END produces the
// same verdict again (the real engine emits its terminal verdict at
// end_request, so the attachment's final wait resolves on REQUEST_END).
func (e *Engine) requestFrame(c transport.EngineConn, b []byte, st *connState, desc string) {
	_, sid, isStart, _ := parseRequest(b)
	isEnd := isRequestEnd(b)
	e.record(b, desc, isStart)
	if !isStart && !isEnd {
		return
	}

	e.mu.Lock()
	flaky := e.flaky
	reply := e.replyEnabled
	e.mu.Unlock()

	if flaky > 0 && isStart {
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

// responseFrame records a response-family frame. RESPONSE_CODE additionally
// tallies the response counter and replies with the scripted response verdict
// unless verdict replies are disabled.
func (e *Engine) responseFrame(c transport.EngineConn, b []byte, st *connState, desc string) {
	_, sid, _, _ := parseRequest(b)
	e.record(b, desc, false)
	if !isResponseCode(b) {
		return
	}

	e.mu.Lock()
	e.responses++
	reply := e.replyEnabled
	e.mu.Unlock()

	if reply {
		v := e.responseVerdictFor(sid)
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
	frameResponse
)
