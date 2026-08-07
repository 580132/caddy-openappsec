package app

import (
	"context"
	"time"

	"github.com/580132/caddy-openappsec/internal/config"
	"github.com/580132/caddy-openappsec/internal/protocol"
)

// VerdictAcquirer inspects one request and returns the engine's verdict or a
// fail-open default. It is the request-agnostic surface the HTTP handler wave
// calls; it owns connection lifecycle (Acquire/Release) and hides reconnects.
type VerdictAcquirer interface {
	AcquireVerdict(ctx context.Context, req RequestData) (*protocol.Verdict, error)
	// AcquireResponseVerdict inspects a fully-buffered response and returns
	// the engine's response verdict or a fail-open ACCEPT.
	AcquireResponseVerdict(ctx context.Context, code int, contentLength int64, body []byte) (*protocol.Verdict, error)
}

// FailOpenPolicy implements VerdictAcquirer with fail-open timing: it waits
// on the engine for the verdict budget and, if the engine is silent or
// unreachable, lets the request through (ACCEPT) unless FailOpen is explicitly
// disabled.
type FailOpenPolicy struct {
	cfg  config.EngineConfig
	pool *Pool
}

// NewFailOpenPolicy wraps pool with the fail-open decision surface.
func NewFailOpenPolicy(cfg config.EngineConfig, pool *Pool) *FailOpenPolicy {
	return &FailOpenPolicy{cfg: cfg, pool: pool}
}

// verdictBudget is the total time the policy waits on the engine for one
// verdict before failing open: MaxRetriesForVerdict polls of
// ReqMaxProcessingMs each (defaults 20 x 150ms = 3s).
func verdictBudget(cfg config.EngineConfig) time.Duration {
	budget := time.Duration(cfg.MaxRetriesForVerdict) * time.Duration(cfg.ReqMaxProcessingMs) * time.Millisecond
	if budget <= 0 {
		budget = 3 * time.Second
	}
	return budget
}

// failOpenEnabled reports whether engine failure should let traffic through.
// The tri-state FailOpen pointer defaults to true when unset.
func failOpenEnabled(cfg config.EngineConfig) bool {
	if cfg.FailOpen == nil {
		return true
	}
	return *cfg.FailOpen
}

// failOpen reports whether engine failure should let traffic through.
func (p *FailOpenPolicy) failOpen() bool {
	return failOpenEnabled(p.cfg)
}

// AcquireVerdict inspects req and returns the engine's verdict. If the engine
// cannot be reached or stays silent past the verdict budget, it returns an
// ACCEPT verdict (fail-open) unless explicitly disabled, in which case the
// underlying error is returned. A caller-cancelled context also produces the
// fail-open default when enabled.
func (p *FailOpenPolicy) AcquireVerdict(ctx context.Context, req RequestData) (*protocol.Verdict, error) {
	c, err := p.pool.Acquire(ctx, p.cfg.RegistrationSocket)
	if err != nil {
		if p.failOpen() {
			return p.failOpenVerdict(0), nil
		}
		return nil, err
	}
	defer p.pool.Release(p.cfg.RegistrationSocket)

	sid, err := c.SendRequest(ctx, req)
	if err != nil {
		if p.failOpen() {
			return p.failOpenVerdict(0), nil
		}
		return nil, err
	}
	defer c.EndRequest(sid)

	v, err := p.await(ctx, c, sid)
	if err != nil {
		if p.failOpen() {
			return p.failOpenVerdict(sid), nil
		}
		return nil, err
	}
	return v, nil
}

// failOpenVerdict lets the request through when the engine is unavailable.
func (p *FailOpenPolicy) failOpenVerdict(sid uint32) *protocol.Verdict {
	return &protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: sid}
}

// AcquireResponseVerdict inspects a fully-buffered response and returns the
// engine's response verdict. It mirrors AcquireVerdict's fail-open posture:
// if the engine cannot be reached or stays silent past the verdict budget, it
// returns an ACCEPT verdict (keep the response) unless explicitly disabled,
// in which case the underlying error is returned.
func (p *FailOpenPolicy) AcquireResponseVerdict(ctx context.Context, code int, contentLength int64, body []byte) (*protocol.Verdict, error) {
	c, err := p.pool.Acquire(ctx, p.cfg.RegistrationSocket)
	if err != nil {
		if p.failOpen() {
			return p.failOpenVerdict(0), nil
		}
		return nil, err
	}
	defer p.pool.Release(p.cfg.RegistrationSocket)

	sid, err := c.SendResponse(ctx, code, contentLength)
	if err != nil {
		if p.failOpen() {
			return p.failOpenVerdict(0), nil
		}
		return nil, err
	}
	defer c.EndRequest(sid)

	if err := c.SendResponseBody(ctx, sid, body, true); err != nil {
		if p.failOpen() {
			return p.failOpenVerdict(sid), nil
		}
		return nil, err
	}

	v, err := p.await(ctx, c, sid)
	if err != nil {
		if p.failOpen() {
			return p.failOpenVerdict(sid), nil
		}
		return nil, err
	}
	return v, nil
}

// await collects the final verdict for sid from the engine. The engine replies
// per chunk: intermediate frames (INSPECT) arrive after REQUEST_START/HEADER/
// BODY and are skipped, and the terminal verdict (ACCEPT, DROP,
// CUSTOM_RESPONSE, or IRRELEVANT) is the one produced at REQUEST_END
// (nginx_attachment.cc handleRequestFromQueue, waap_component_impl.cc
// respond(EndRequestEvent)). It polls until the verdict budget expires: a
// REQUEST_DELAYED_VERDICT frame holds for HoldVerdictRetries x
// HoldVerdictPollingMs before re-polling; unrelated frames are skipped at the
// FailOpenTimeoutMs poll interval. The fail-open decision belongs to the
// caller.
func (p *FailOpenPolicy) await(ctx context.Context, c *Conn, sid uint32) (*protocol.Verdict, error) {
	poll := time.Duration(p.cfg.FailOpenTimeoutMs) * time.Millisecond
	if poll <= 0 {
		poll = 50 * time.Millisecond
	}
	hold := time.Duration(p.cfg.HoldVerdictRetries) * time.Duration(p.cfg.HoldVerdictPollingMs) * time.Millisecond
	deadline := time.Now().Add(verdictBudget(p.cfg))

	for time.Now().Before(deadline) {
		waitCtx, cancel := context.WithDeadline(ctx, deadline)
		payload, err := c.recv(waitCtx)
		cancel()
		if err != nil {
			return nil, err
		}
		if v, err := protocol.ParseVerdict(payload); err == nil && v.SessionID == sid {
			// Skip intermediate INSPECT verdicts: the final decision is the
			// terminal kind produced at REQUEST_END.
			if v.Kind != protocol.VerdictInspect {
				return v, nil
			}
			continue
		}
		if d, err := protocol.ParseDelayedVerdict(payload); err == nil && d.SessionID == sid {
			time.Sleep(hold)
			continue
		}
		// Unrelated frame (another session, keep-alive echo): keep polling.
		time.Sleep(poll)
	}
	return nil, context.DeadlineExceeded
}
