package app

import (
	"context"
	"testing"
	"time"

	"github.com/580132/caddy-openappsec/internal/protocol"
)

// verdictBudget is the total time AcquireVerdict waits on the engine before
// failing open: MaxRetriesForVerdict polls of ReqMaxProcessingMs each
// (defaults 20 x 150ms = 3s).
func Test_verdictBudget(t *testing.T) {
	cfg := testConfig(t, "budget.sock")
	cfg.ReqMaxProcessingMs = 30
	cfg.MaxRetriesForVerdict = 2
	if got := verdictBudget(cfg); got != 60*time.Millisecond {
		t.Fatalf("verdictBudget = %v, want 60ms", got)
	}
}

// Test_FailOpen_returns_accept_when_engine_silent verifies the fail-open
// default (FailOpen unset): when the engine never replies, AcquireVerdict
// waits the full budget and then returns an ACCEPT verdict instead of an
// error, so traffic passes.
func Test_FailOpen_returns_accept_when_engine_silent(t *testing.T) {
	// Given a silent engine and the default (nil) fail-open setting
	cfg := testConfig(t, "policy-silent.sock")
	cfg.ReqMaxProcessingMs = 30
	cfg.MaxRetriesForVerdict = 2
	f := newFakeEngine(t, cfg)
	defer f.close()
	pol := NewFailOpenPolicy(cfg, NewPool(cfg, &memoryDialer{cfg: cfg}))

	// When a request waits for a verdict that never comes
	start := time.Now()
	v, err := pol.AcquireVerdict(context.Background(), RequestData{
		Start: protocol.RequestStart{HTTPProtocol: "HTTP/1.1"},
	})
	requireNoError(t, err)

	// Then it fails open with an ACCEPT verdict after the full budget
	if v.Kind != protocol.VerdictAccept {
		t.Fatalf("fail-open verdict kind = %v, want ACCEPT", v.Kind)
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Fatalf("failed open too early (%v), did not wait the 60ms budget", elapsed)
	}
}

// Test_FailOpen_disabled_returns_error_when_engine_silent verifies an
// explicit false survives: the engine silence surfaces as an error.
func Test_FailOpen_disabled_returns_error_when_engine_silent(t *testing.T) {
	// Given a silent engine and fail-open explicitly disabled
	cfg := testConfig(t, "policy-closed.sock")
	cfg.ReqMaxProcessingMs = 30
	cfg.MaxRetriesForVerdict = 2
	cfg.FailOpen = boolPtr(false)
	f := newFakeEngine(t, cfg)
	defer f.close()
	pol := NewFailOpenPolicy(cfg, NewPool(cfg, &memoryDialer{cfg: cfg}))

	// When/Then
	_, err := pol.AcquireVerdict(context.Background(), RequestData{
		Start: protocol.RequestStart{HTTPProtocol: "HTTP/1.1"},
	})
	requireError(t, err, "deadline exceeded")
}

// Test_AcquireVerdict_returns_engine_verdict verifies the happy path: the
// engine's DROP verdict is returned with a live session id.
func Test_AcquireVerdict_returns_engine_verdict(t *testing.T) {
	// Given an engine that drops the request
	cfg := testConfig(t, "policy-drop.sock")
	f := newFakeEngine(t, cfg)
	f.reply = func(sid uint32) *protocol.Verdict {
		return &protocol.Verdict{
			Kind:      protocol.VerdictDrop,
			SessionID: sid,
			WebResponse: &protocol.WebResponse{
				Type:       protocol.WebResponseCustom,
				StatusCode: 403,
				Title:      "Blocked",
				Body:       "denied",
			},
		}
	}
	defer f.close()
	pol := NewFailOpenPolicy(cfg, NewPool(cfg, &memoryDialer{cfg: cfg}))

	// When
	v, err := pol.AcquireVerdict(context.Background(), RequestData{
		Start: protocol.RequestStart{HTTPProtocol: "HTTP/1.1", Method: "GET", Host: "example.com"},
	})
	requireNoError(t, err)

	// Then the engine verdict is returned as-is
	if v.Kind != protocol.VerdictDrop {
		t.Fatalf("verdict kind = %v, want DROP", v.Kind)
	}
	if v.SessionID == 0 {
		t.Fatal("verdict has no session id")
	}
	if v.WebResponse == nil || v.WebResponse.StatusCode != 403 {
		t.Fatalf("verdict web response = %+v, want status 403", v.WebResponse)
	}
}

// Test_AcquireVerdict_handles_delayed_verdict verifies the delayed-hold:
// after a REQUEST_DELAYED_VERDICT frame the policy holds for
// HoldVerdictRetries x HoldVerdictPollingMs and then collects the verdict.
func Test_AcquireVerdict_handles_delayed_verdict(t *testing.T) {
	// Given an engine that announces a delayed verdict before deciding
	cfg := testConfig(t, "policy-delayed.sock")
	f := newFakeEngine(t, cfg)
	f.delayed = true
	f.reply = func(sid uint32) *protocol.Verdict {
		return &protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: sid}
	}
	defer f.close()
	pol := NewFailOpenPolicy(cfg, NewPool(cfg, &memoryDialer{cfg: cfg}))

	// When/Then
	v, err := pol.AcquireVerdict(context.Background(), RequestData{
		Start: protocol.RequestStart{HTTPProtocol: "HTTP/1.1"},
	})
	requireNoError(t, err)
	if v.Kind != protocol.VerdictAccept {
		t.Fatalf("verdict kind = %v, want ACCEPT", v.Kind)
	}
}

// Test_AcquireVerdict_releases_pool_entry verifies the policy does not leak
// pool references: after a verdict the shared connection is released.
func Test_AcquireVerdict_releases_pool_entry(t *testing.T) {
	// Given
	cfg := testConfig(t, "policy-release.sock")
	f := newFakeEngine(t, cfg)
	f.reply = func(sid uint32) *protocol.Verdict {
		return &protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: sid}
	}
	defer f.close()
	p := NewPool(cfg, &memoryDialer{cfg: cfg})
	pol := NewFailOpenPolicy(cfg, p)

	// When
	_, err := pol.AcquireVerdict(context.Background(), RequestData{
		Start: protocol.RequestStart{HTTPProtocol: "HTTP/1.1"},
	})
	requireNoError(t, err)

	// Then the pool entry is gone (conn closed, refcount zero)
	if len(p.entries) != 0 {
		t.Fatalf("pool entry leaked after AcquireVerdict: %d entries", len(p.entries))
	}
}

// Test_FailOpen_accepts_when_engine_unreachable verifies fail-open also
// applies when the engine cannot even be dialed.
func Test_FailOpen_accepts_when_engine_unreachable(t *testing.T) {
	// Given no engine at all
	cfg := testConfig(t, "policy-dead.sock")
	pol := NewFailOpenPolicy(cfg, NewPool(cfg, &memoryDialer{cfg: cfg}))

	// When/Then
	v, err := pol.AcquireVerdict(context.Background(), RequestData{
		Start: protocol.RequestStart{HTTPProtocol: "HTTP/1.1"},
	})
	requireNoError(t, err)
	if v.Kind != protocol.VerdictAccept {
		t.Fatalf("verdict kind = %v, want ACCEPT", v.Kind)
	}
}
