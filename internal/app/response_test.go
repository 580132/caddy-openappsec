package app

import (
	"context"
	"testing"
	"time"

	"github.com/580132/caddy-openappsec/internal/protocol"
)

// Test_Conn_SendResponse_roundtrips verifies SendResponse + SendResponseBody
// deliver the response frames to the engine and the response verdict is
// returned with a live session id.
func Test_Conn_SendResponse_roundtrips(t *testing.T) {
	// Given a fake engine that drops the response
	cfg := testConfig(t, "resp-roundtrip.sock")
	f := newFakeEngine(t, cfg)
	f.responseReply = func(sid uint32) *protocol.Verdict {
		return &protocol.Verdict{
			Kind:      protocol.VerdictDrop,
			SessionID: sid,
			WebResponse: &protocol.WebResponse{
				Type:       protocol.WebResponseCustom,
				StatusCode: 403,
				Title:      "Blocked",
				Body:       "response denied",
			},
		}
	}
	defer f.close()
	pol := NewFailOpenPolicy(cfg, NewPool(cfg, &memoryDialer{cfg: cfg}))

	// When a response is inspected
	v, err := pol.AcquireResponseVerdict(context.Background(), 200, 5, []byte("hello"))
	requireNoError(t, err)

	// Then the DROP verdict is returned with the response session id
	if v.Kind != protocol.VerdictDrop {
		t.Fatalf("response verdict kind = %v, want DROP", v.Kind)
	}
	if v.SessionID == 0 {
		t.Fatal("response verdict has no session id")
	}
	if v.WebResponse == nil || v.WebResponse.StatusCode != 403 {
		t.Fatalf("response verdict web response = %+v, want status 403", v.WebResponse)
	}
}

// Test_FailOpenResponse_returns_accept_when_engine_silent verifies the
// fail-open default (FailOpen unset): when the engine never replies to a
// response inspection, AcquireResponseVerdict waits the full budget and then
// returns an ACCEPT verdict, keeping the response.
func Test_FailOpenResponse_returns_accept_when_engine_silent(t *testing.T) {
	// Given a silent engine and the default (nil) fail-open setting
	cfg := testConfig(t, "resp-silent.sock")
	cfg.ReqMaxProcessingMs = 30
	cfg.MaxRetriesForVerdict = 2
	f := newFakeEngine(t, cfg)
	defer f.close()
	pol := NewFailOpenPolicy(cfg, NewPool(cfg, &memoryDialer{cfg: cfg}))

	// When a response waits for a verdict that never comes
	start := time.Now()
	v, err := pol.AcquireResponseVerdict(context.Background(), 200, 0, nil)
	requireNoError(t, err)

	// Then it fails open with an ACCEPT verdict after the full budget
	if v.Kind != protocol.VerdictAccept {
		t.Fatalf("fail-open response verdict kind = %v, want ACCEPT", v.Kind)
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Fatalf("failed open too early (%v), did not wait the 60ms budget", elapsed)
	}
}

// Test_FailOpenResponse_disabled_returns_error_when_engine_silent verifies an
// explicit false survives: response-engine silence surfaces as an error.
func Test_FailOpenResponse_disabled_returns_error_when_engine_silent(t *testing.T) {
	// Given a silent engine and fail-open explicitly disabled
	cfg := testConfig(t, "resp-closed.sock")
	cfg.ReqMaxProcessingMs = 30
	cfg.MaxRetriesForVerdict = 2
	cfg.FailOpen = boolPtr(false)
	f := newFakeEngine(t, cfg)
	defer f.close()
	pol := NewFailOpenPolicy(cfg, NewPool(cfg, &memoryDialer{cfg: cfg}))

	// When/Then
	_, err := pol.AcquireResponseVerdict(context.Background(), 200, 0, nil)
	requireError(t, err, "deadline exceeded")
}

// Test_FailOpenResponse_accepts_when_engine_unreachable verifies fail-open
// also applies to the response path when the engine cannot even be dialed.
func Test_FailOpenResponse_accepts_when_engine_unreachable(t *testing.T) {
	// Given no engine at all
	cfg := testConfig(t, "resp-dead.sock")
	pol := NewFailOpenPolicy(cfg, NewPool(cfg, &memoryDialer{cfg: cfg}))

	// When/Then
	v, err := pol.AcquireResponseVerdict(context.Background(), 200, 0, nil)
	requireNoError(t, err)
	if v.Kind != protocol.VerdictAccept {
		t.Fatalf("verdict kind = %v, want ACCEPT", v.Kind)
	}
}
