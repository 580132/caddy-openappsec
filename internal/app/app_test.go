package app

import (
	"context"
	"testing"

	"github.com/580132/caddy-openappsec/internal/protocol"
	"github.com/caddyserver/caddy/v2"
)

// Test_App_CaddyModule_returns_openappsec_namespace verifies the module ID and
// that New returns a fresh instance.
func Test_App_CaddyModule_returns_openappsec_namespace(t *testing.T) {
	// When
	mi := (App{}).CaddyModule()

	// Then
	if mi.ID != "http.openappsec" {
		t.Fatalf("module id = %q, want %q", mi.ID, "http.openappsec")
	}
	if mi.New == nil {
		t.Fatal("New constructor is nil")
	}
	inst := mi.New()
	if _, ok := inst.(*App); !ok {
		t.Fatalf("New returned %T, want *App", inst)
	}
}

// Test_App_Start_Stop_releases_connection verifies the lifecycle: Provision
// builds the policy, Start acquires a connection to the engine, and Stop
// releases it so the pool is empty afterwards.
func Test_App_Start_Stop_releases_connection(t *testing.T) {
	// Given a provisioned app against a live engine
	cfg := testConfig(t, "app.sock")
	f := newFakeEngine(t, cfg)
	defer f.close()

	app := App{Config: cfg}
	app.pool = NewPool(cfg, &memoryDialer{cfg: cfg}) // test seam: bypass the global pool
	requireNoError(t, app.Provision(caddy.Context{}))

	// When Start and Stop run
	requireNoError(t, app.Start())
	if len(app.pool.entries) != 1 {
		t.Fatalf("pool entries after Start = %d, want 1", len(app.pool.entries))
	}
	requireNoError(t, app.Stop())

	// Then the pool is empty (connection released and closed)
	if len(app.pool.entries) != 0 {
		t.Fatalf("pool entries after Stop = %d, want 0", len(app.pool.entries))
	}
}

// Test_App_policy_acquires_verdict_through_the_app verifies the app's policy
// surface answers verdicts end to end.
func Test_App_policy_acquires_verdict_through_the_app(t *testing.T) {
	// Given a provisioned app whose engine accepts the request
	cfg := testConfig(t, "app-verdict.sock")
	f := newFakeEngine(t, cfg)
	f.reply = func(sid uint32) *protocol.Verdict {
		return &protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: sid}
	}
	defer f.close()

	app := App{Config: cfg}
	app.pool = NewPool(cfg, &memoryDialer{cfg: cfg}) // test seam: bypass the global pool
	requireNoError(t, app.Provision(caddy.Context{}))
	defer app.Stop()

	// When a verdict is acquired through the app
	v, err := app.policy.AcquireVerdict(context.Background(), RequestData{
		Start: protocol.RequestStart{HTTPProtocol: "HTTP/1.1"},
	})
	requireNoError(t, err)

	// Then the engine verdict comes back
	if v.Kind != protocol.VerdictAccept {
		t.Fatalf("verdict kind = %v, want ACCEPT", v.Kind)
	}
}
