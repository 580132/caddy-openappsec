//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	originBody = "hello from origin"
	blockBody  = "This request was blocked by the mock open-appsec engine."
	injectTag  = "<mock-inject>"
	requestWin = 10 * time.Second
)

// TestMain builds both subprocess binaries (cmd/mockengine, cmd/caddy) once
// before the suite runs, and cleans up the shared build dir afterwards.
func TestMain(m *testing.M) {
	if err := buildBinaries(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: failed to build binaries: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	if buildDirPath != "" {
		_ = os.RemoveAll(buildDirPath)
	}
	os.Exit(code)
}

// TestE2EAllow verifies the allow scenario: the engine ACCEPTs every request,
// so a GET passes through to the origin with its body intact. The engine's
// own log must show the REQUEST_START frame, proving the request was actually
// inspected across the process boundary.
func TestE2EAllow(t *testing.T) {
	eng := startMockEngine(t, "allow", 0)
	caddy := startCaddy(t, eng.addr, `respond "hello from origin"`)

	resp, body := getWithRetry(t, caddy.URL(), requestWin)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", resp.StatusCode, body)
	}
	if got := string(body); !strings.Contains(got, originBody) {
		t.Fatalf("body = %q, want it to contain %q (origin pass-through)", got, originBody)
	}
	waitForOutputSubstr(t, eng.p, "REQUEST_START", 5*time.Second)
}

// TestE2EBlock verifies the block scenario: the engine DROPs every request
// with a custom web response. The handler must synthesize a 403 whose body is
// the mock's custom block text, and the origin must never be reached.
func TestE2EBlock(t *testing.T) {
	eng := startMockEngine(t, "block", 0)
	caddy := startCaddy(t, eng.addr, `respond "hello from origin"`)

	resp, body := getWithRetry(t, caddy.URL(), requestWin)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), blockBody) {
		t.Fatalf("block page = %q, want it to contain %q (mock web response body)", body, blockBody)
	}
	if strings.Contains(string(body), originBody) {
		t.Fatalf("block page = %q, must not contain the origin body", body)
	}
}

// TestE2EInject verifies the inject scenario: the engine replies INJECT with
// a body modification. The handler applies the injection to the buffered
// request body and forwards it. The origin here echoes the (modified) request
// body back via the `{http.request.body}` placeholder — a core static_response
// feature, so no extra modules are needed in the thin caddy build — making the
// injected payload observable in the response the client receives.
func TestE2EInject(t *testing.T) {
	eng := startMockEngine(t, "inject", 0)
	caddy := startCaddy(t, eng.addr, `respond "{http.request.body}"`)

	resp, body := getWithRetry(t, caddy.URL(), requestWin)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (injected requests pass through); body: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), injectTag) {
		t.Fatalf("response body = %q, want it to contain %q (injection applied and echoed by the origin)", body, injectTag)
	}
}

// TestE2EFlaky verifies the flaky scenario: the engine closes each connection
// after one request frame, forcing the app's pool to reconnect on the next
// send. Fail-open tolerates the transient drop, so within a bounded window the
// requests pass through. Only the final request is asserted, so a transient
// connection-level hiccup cannot flake the test; the earlier requests only
// need to terminate (each is bounded by its own per-request timeout).
func TestE2EFlaky(t *testing.T) {
	eng := startMockEngine(t, "flaky", 1)
	caddy := startCaddy(t, eng.addr, `respond "hello from origin"`)

	var lastResp *http.Response
	var lastBody []byte
	for i := 0; i < 5; i++ {
		lastResp, lastBody = getWithRetry(t, caddy.URL(), requestWin)
		time.Sleep(150 * time.Millisecond)
	}
	if lastResp.StatusCode != http.StatusOK {
		t.Fatalf("final request: status = %d, want 200; body: %s", lastResp.StatusCode, lastBody)
	}
	if !strings.Contains(string(lastBody), originBody) {
		t.Fatalf("final request: body = %q, want pass-through", lastBody)
	}
}

// TestE2EDown verifies the down scenario: the engine completes the handshake
// but never replies to requests. The fail-open verdict budget (15 verdict
// polls x req_max_processing_ms 300 = ~4.5s) expires and the request passes
// through to the origin. The short timeouts keep the budget bounded; the 10s
// request window absorbs the first (slow) request.
func TestE2EDown(t *testing.T) {
	eng := startMockEngine(t, "down", 0)
	caddy := startCaddy(t, eng.addr,
		`respond "hello from origin"`,
		"fail_open_timeout_ms 500",
		"req_max_processing_ms 300",
	)

	resp, body := getWithRetry(t, caddy.URL(), requestWin)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open); body: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), originBody) {
		t.Fatalf("body = %q, want pass-through", body)
	}
}
