package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/580132/caddy-openappsec/internal/app"
	"github.com/580132/caddy-openappsec/internal/config"
	"github.com/580132/caddy-openappsec/internal/mock"
	"github.com/580132/caddy-openappsec/internal/protocol"
	"github.com/580132/caddy-openappsec/internal/transport"
	"github.com/580132/caddy-openappsec/internal/transport/memory"
)

// boolPtr returns a pointer to b for exercising the fail-open tri-state.
func boolPtr(b bool) *bool { return &b }

// fixtureCounter yields unique engine addresses so parallel tests never share
// a memory-transport listener.
var fixtureCounter atomic.Uint64

// fixture wires a scriptable mock engine, a fresh (non-global) app pool with
// an in-memory dialer, and a Handler whose acquirer is the app fail-open
// policy — the same surface Provision builds, minus the caddy context.
type fixture struct {
	t       *testing.T
	engine  *mock.Engine
	handler *Handler
	pool    *app.Pool
}

// fixtureOpt mutates the engine config and handler before wiring, so tests
// can override fail-open posture before the policy snapshot is taken.
type fixtureOpt func(cfg *config.EngineConfig, h *Handler)

// failClosed makes both the engine policy and the handler reject when the
// engine is unavailable (fail_open: false).
func failClosed(cfg *config.EngineConfig, h *Handler) {
	cfg.FailOpen = boolPtr(false)
	h.FailOpen = boolPtr(false)
}

func newFixture(t *testing.T, opts ...fixtureOpt) *fixture {
	t.Helper()
	addr := fmt.Sprintf("handler-%d", fixtureCounter.Add(1))
	eng, err := mock.New(addr)
	if err != nil {
		t.Fatalf("mock.New(%q): %v", addr, err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	cfg := testEngineConfig(t, addr)
	h := &Handler{
		Engine:   cfg,
		logger:   zap.NewNop(),
		acquirer: nil, // set below after opts
	}
	for _, o := range opts {
		o(&cfg, h)
	}
	h.SetDefaults()
	h.ResponseBufferLimit = 64 * 1024
	h.BodyBufferLimit = 1024 * 1024

	pool := app.NewPool(cfg, &memoryDialer{cfg: cfg})
	t.Cleanup(pool.Close)
	h.acquirer = app.NewFailOpenPolicy(cfg, pool)

	return &fixture{t: t, engine: eng, handler: h, pool: pool}
}

// testEngineConfig returns an engine config with small, test-friendly
// timings and a keep-alive interval long enough that it never fires.
func testEngineConfig(t *testing.T, addr string) config.EngineConfig {
	t.Helper()
	return config.EngineConfig{
		RegistrationSocket:    addr,
		KeepAlivePath:         addr + "-keepalive",
		VerdictSignalPath:     "/dev/shm/test/" + addr + "/verdict",
		FamilyName:            "test-container",
		WorkerID:              0,
		Workers:               1,
		AttachmentType:        "nginx",
		KeepAliveIntervalMs:   60000,
		RegistrationTimeoutMs: 100,
		ReconnectBackoffMinMs: 5,
		ReconnectBackoffMaxMs: 50,
		FailOpenTimeoutMs:     5,
		FailOpenHoldTimeoutMs: 25,
		ReqMaxProcessingMs:    150,
		MinRetriesForVerdict:  1,
		MaxRetriesForVerdict:  3,
		HoldVerdictRetries:    1,
		HoldVerdictPollingMs:  1,
	}
}

// serve drives the handler over httptest, failing on an unexpected error.
func (fx *fixture) serve(r *http.Request, next caddyhttp.Handler) *httptest.ResponseRecorder {
	fx.t.Helper()
	w := httptest.NewRecorder()
	if err := fx.handler.ServeHTTP(w, r, next); err != nil {
		fx.t.Fatalf("ServeHTTP returned error: %v", err)
	}
	return w
}

// memoryDialer is the attachment-side client dialer over the in-memory
// transport. It mirrors internal/app's unexported memoryDialer exactly:
// dial the registration socket, run phase 1 (§G.1), close it, then dial the
// returned verdict-signal path for phase 2 (§G.2) and return the handshaked
// connection. It exists so the handler tests can wire the mock engine
// through the app's public pool surface.
type memoryDialer struct {
	cfg config.EngineConfig
}

func (d *memoryDialer) Dial(ctx context.Context) (transport.EngineConn, error) {
	conn, err := memory.Dial(d.cfg.RegistrationSocket)
	if err != nil {
		return nil, err
	}
	reg := protocol.Registration{
		AttachmentType: 0,
		WorkerID:       uint8(d.cfg.WorkerID) + 1,
		WorkersAmount:  uint8(d.cfg.Workers),
		FamilyName:     d.cfg.FamilyName,
	}
	if err := conn.Send(ctx, reg.Encode()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	reply, err := conn.Recv(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	path, err := protocol.ParseRegistrationReply(reply)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	// §G.1 one-shot: the registration connection is closed after the reply.
	if err := conn.Close(); err != nil {
		return nil, err
	}
	comm, err := memory.Dial(path.Path)
	if err != nil {
		return nil, err
	}
	if err := comm.Send(ctx, (protocol.CommData{UID: d.cfg.FamilyName, TargetCore: -1}).Encode()); err != nil {
		_ = comm.Close()
		return nil, err
	}
	ack, err := comm.Recv(ctx)
	if err != nil {
		_ = comm.Close()
		return nil, err
	}
	if len(ack) == 0 {
		_ = comm.Close()
		return nil, fmt.Errorf("memoryDialer: empty comm ack")
	}
	return comm, nil
}

func (d *memoryDialer) DialKeepAlive(ctx context.Context) (transport.EngineConn, error) {
	return memory.Dial(d.cfg.KeepAlivePath)
}

// echoNext is a stub origin handler that echoes the request body back as the
// response body.
func echoNext(called *bool) caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if called != nil {
			*called = true
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(b)
		return err
	})
}

// Test_Handler_CaddyModule_returns_openappsec_namespace verifies the module
// ID and that New returns a fresh instance.
func Test_Handler_CaddyModule_returns_openappsec_namespace(t *testing.T) {
	// When
	mi := (Handler{}).CaddyModule()

	// Then
	if mi.ID != "http.handlers.openappsec" {
		t.Fatalf("module id = %q, want %q", mi.ID, "http.handlers.openappsec")
	}
	if mi.New == nil {
		t.Fatal("New constructor is nil")
	}
	inst := mi.New()
	if _, ok := inst.(*Handler); !ok {
		t.Fatalf("New returned %T, want *Handler", inst)
	}
}

// Test_Handler_Allow_forwards_with_body_intact verifies an ACCEPT verdict
// forwards to next and the original request body reaches the origin intact.
func Test_Handler_Allow_forwards_with_body_intact(t *testing.T) {
	// Given an engine that accepts and a stub origin that echoes the body
	fx := newFixture(t)
	fx.engine.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})

	var nextCalled bool
	body := "hello upstream body"

	// When the request flows through the handler
	req := httptest.NewRequest(http.MethodPost, "/submit?q=1", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	w := fx.serve(req, echoNext(&nextCalled))

	// Then next ran and the origin saw the exact request body
	if !nextCalled {
		t.Fatal("next handler was not called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Body.String(); got != body {
		t.Fatalf("origin received body %q, want %q", got, body)
	}
}

// Test_Handler_Block_returns_403_without_calling_next verifies a DROP verdict
// synthesizes the block response from the verdict's web response and next is
// never invoked.
func Test_Handler_Block_returns_403_without_calling_next(t *testing.T) {
	// Given a DROP verdict carrying a custom 403 web response
	fx := newFixture(t)
	fx.engine.SetNextVerdict(protocol.Verdict{
		Kind: protocol.VerdictDrop,
		WebResponse: &protocol.WebResponse{
			Type:       protocol.WebResponseCustom,
			StatusCode: 403,
			Title:      "Blocked",
			Body:       "request denied by policy",
		},
	})
	var nextCalled bool
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	})

	// When the request flows through the handler
	req := httptest.NewRequest(http.MethodGet, "/forbidden", nil)
	w := fx.serve(req, next)

	// Then a block response is synthesized and next is not called
	if nextCalled {
		t.Fatal("next handler was called on a blocked request")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html (synthesized, not on the wire)", ct)
	}
	if !strings.Contains(w.Body.String(), "Blocked") {
		t.Fatalf("block page missing title, got: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "request denied by policy") {
		t.Fatalf("block page missing body, got: %s", w.Body.String())
	}
}

// Test_Handler_Block_config_page_overrides_verdict verifies that when the
// verdict carries no web response fields, the configured block page and
// status are used.
func Test_Handler_Block_config_page_overrides_verdict(t *testing.T) {
	fx := newFixture(t)
	fx.handler.BlockStatusCode = 418
	fx.handler.BlockPageTitle = "Custom Title"
	fx.handler.BlockPageBody = "Custom body text"
	fx.engine.SetNextVerdict(protocol.Verdict{
		Kind:        protocol.VerdictDrop,
		WebResponse: &protocol.WebResponse{Type: protocol.WebResponseCodeOnly, StatusCode: 403},
	})
	var nextCalled bool
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := fx.serve(req, next)

	if nextCalled {
		t.Fatal("next handler was called on a blocked request")
	}
	if w.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418 from config", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Custom Title") || !strings.Contains(w.Body.String(), "Custom body text") {
		t.Fatalf("block page did not use config values, got: %s", w.Body.String())
	}
}

// Test_Handler_LearnMode_DROP_forwards verifies that in learn mode a DROP
// verdict is logged and the request is forwarded instead of blocked.
func Test_Handler_LearnMode_DROP_forwards(t *testing.T) {
	fx := newFixture(t)
	fx.handler.Mode = config.ModeLearn
	fx.engine.SetNextVerdict(protocol.Verdict{
		Kind:        protocol.VerdictDrop,
		WebResponse: &protocol.WebResponse{Type: protocol.WebResponseCodeOnly, StatusCode: 403},
	})
	var nextCalled bool
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("learned through"))
		return err
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := fx.serve(req, next)

	if !nextCalled {
		t.Fatal("next handler was not called in learn mode")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (learn mode forwards)", w.Code)
	}
	if got := w.Body.String(); got != "learned through" {
		t.Fatalf("body = %q, want origin response", got)
	}
}

// Test_Handler_EngineDown_fails_open verifies that an unreachable engine
// degrades to allow-through (next runs) by default.
func Test_Handler_EngineDown_fails_open(t *testing.T) {
	fx := newFixture(t)
	if err := fx.engine.SetEngineDown(); err != nil {
		t.Fatalf("SetEngineDown: %v", err)
	}
	var nextCalled bool
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("ok"))
		return err
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := fx.serve(req, next)

	if !nextCalled {
		t.Fatal("next handler was not called when the engine was down")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open)", w.Code)
	}
}

// Test_Handler_EngineDown_fails_closed verifies that with fail_open
// explicitly false, an unreachable engine yields 502 and next is not called.
func Test_Handler_EngineDown_fails_closed(t *testing.T) {
	fx := newFixture(t, failClosed)
	if err := fx.engine.SetEngineDown(); err != nil {
		t.Fatalf("SetEngineDown: %v", err)
	}
	var nextCalled bool
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := fx.serve(req, next)

	if nextCalled {
		t.Fatal("next handler was called when fail-closed")
	}
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
}

// Test_Handler_GzipRequestBody_roundtrip verifies a gzip request body is
// decompressed for inspection and the ORIGINAL compressed bytes are restored
// for forwarding.
func Test_Handler_GzipRequestBody_roundtrip(t *testing.T) {
	fx := newFixture(t)
	fx.engine.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})

	payload := "compressed request payload"
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte(payload)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	var nextBody []byte
	var nextCalled bool
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		nextBody = b
		w.WriteHeader(http.StatusOK)
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(gz.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")
	w := fx.serve(req, next)

	// Then the origin received the original compressed bytes, byte for byte
	if !nextCalled {
		t.Fatal("next handler was not called")
	}
	if !bytes.Equal(nextBody, gz.Bytes()) {
		t.Fatalf("origin received %d bytes, want the original gzip body (%d bytes)", len(nextBody), len(gz.Bytes()))
	}
	zr, err := gzip.NewReader(bytes.NewReader(nextBody))
	if err != nil {
		t.Fatalf("origin body is not valid gzip: %v", err)
	}
	decoded, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip origin body: %v", err)
	}
	if string(decoded) != payload {
		t.Fatalf("gunzipped origin body = %q, want %q", decoded, payload)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

// Test_Handler_SSE_response_passthrough verifies text/event-stream responses
// stream through unmodified and unbuffered.
func Test_Handler_SSE_response_passthrough(t *testing.T) {
	fx := newFixture(t)
	fx.engine.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("response writer does not implement http.Flusher")
		}
		for i := 0; i < 3; i++ {
			if _, err := w.Write([]byte("data: event " + strconv.Itoa(i) + "\n\n")); err != nil {
				return err
			}
			fl.Flush()
		}
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	req.Header.Del("Accept-Encoding") // never recompress SSE
	w := fx.serve(req, next)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := strings.Count(w.Body.String(), "data: event"); got != 3 {
		t.Fatalf("received %d SSE events, want 3 (streamed unmodified)", got)
	}
	if enc := w.Header().Get("Content-Encoding"); enc != "" {
		t.Fatalf("Content-Encoding = %q, want identity for SSE passthrough", enc)
	}
}

// Test_Handler_Response_over_cap_passthrough verifies a response larger than
// the buffer cap streams through completely via the passthrough transition.
func Test_Handler_Response_over_cap_passthrough(t *testing.T) {
	fx := newFixture(t)
	fx.handler.ResponseBufferLimit = 32
	fx.engine.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})

	large := bytes.Repeat([]byte("x"), 1000)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(large)
		return err
	})

	req := httptest.NewRequest(http.MethodGet, "/big", nil)
	req.Header.Del("Accept-Encoding")
	w := fx.serve(req, next)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.Len() != len(large) {
		t.Fatalf("received %d bytes, want %d (full response past the cap)", w.Body.Len(), len(large))
	}
	if !bytes.Equal(w.Body.Bytes(), large) {
		t.Fatal("response body was corrupted by the passthrough transition")
	}
}

// Test_Handler_Response_recompressed_for_gzip_client verifies an identity
// response is recompressed for a client that accepts gzip.
func Test_Handler_Response_recompressed_for_gzip_client(t *testing.T) {
	fx := newFixture(t)
	fx.engine.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})

	payload := "hello response body"
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(payload))
		return err
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := fx.serve(req, next)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if enc := w.Header().Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", enc)
	}
	if cl := w.Header().Get("Content-Length"); cl != strconv.Itoa(w.Body.Len()) {
		t.Fatalf("Content-Length = %q, want %d", cl, w.Body.Len())
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatalf("response is not valid gzip: %v", err)
	}
	decoded, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip response: %v", err)
	}
	if string(decoded) != payload {
		t.Fatalf("gunzipped response = %q, want %q", decoded, payload)
	}
}

// Test_Handler_Inject_applies_header_modification verifies an INJECT verdict
// with a header modification reaches next on the request headers.
func Test_Handler_Inject_applies_header_modification(t *testing.T) {
	fx := newFixture(t)
	fx.engine.SetNextVerdict(protocol.Verdict{
		Kind: protocol.VerdictInject,
		Injections: []protocol.Injection{
			{InjectionPos: protocol.InjectPosIrrelevant, ModType: protocol.ModAppend, IsHeader: true, Data: []byte("X-Mock-Inject: yes")},
		},
	})

	var got string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		got = r.Header.Get("X-Mock-Inject")
		w.WriteHeader(http.StatusOK)
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := fx.serve(req, next)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got != "yes" {
		t.Fatalf("X-Mock-Inject = %q, want %q (injection applied to request)", got, "yes")
	}
}

// Test_Handler_Inject_applies_body_modification verifies an INJECT verdict
// with a body modification reaches next appended to the request body.
func Test_Handler_Inject_applies_body_modification(t *testing.T) {
	fx := newFixture(t)
	fx.engine.SetNextVerdict(protocol.Verdict{
		Kind: protocol.VerdictInject,
		Injections: []protocol.Injection{
			{InjectionPos: protocol.InjectPosIrrelevant, ModType: protocol.ModInject, IsHeader: false, Data: []byte("<injected>")},
		},
	})

	var got []byte
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		var err error
		got, err = io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		w.WriteHeader(http.StatusOK)
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("original body"))
	w := fx.serve(req, next)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !bytes.Contains(got, []byte("<injected>")) {
		t.Fatalf("origin body = %q, want it to contain the injected payload", got)
	}
	if !bytes.Contains(got, []byte("original body")) {
		t.Fatalf("origin body = %q, want it to contain the original body", got)
	}
}

// Test_Handler_RequestMetadata_sent_to_engine verifies the engine receives a
// REQUEST_START frame carrying the request's method, URI, and host.
func Test_Handler_RequestMetadata_sent_to_engine(t *testing.T) {
	fx := newFixture(t)
	fx.engine.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/login?next=/dashboard", strings.NewReader("x=1"))
	req.Host = "app.example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := fx.serve(req, next)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if n := fx.engine.Requests(); n != 1 {
		t.Fatalf("engine received %d REQUEST_START frames, want 1", n)
	}
	frames := fx.engine.ReceivedFrames()
	var sawMetadata bool
	for _, f := range frames {
		if strings.Contains(f.Meaning, "method=\"POST\"") &&
			strings.Contains(f.Meaning, "uri=\"/login?next=/dashboard\"") &&
			strings.Contains(f.Meaning, "host=\"app.example.com\"") {
			sawMetadata = true
		}
	}
	if !sawMetadata {
		t.Fatalf("no REQUEST_START with the expected metadata among frames: %v", frames)
	}
}

// Test_Handler_Provision_fails_open_when_engine_unreachable verifies
// Provision tolerates an unreachable engine when fail-open is the default.
func Test_Handler_Provision_fails_open_when_engine_unreachable(t *testing.T) {
	// Given a handler pointed at an address with no engine listening
	h := &Handler{Engine: testEngineConfig(t, "handler-no-engine")}
	h.SetDefaults()
	h.ResponseBufferLimit = 1024
	h.BodyBufferLimit = 1024

	// When Provision runs (the engine cannot be reached)
	err := h.Provision(caddy.Context{})

	// Then provisioning succeeds (requests will fail open)
	if err != nil {
		t.Fatalf("Provision = %v, want nil (fail-open tolerates an unreachable engine)", err)
	}
	if h.acquirer == nil {
		t.Fatal("Provision did not build a VerdictAcquirer")
	}
	if h.pool == nil {
		t.Fatal("Provision did not keep the shared pool reference")
	}
	_ = h.Cleanup()
}

// Test_Handler_Provision_fails_closed_when_engine_unreachable verifies
// Provision fails when fail_open is explicitly disabled and the engine is
// unreachable.
func Test_Handler_Provision_fails_closed_when_engine_unreachable(t *testing.T) {
	// Given a fail-closed handler pointed at an address with no engine
	h := &Handler{Engine: testEngineConfig(t, "handler-no-engine-2")}
	h.SetDefaults()
	h.ResponseBufferLimit = 1024
	h.BodyBufferLimit = 1024
	h.FailOpen = boolPtr(false)

	// When Provision runs
	err := h.Provision(caddy.Context{})

	// Then provisioning fails with an engine-unreachable error
	if err == nil {
		t.Fatal("Provision = nil, want an error (fail-closed requires the engine)")
	}
	if !strings.Contains(err.Error(), "engine") && !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("Provision error = %v, want an engine-unreachable explanation", err)
	}
	_ = h.Cleanup()
}
