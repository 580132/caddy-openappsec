package mock

import (
	"testing"

	"github.com/580132/caddy-openappsec/internal/protocol"
)

// Test_Engine_Verdict_Accept_byte_exact verifies an ACCEPT scripted verdict
// is echoed byte-exact with the request's session id.
func Test_Engine_Verdict_Accept_byte_exact(t *testing.T) {
	// Given
	const addr = "mock-accept"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()
	eng.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})
	c := dial(t, addr)
	c.handshake("caddy")

	// When
	const sid = uint32(3)
	c.send(protocol.RequestStart{SessionID: sid, Method: "GET", UnparsedURI: "/hello", Host: "example.com"}.Encode())
	got := c.recv()

	// Then
	want := (&protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: sid}).Encode()
	mustEqualBytes(t, want, got, "accept verdict")
}

// Test_Engine_Verdict_Drop_byte_exact verifies a DROP scripted verdict
// carrying a custom 403 web response is echoed byte-exact.
func Test_Engine_Verdict_Drop_byte_exact(t *testing.T) {
	// Given
	const addr = "mock-drop"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()
	scripted := protocol.Verdict{
		Kind: protocol.VerdictDrop,
		WebResponse: &protocol.WebResponse{
			Type:       protocol.WebResponseCustom,
			StatusCode: 403,
			Title:      "Blocked",
			Body:       "Access denied by mock engine.",
		},
	}
	eng.SetNextVerdict(scripted)
	c := dial(t, addr)
	c.handshake("caddy")

	// When
	const sid = uint32(5)
	c.send(protocol.RequestStart{SessionID: sid, Method: "POST", UnparsedURI: "/admin"}.Encode())
	got := c.recv()

	// Then
	want := (&protocol.Verdict{Kind: protocol.VerdictDrop, SessionID: sid, WebResponse: scripted.WebResponse}).Encode()
	mustEqualBytes(t, want, got, "drop verdict")
}

// Test_Engine_Verdict_Inject_byte_exact verifies an INJECT scripted verdict
// with a body modification is echoed byte-exact.
func Test_Engine_Verdict_Inject_byte_exact(t *testing.T) {
	// Given
	const addr = "mock-inject"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()
	eng.SetNextVerdict(protocol.Verdict{
		Kind: protocol.VerdictInject,
		Injections: []protocol.Injection{
			{InjectionPos: protocol.InjectPosIrrelevant, ModType: protocol.ModInject, IsHeader: false, Data: []byte("<mock-inject>")},
		},
	})
	c := dial(t, addr)
	c.handshake("caddy")

	// When
	const sid = uint32(7)
	c.send(protocol.RequestStart{SessionID: sid, Method: "GET", UnparsedURI: "/"}.Encode())
	got := c.recv()

	// Then
	want := (&protocol.Verdict{
		Kind:      protocol.VerdictInject,
		SessionID: sid,
		Injections: []protocol.Injection{
			{InjectionPos: protocol.InjectPosIrrelevant, ModType: protocol.ModInject, IsHeader: false, Data: []byte("<mock-inject>")},
		},
	}).Encode()
	mustEqualBytes(t, want, got, "inject verdict")
}

// Test_Engine_Verdict_Queue_FIFO verifies scripted verdicts are popped in
// FIFO order and each reply echoes its own request's session id.
func Test_Engine_Verdict_Queue_FIFO(t *testing.T) {
	// Given
	const addr = "mock-fifo"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()
	eng.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})
	eng.SetNextVerdict(protocol.Verdict{Kind: protocol.VerdictDrop, WebResponse: &protocol.WebResponse{Type: protocol.WebResponseCodeOnly, StatusCode: 403}})
	c := dial(t, addr)
	c.handshake("caddy")

	// When
	c.send(protocol.RequestStart{SessionID: 11, Method: "GET"}.Encode())
	first := c.recv()
	c.send(protocol.RequestStart{SessionID: 13, Method: "GET"}.Encode())
	second := c.recv()

	// Then
	mustEqualBytes(t, (&protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: 11}).Encode(), first, "first verdict")
	mustEqualBytes(t, (&protocol.Verdict{Kind: protocol.VerdictDrop, SessionID: 13, WebResponse: &protocol.WebResponse{Type: protocol.WebResponseCodeOnly, StatusCode: 403}}).Encode(), second, "second verdict")
}

// Test_Engine_Verdict_Default_Accept verifies an empty script queue yields an
// ACCEPT verdict.
func Test_Engine_Verdict_Default_Accept(t *testing.T) {
	// Given
	const addr = "mock-default"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()
	c := dial(t, addr)
	c.handshake("caddy")

	// When
	const sid = uint32(3)
	c.send(protocol.RequestStart{SessionID: sid, Method: "GET"}.Encode())
	got := c.recv()

	// Then
	mustEqualBytes(t, (&protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: sid}).Encode(), got, "default verdict")
}
