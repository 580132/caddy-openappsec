package mock

import (
	"testing"

	"github.com/580132/caddy-openappsec/internal/protocol"
)

// Test_Engine_ResponseVerdict_Drop_byte_exact verifies a scripted response
// DROP verdict is echoed byte-exact with the response session id when a client
// submits response frames.
func Test_Engine_ResponseVerdict_Drop_byte_exact(t *testing.T) {
	// Given
	const addr = "mock-resp-drop"
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
			Body:       "Response denied by mock engine.",
		},
	}
	eng.SetNextResponseVerdict(scripted)
	c := dial(t, addr)
	c.handshake("caddy")

	// When a client submits response frames
	const sid = uint32(3)
	c.send(protocol.ResponseCode{SessionID: sid, Code: 200}.Encode())
	got := c.recv()

	// Then the scripted DROP verdict is echoed with the response session id
	want := (&protocol.Verdict{Kind: protocol.VerdictDrop, SessionID: sid, WebResponse: scripted.WebResponse}).Encode()
	mustEqualBytes(t, want, got, "response drop verdict")
}

// Test_Engine_ResponseVerdict_Default_Accept verifies an empty response
// verdict queue yields an ACCEPT verdict.
func Test_Engine_ResponseVerdict_Default_Accept(t *testing.T) {
	// Given
	const addr = "mock-resp-default"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()
	c := dial(t, addr)
	c.handshake("caddy")

	// When
	const sid = uint32(5)
	c.send(protocol.ResponseCode{SessionID: sid, Code: 200}.Encode())
	got := c.recv()

	// Then
	mustEqualBytes(t, (&protocol.Verdict{Kind: protocol.VerdictAccept, SessionID: sid}).Encode(), got, "default response verdict")
}

// Test_Engine_ResponseFrames_Tallied verifies response frames are recorded and
// the RESPONSE_CODE counter is tallied, while request verdicts stay on the
// request queue.
func Test_Engine_ResponseFrames_Tallied(t *testing.T) {
	// Given
	const addr = "mock-resp-tally"
	eng, err := New(addr)
	if err != nil {
		t.Fatalf("New(%q): %v", addr, err)
	}
	defer eng.Close()
	eng.SetNextResponseVerdict(protocol.Verdict{Kind: protocol.VerdictAccept})
	c := dial(t, addr)
	c.handshake("caddy")

	// When a client submits a full response inspection
	const sid = uint32(3)
	c.send(protocol.ResponseCode{SessionID: sid, Code: 200}.Encode())
	_ = c.recv()
	c.send(protocol.ContentLength{SessionID: sid, Length: 5}.Encode())
	c.send(protocol.BodyChunk{DataType: protocol.DataTypeResponseBody, SessionID: sid, IsLastChunk: true, Data: []byte("hello")}.Encode())

	// Then the RESPONSE_CODE counter is tallied and the frames are recorded
	waitFor(t, "response tally", func() bool { return eng.ResponseCount() == 1 })
	if eng.ResponseCount() != 1 {
		t.Fatalf("ResponseCount() = %d, want 1", eng.ResponseCount())
	}
	// handshake(2) + RESPONSE_CODE + CONTENT_LENGTH + RESPONSE_BODY = 5 frames
	waitFor(t, "response frames recorded", func() bool { return eng.FrameCount() == 5 })
	frames := eng.ReceivedFrames()
	seen := map[string]int{}
	for _, f := range frames {
		seen[f.Meaning]++
	}
	want := map[string]int{
		"RESPONSE_CODE session=3 code=200":                 1,
		"CONTENT_LENGTH session=3 length=5":                1,
		"RESPONSE_BODY session=3 last=true part=0 bytes=5": 1,
	}
	for meaning, n := range want {
		if seen[meaning] != n {
			t.Errorf("meaning %q seen %d times, want %d (got %v)", meaning, seen[meaning], n, frames)
		}
	}
}
