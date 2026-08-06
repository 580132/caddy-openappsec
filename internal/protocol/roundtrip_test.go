package protocol

import (
	"reflect"
	"testing"
)

// Test_RequestStart_roundtrip verifies a fully-populated REQUEST_START block
// survives encode -> decode unchanged.
func Test_RequestStart_roundtrip(t *testing.T) {
	// Given
	want := &RequestStart{
		SessionID:     7,
		HTTPProtocol:  "HTTP/1.1",
		Method:        "GET",
		Host:          "example.com",
		ListeningIP:   "192.168.1.10",
		ListeningPort: 8080,
		UnparsedURI:   "/path?q=1",
		ClientIP:      "10.0.0.5",
		ClientPort:    54321,
		ParsedHost:    "example.com",
		ParsedURI:     "/path",
		WAFTag:        "prod",
	}

	// When
	got, err := ParseRequestStart(want.Encode())

	// Then
	requireNoError(t, err)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v", want, got)
	}
}

// Test_KeepAlive_roundtrip verifies the keep-alive frame (§G.3) round-trips.
func Test_KeepAlive_roundtrip(t *testing.T) {
	// Given
	want := &KeepAlive{WorkerID: 2, FamilyName: "caddy"}

	// When
	got, err := ParseKeepAlive(want.Encode())

	// Then
	requireNoError(t, err)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v", want, got)
	}
}

// Test_InjectVerdict_roundtrip verifies an INJECT verdict with multiple
// modifications survives encode and re-decode unchanged.
func Test_InjectVerdict_roundtrip(t *testing.T) {
	// Given
	want := &Verdict{
		Kind:      VerdictInject,
		SessionID: 1,
		Injections: []Injection{
			{InjectionPos: 5, ModType: ModInject, InjectionSize: 8, IsHeader: true, OrigBufferIndex: 0, Data: []byte("<script>")},
			{InjectionPos: InjectPosIrrelevant, ModType: ModAppend, InjectionSize: 9, IsHeader: false, OrigBufferIndex: 3, Data: []byte("</script>")},
		},
	}

	// When
	got, err := ParseVerdict(want.Encode())

	// Then
	requireNoError(t, err)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v", want, got)
	}
}

// Test_DropVerdict_roundtrip verifies a DROP verdict carrying a custom web
// response survives encode and re-decode unchanged.
func Test_DropVerdict_roundtrip(t *testing.T) {
	// Given
	want := &Verdict{
		Kind:      VerdictDrop,
		SessionID: 1,
		WebResponse: &WebResponse{
			Type:       WebResponseCustom,
			StatusCode: 403,
			Title:      "Blocked",
			Body:       "Access denied.",
			UUID:       "abc123",
		},
	}

	// When
	got, err := ParseVerdict(want.Encode())

	// Then
	requireNoError(t, err)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v", want, got)
	}
}

// Test_SessionAllocator_allocates_odd_ids verifies the allocator mirrors the
// nginx reference sequence (3, 5, 7, ...) and that reclaim rewinds only the
// most recent id.
func Test_SessionAllocator_allocates_odd_ids(t *testing.T) {
	// Given
	a := NewSessionAllocator()

	// When
	first := a.Allocate()
	second := a.Allocate()
	third := a.Allocate()

	// Then
	if first != 3 || second != 5 || third != 7 {
		t.Fatalf("allocated %d, %d, %d; want 3, 5, 7", first, second, third)
	}

	// Reclaiming the most recent id rewinds the allocator.
	a.Reclaim(third)
	if got := a.Allocate(); got != 7 {
		t.Errorf("after reclaim, Allocate() = %d, want 7", got)
	}

	// Reclaiming an older id is a no-op.
	a.Reclaim(first)
	if got := a.Allocate(); got != 9 {
		t.Errorf("after stale reclaim, Allocate() = %d, want 9", got)
	}
}
