package protocol

import (
	"reflect"
	"testing"
)

// Test_Registration_roundtrip verifies a fully-populated phase-1 registration
// frame (§G.1) survives encode -> decode unchanged.
func Test_Registration_roundtrip(t *testing.T) {
	// Given
	want := &Registration{AttachmentType: 0, WorkerID: 1, WorkersAmount: 2, FamilyName: "container-abc"}

	// When
	got, err := ParseRegistration(want.Encode())

	// Then
	requireNoError(t, err)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v", want, got)
	}
}

// Test_RegistrationReply_roundtrip verifies the phase-1 path reply (§G.1)
// survives encode -> decode unchanged.
func Test_RegistrationReply_roundtrip(t *testing.T) {
	// Given
	want := &RegistrationReply{Path: "/dev/shm/cp-nano-http-transaction-handler"}

	// When
	got, err := ParseRegistrationReply(want.Encode())

	// Then
	requireNoError(t, err)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v", want, got)
	}
}

// Test_CommData_roundtrip verifies the phase-2 comm frame (§G.2) survives
// encode -> decode unchanged.
func Test_CommData_roundtrip(t *testing.T) {
	// Given
	want := &CommData{UID: "unique-id-42", UserID: 1000, GroupID: 1000}

	// When
	got, err := ParseCommData(want.Encode())

	// Then
	requireNoError(t, err)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v", want, got)
	}
}

// Test_Ack_roundtrip verifies the one-byte acknowledgement (§G.2) survives
// encode -> decode unchanged.
func Test_Ack_roundtrip(t *testing.T) {
	// Given
	want := &Ack{Value: 1}

	// When
	got, err := ParseAck(want.Encode())

	// Then
	requireNoError(t, err)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v", want, got)
	}
}

// Test_Handshake_Fixtures_encode_bytes pins the exact wire bytes of every
// handshake frame to the layouts of docs/attachment-protocol.md §G.
func Test_Handshake_Fixtures_encode_bytes(t *testing.T) {
	tests := []struct {
		name string
		hex  string
		enc  func() []byte
	}{
		{
			name: "registration_phase1",
			hex:  "0001020461626364", // type=0 worker=1 workers=2 len=4 "abcd"
			enc: func() []byte {
				return Registration{AttachmentType: 0, WorkerID: 1, WorkersAmount: 2, FamilyName: "abcd"}.Encode()
			},
		},
		{
			name: "registration_reply_path",
			hex:  "0b6d6f636b2d656e67696e65", // len=11 "mock-engine"
			enc: func() []byte {
				return RegistrationReply{Path: "mock-engine"}.Encode()
			},
		},
		{
			name: "comm_data_phase2",
			hex:  "04616263640100000002000000", // len=4 "abcd" user=1 group=2
			enc: func() []byte {
				return CommData{UID: "abcd", UserID: 1, GroupID: 2}.Encode()
			},
		},
		{
			name: "comm_ack",
			hex:  "01",
			enc: func() []byte {
				return Ack{Value: 1}.Encode()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When
			got := tt.enc()

			// Then
			want := mustHex(t, tt.hex)
			if string(got) != string(want) {
				t.Fatalf("encoded bytes mismatch\nwant: %x\ngot:  %x", want, got)
			}
		})
	}
}

// Test_Handshake_Fixtures_decode decodes the same golden vectors and asserts
// every decoded field.
func Test_Handshake_Fixtures_decode(t *testing.T) {
	tests := []struct {
		name   string
		hex    string
		decode func([]byte) (any, error)
		check  func(*testing.T, any)
	}{
		{
			name: "registration_phase1",
			hex:  "0001020461626364",
			decode: func(b []byte) (any, error) {
				return ParseRegistration(b)
			},
			check: func(t *testing.T, v any) {
				g := v.(*Registration)
				if g.AttachmentType != 0 || g.WorkerID != 1 || g.WorkersAmount != 2 || g.FamilyName != "abcd" {
					t.Fatalf("decoded %+v", g)
				}
			},
		},
		{
			name: "registration_reply_path",
			hex:  "0b6d6f636b2d656e67696e65",
			decode: func(b []byte) (any, error) {
				return ParseRegistrationReply(b)
			},
			check: func(t *testing.T, v any) {
				if g := v.(*RegistrationReply); g.Path != "mock-engine" {
					t.Fatalf("decoded %+v", g)
				}
			},
		},
		{
			name: "comm_data_phase2",
			hex:  "04616263640100000002000000",
			decode: func(b []byte) (any, error) {
				return ParseCommData(b)
			},
			check: func(t *testing.T, v any) {
				g := v.(*CommData)
				if g.UID != "abcd" || g.UserID != 1 || g.GroupID != 2 {
					t.Fatalf("decoded %+v", g)
				}
			},
		},
		{
			name: "comm_ack",
			hex:  "01",
			decode: func(b []byte) (any, error) {
				return ParseAck(b)
			},
			check: func(t *testing.T, v any) {
				if g := v.(*Ack); g.Value != 1 {
					t.Fatalf("decoded %+v", g)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			b := mustHex(t, tt.hex)

			// When
			got, err := tt.decode(b)

			// Then
			requireNoError(t, err)
			tt.check(t, got)
		})
	}
}
