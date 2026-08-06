package protocol

import (
	"encoding/hex"
	"testing"
)

// requireNoError fails the test if err is non-nil.
func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// decodeFunc decodes a wire message into a decoded value.
type decodeFunc func([]byte) (any, error)

// checkFunc asserts every field of a decoded fixture.
type checkFunc func(*testing.T, any)

// mustHex decodes a hex string, failing the test on a malformed literal.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	requireNoError(t, err)
	return b
}

// Test_Fixtures_decode reproduces every golden byte vector from the contract
// doc's "Byte Fixtures" section and asserts every decoded field.
func Test_Fixtures_decode(t *testing.T) {
	tests := []struct {
		name   string
		hex    string
		decode decodeFunc
		check  checkFunc
	}{
		{
			name:   "fixture1_request_start_minimal",
			hex:    "00000100000000000000000000000000000000000000000000000000",
			decode: func(b []byte) (any, error) { return ParseRequestStart(b) },
			check:  checkRequestStart,
		},
		{
			name:   "fixture2_request_end",
			hex:    "030001000000",
			decode: func(b []byte) (any, error) { return ParseRequestEnd(b) },
			check:  checkRequestEnd,
		},
		{
			name:   "fixture3_response_code",
			hex:    "040001000000c800",
			decode: func(b []byte) (any, error) { return ParseResponseCode(b) },
			check:  checkResponseCode,
		},
		{
			name:   "fixture4_content_length",
			hex:    "0800010000000500000000000000",
			decode: func(b []byte) (any, error) { return ParseContentLength(b) },
			check:  checkContentLength,
		},
		{
			name:   "fixture5_request_header_bulk",
			hex:    "01000100000001000400486f73740b006578616d706c652e636f6d",
			decode: func(b []byte) (any, error) { return ParseHeaderBulk(b) },
			check:  checkHeaderBulk,
		},
		{
			name:   "fixture6_request_body",
			hex:    "020001000000010068656c6c6f",
			decode: func(b []byte) (any, error) { return ParseBodyChunk(b) },
			check:  checkBodyChunk,
		},
		{
			name:   "fixture7_verdict_accept",
			hex:    "01000100000000",
			decode: func(b []byte) (any, error) { return ParseVerdict(b) },
			check:  checkVerdictAccept,
		},
		{
			name: "fixture8_verdict_drop_web_response",
			// The contract doc prints "C8 01" for response_code 200, but 200
			// is 0x00C8, which is "C8 00" in the little-endian byte order the
			// doc mandates for its fixtures (and which Fixture 3 uses). The
			// doc's "C8 01" is a typo; this vector uses the C-source-correct
			// little-endian bytes.
			hex:    "020001000000010000c8000000",
			decode: func(b []byte) (any, error) { return ParseVerdict(b) },
			check:  checkVerdictDrop,
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

// Test_Fixtures_encode_bytes verifies the REQUEST_START builder reproduces
// Fixture 1 byte-for-byte, and the keep-alive builder matches §G.3.
func Test_Fixtures_encode_bytes(t *testing.T) {
	tests := []struct {
		name string
		hex  string
		enc  func() []byte
	}{
		{
			name: "fixture1_request_start_minimal",
			hex:  "00000100000000000000000000000000000000000000000000000000",
			enc: func() []byte {
				m := RequestStart{SessionID: 1}
				return m.Encode()
			},
		},
		{
			name: "keepalive_worker1_family_nginx",
			hex:  "01056e67696e78",
			enc: func() []byte {
				m := KeepAlive{WorkerID: 1, FamilyName: "nginx"}
				return m.Encode()
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
