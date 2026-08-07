package mock

import (
	"testing"

	"github.com/580132/caddy-openappsec/internal/protocol"
)

// Test_DescribeFrame covers the one-line frame meanings used by the CLI hex
// dump. Frames are built with the protocol encoders so the fixtures cannot
// drift from the wire format.
func Test_DescribeFrame(t *testing.T) {
	tests := []struct {
		name  string
		frame []byte
		want  string
	}{
		{"request_start", protocol.RequestStart{SessionID: 5, Method: "GET", UnparsedURI: "/hi", Host: "my-host"}.Encode(), "REQUEST_START session=5 method=\"GET\" uri=\"/hi\" host=\"my-host\""},
		{"request_end", protocol.RequestEnd{DataType: protocol.DataTypeRequestEnd, SessionID: 1}.Encode(), "REQUEST_END session=1"},
		{"response_end", protocol.RequestEnd{DataType: protocol.DataTypeResponseEnd, SessionID: 1}.Encode(), "RESPONSE_END session=1"},
		{"response_code", protocol.ResponseCode{SessionID: 1, Code: 200}.Encode(), "RESPONSE_CODE session=1 code=200"},
		{"content_length", protocol.ContentLength{SessionID: 1, Length: 5}.Encode(), "CONTENT_LENGTH session=1 length=5"},
		{"delayed_verdict", protocol.DelayedVerdict{SessionID: 1}.Encode(), "REQUEST_DELAYED_VERDICT session=1"},
		{"request_header", protocol.HeaderBulk{DataType: protocol.DataTypeRequestHeader, SessionID: 1, IsLastPart: true, Headers: []protocol.Header{{Key: "Host", Value: "example.com"}}}.Encode(), "REQUEST_HEADER session=1 last=true part=0 headers=1"},
		{"request_body", protocol.BodyChunk{DataType: protocol.DataTypeRequestBody, SessionID: 1, IsLastChunk: true, Data: []byte("hello")}.Encode(), "REQUEST_BODY session=1 last=true part=0 bytes=5"},
		{"registration", protocol.Registration{AttachmentType: 0, WorkerID: 1, WorkersAmount: 2, FamilyName: "abcd"}.Encode(), "REGISTRATION type=0 worker=1 workers=2 family=\"abcd\""},
		{"comm_data", protocol.CommData{UID: "abcd", UserID: 1, GroupID: 2, TargetCore: -1}.Encode(), "COMM_DATA uid=\"abcd\" user=1 group=2 target_core=-1"},
		{"keep_alive", protocol.KeepAlive{WorkerID: 1, FamilyName: "nginx"}.Encode(), "KEEP_ALIVE worker=1 family=\"nginx\""},
		{"unknown", []byte{0xde, 0xad, 0xbe, 0xef}, "UNKNOWN (4 bytes)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When
			got := DescribeFrame(tt.frame)

			// Then
			if got != tt.want {
				t.Fatalf("DescribeFrame = %q, want %q", got, tt.want)
			}
		})
	}
}
