package protocol

import "testing"

func checkRequestStart(t *testing.T, got any) {
	t.Helper()
	m, ok := got.(*RequestStart)
	if !ok {
		t.Fatalf("decoded as %T, want *RequestStart", got)
	}
	if m.SessionID != 1 {
		t.Errorf("SessionID = %d, want 1", m.SessionID)
	}
	if m.HTTPProtocol != "" || m.Method != "" || m.Host != "" || m.ListeningIP != "" ||
		m.UnparsedURI != "" || m.ClientIP != "" || m.ParsedHost != "" || m.ParsedURI != "" || m.WAFTag != "" {
		t.Errorf("expected all strings empty, got %+v", m)
	}
	if m.ListeningPort != 0 || m.ClientPort != 0 {
		t.Errorf("expected both ports 0, got listening=%d client=%d", m.ListeningPort, m.ClientPort)
	}
}

func checkRequestEnd(t *testing.T, got any) {
	t.Helper()
	m, ok := got.(*RequestEnd)
	if !ok {
		t.Fatalf("decoded as %T, want *RequestEnd", got)
	}
	if m.DataType != DataTypeRequestEnd {
		t.Errorf("DataType = %d, want REQUEST_END (3)", m.DataType)
	}
	if m.SessionID != 1 {
		t.Errorf("SessionID = %d, want 1", m.SessionID)
	}
}

func checkResponseCode(t *testing.T, got any) {
	t.Helper()
	m, ok := got.(*ResponseCode)
	if !ok {
		t.Fatalf("decoded as %T, want *ResponseCode", got)
	}
	if m.Code != 200 {
		t.Errorf("Code = %d, want 200", m.Code)
	}
	if m.SessionID != 1 {
		t.Errorf("SessionID = %d, want 1", m.SessionID)
	}
}

func checkContentLength(t *testing.T, got any) {
	t.Helper()
	m, ok := got.(*ContentLength)
	if !ok {
		t.Fatalf("decoded as %T, want *ContentLength", got)
	}
	if m.Length != 5 {
		t.Errorf("Length = %d, want 5", m.Length)
	}
	if m.SessionID != 1 {
		t.Errorf("SessionID = %d, want 1", m.SessionID)
	}
}

func checkHeaderBulk(t *testing.T, got any) {
	t.Helper()
	m, ok := got.(*HeaderBulk)
	if !ok {
		t.Fatalf("decoded as %T, want *HeaderBulk", got)
	}
	if m.DataType != DataTypeRequestHeader {
		t.Errorf("DataType = %d, want REQUEST_HEADER (1)", m.DataType)
	}
	if m.SessionID != 1 {
		t.Errorf("SessionID = %d, want 1", m.SessionID)
	}
	if !m.IsLastPart {
		t.Errorf("IsLastPart = false, want true")
	}
	if m.BulkPartIndex != 0 {
		t.Errorf("BulkPartIndex = %d, want 0", m.BulkPartIndex)
	}
	if len(m.Headers) != 1 {
		t.Fatalf("len(Headers) = %d, want 1", len(m.Headers))
	}
	if m.Headers[0].Key != "Host" {
		t.Errorf("Headers[0].Key = %q, want %q", m.Headers[0].Key, "Host")
	}
	if m.Headers[0].Value != "example.com" {
		t.Errorf("Headers[0].Value = %q, want %q", m.Headers[0].Value, "example.com")
	}
}

func checkBodyChunk(t *testing.T, got any) {
	t.Helper()
	m, ok := got.(*BodyChunk)
	if !ok {
		t.Fatalf("decoded as %T, want *BodyChunk", got)
	}
	if m.DataType != DataTypeRequestBody {
		t.Errorf("DataType = %d, want REQUEST_BODY (2)", m.DataType)
	}
	if m.SessionID != 1 {
		t.Errorf("SessionID = %d, want 1", m.SessionID)
	}
	if !m.IsLastChunk {
		t.Errorf("IsLastChunk = false, want true")
	}
	if m.PartCount != 0 {
		t.Errorf("PartCount = %d, want 0", m.PartCount)
	}
	if string(m.Data) != "hello" {
		t.Errorf("Data = %q, want %q", m.Data, "hello")
	}
}

func checkVerdictAccept(t *testing.T, got any) {
	t.Helper()
	v, ok := got.(*Verdict)
	if !ok {
		t.Fatalf("decoded as %T, want *Verdict", got)
	}
	if v.Kind != VerdictAccept {
		t.Errorf("Kind = %d, want ACCEPT (1)", v.Kind)
	}
	if v.SessionID != 1 {
		t.Errorf("SessionID = %d, want 1", v.SessionID)
	}
	if v.WebResponse != nil {
		t.Errorf("WebResponse = %+v, want nil", v.WebResponse)
	}
	if len(v.Injections) != 0 {
		t.Errorf("Injections = %+v, want none", v.Injections)
	}
}

func checkVerdictDrop(t *testing.T, got any) {
	t.Helper()
	v, ok := got.(*Verdict)
	if !ok {
		t.Fatalf("decoded as %T, want *Verdict", got)
	}
	if v.Kind != VerdictDrop {
		t.Errorf("Kind = %d, want DROP (2)", v.Kind)
	}
	if v.SessionID != 1 {
		t.Errorf("SessionID = %d, want 1", v.SessionID)
	}
	if v.WebResponse == nil {
		t.Fatalf("WebResponse = nil, want a web response")
	}
	if v.WebResponse.Type != WebResponseCustom {
		t.Errorf("WebResponse.Type = %d, want CUSTOM_WEB_RESPONSE (0)", v.WebResponse.Type)
	}
	if v.WebResponse.StatusCode != 200 {
		t.Errorf("WebResponse.StatusCode = %d, want 200", v.WebResponse.StatusCode)
	}
	if v.WebResponse.Title != "" || v.WebResponse.Body != "" || v.WebResponse.UUID != "" {
		t.Errorf("expected empty title/body/uuid, got %+v", v.WebResponse)
	}
	if len(v.Injections) != 0 {
		t.Errorf("Injections = %+v, want none", v.Injections)
	}
}
