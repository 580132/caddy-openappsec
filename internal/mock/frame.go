package mock

import (
	"encoding/binary"
	"fmt"

	"github.com/580132/caddy-openappsec/internal/protocol"
)

// classify determines what kind of frame b is, given the connection's
// handshake phase. Request frames (data types 0-10) are recognized first:
// their data_type is a little-endian uint16 below 256, so the second byte is
// zero, while registration frames carry worker_id+1 (>= 1) and comm/keep
// -alive frames carry a length or a uid byte there. A registration frame is
// only accepted on a fresh connection (phase 0), matching the app's client
// which sends REGISTRATION, then COMM_DATA, then requests on one connection.
func classify(b []byte, phase int) (kind frameKind, desc string) {
	if len(b) >= 2 && b[1] == 0 {
		if d, _, _, ok := parseRequest(b); ok {
			if isResponseFrame(b) {
				return frameResponse, d
			}
			return frameRequest, d
		}
	}
	if phase == 0 {
		if reg, err := protocol.ParseRegistration(b); err == nil {
			return frameRegistration, fmt.Sprintf(
				"REGISTRATION type=%d worker=%d workers=%d family=%q",
				reg.AttachmentType, reg.WorkerID, reg.WorkersAmount, reg.FamilyName,
			)
		}
	}
	if cd, err := protocol.ParseCommData(b); err == nil {
		return frameComm, fmt.Sprintf("COMM_DATA uid=%q user=%d group=%d target_core=%d",
			cd.UID, cd.UserID, cd.GroupID, cd.TargetCore)
	}
	if ka, err := protocol.ParseKeepAlive(b); err == nil {
		return frameKeepAlive, fmt.Sprintf("KEEP_ALIVE worker=%d family=%q", ka.WorkerID, ka.FamilyName)
	}
	return frameUnknown, fmt.Sprintf("UNKNOWN (%d bytes)", len(b))
}

// isResponseFrame reports whether b is a response-family frame
// (RESPONSE_CODE, RESPONSE_HEADER, RESPONSE_BODY, RESPONSE_END, or
// CONTENT_LENGTH). These open and feed a response inspection session.
func isResponseFrame(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	switch protocol.DataType(binary.LittleEndian.Uint16(b[:2])) {
	case protocol.DataTypeResponseCode, protocol.DataTypeResponseHeader,
		protocol.DataTypeResponseBody, protocol.DataTypeResponseEnd,
		protocol.DataTypeContentLength:
		return true
	}
	return false
}

// isResponseCode reports whether b is a RESPONSE_CODE frame, which opens a
// response inspection session and triggers the scripted response verdict.
func isResponseCode(b []byte) bool {
	return len(b) >= 2 && protocol.DataType(binary.LittleEndian.Uint16(b[:2])) == protocol.DataTypeResponseCode
}

// isRequestEnd reports whether the frame is a REQUEST_END. The real engine
// emits its terminal verdict when the attachment closes the request stage
// (end_request), so the mock replies to REQUEST_END too.
func isRequestEnd(b []byte) bool {
	return len(b) >= 2 && protocol.DataType(binary.LittleEndian.Uint16(b[:2])) == protocol.DataTypeRequestEnd
}

// parseRequest dispatches a request-family frame (REQUEST_START through
// RESPONSE_END) to the protocol parsers and returns a one-line description,
// the session id, and whether the frame is a REQUEST_START. ok is false for
// frames of any other kind.
func parseRequest(b []byte) (desc string, sid uint32, isStart bool, ok bool) {
	if rs, err := protocol.ParseRequestStart(b); err == nil {
		return fmt.Sprintf("REQUEST_START session=%d method=%q uri=%q host=%q",
			rs.SessionID, rs.Method, rs.UnparsedURI, rs.Host), rs.SessionID, true, true
	}
	if re, err := protocol.ParseRequestEnd(b); err == nil {
		kind := "REQUEST_END"
		if re.DataType == protocol.DataTypeResponseEnd {
			kind = "RESPONSE_END"
		}
		return fmt.Sprintf("%s session=%d", kind, re.SessionID), re.SessionID, false, true
	}
	if rc, err := protocol.ParseResponseCode(b); err == nil {
		return fmt.Sprintf("RESPONSE_CODE session=%d code=%d", rc.SessionID, rc.Code), rc.SessionID, false, true
	}
	if cl, err := protocol.ParseContentLength(b); err == nil {
		return fmt.Sprintf("CONTENT_LENGTH session=%d length=%d", cl.SessionID, cl.Length), cl.SessionID, false, true
	}
	if dv, err := protocol.ParseDelayedVerdict(b); err == nil {
		return fmt.Sprintf("REQUEST_DELAYED_VERDICT session=%d", dv.SessionID), dv.SessionID, false, true
	}
	if hb, err := protocol.ParseHeaderBulk(b); err == nil {
		kind := "REQUEST_HEADER"
		if hb.DataType == protocol.DataTypeResponseHeader {
			kind = "RESPONSE_HEADER"
		}
		return fmt.Sprintf("%s session=%d last=%v part=%d headers=%d",
			kind, hb.SessionID, hb.IsLastPart, hb.BulkPartIndex, len(hb.Headers)), hb.SessionID, false, true
	}
	if bc, err := protocol.ParseBodyChunk(b); err == nil {
		kind := "REQUEST_BODY"
		if bc.DataType == protocol.DataTypeResponseBody {
			kind = "RESPONSE_BODY"
		}
		return fmt.Sprintf("%s session=%d last=%v part=%d bytes=%d",
			kind, bc.SessionID, bc.IsLastChunk, bc.PartCount, len(bc.Data)), bc.SessionID, false, true
	}
	return "", 0, false, false
}

// DescribeFrame renders a one-line, human-readable meaning for any frame the
// mock engine understands, or "UNKNOWN (n bytes)" otherwise. It backs the
// ReceivedFrames records and cmd/mockengine's hex dump.
func DescribeFrame(b []byte) string {
	_, desc := classify(b, 0)
	return desc
}
