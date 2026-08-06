package protocol

import "fmt"

// RequestEnd is the REQUEST_END or RESPONSE_END frame
// (ngx_cp_io.c:1030-1059): data_type + session_id.
type RequestEnd struct {
	DataType  DataType
	SessionID uint32
}

// Encode serializes the frame.
func (m RequestEnd) Encode() []byte {
	var w wire
	w.u16(uint16(m.DataType))
	w.u32(m.SessionID)
	return w.buf
}

// ParseRequestEnd decodes a REQUEST_END or RESPONSE_END frame.
func ParseRequestEnd(b []byte) (*RequestEnd, error) {
	r := &reader{buf: b}
	dt, err := r.u16()
	if err != nil {
		return nil, err
	}
	if dt != uint16(DataTypeRequestEnd) && dt != uint16(DataTypeResponseEnd) {
		return nil, fmt.Errorf("protocol: expected REQUEST_END or RESPONSE_END, got %d", dt)
	}
	sid, err := r.u32()
	if err != nil {
		return nil, err
	}
	return &RequestEnd{DataType: DataType(dt), SessionID: sid}, nil
}

// ResponseCode is the RESPONSE_CODE frame (ngx_cp_io.c:1085-1106).
type ResponseCode struct {
	SessionID uint32
	Code      uint16
}

// Encode serializes the frame.
func (m ResponseCode) Encode() []byte {
	var w wire
	w.u16(uint16(DataTypeResponseCode))
	w.u32(m.SessionID)
	w.u16(m.Code)
	return w.buf
}

// ParseResponseCode decodes a RESPONSE_CODE frame.
func ParseResponseCode(b []byte) (*ResponseCode, error) {
	r := &reader{buf: b}
	dt, err := r.u16()
	if err != nil {
		return nil, err
	}
	if dt != uint16(DataTypeResponseCode) {
		return nil, fmt.Errorf("protocol: expected RESPONSE_CODE, got %d", dt)
	}
	sid, err := r.u32()
	if err != nil {
		return nil, err
	}
	code, err := r.u16()
	if err != nil {
		return nil, err
	}
	return &ResponseCode{SessionID: sid, Code: code}, nil
}

// ContentLength is the CONTENT_LENGTH frame (ngx_cp_io.c:1108-1130).
type ContentLength struct {
	SessionID uint32
	Length    uint64
}

// Encode serializes the frame.
func (m ContentLength) Encode() []byte {
	var w wire
	w.u16(uint16(DataTypeContentLength))
	w.u32(m.SessionID)
	w.u64(m.Length)
	return w.buf
}

// ParseContentLength decodes a CONTENT_LENGTH frame.
func ParseContentLength(b []byte) (*ContentLength, error) {
	r := &reader{buf: b}
	dt, err := r.u16()
	if err != nil {
		return nil, err
	}
	if dt != uint16(DataTypeContentLength) {
		return nil, fmt.Errorf("protocol: expected CONTENT_LENGTH, got %d", dt)
	}
	sid, err := r.u32()
	if err != nil {
		return nil, err
	}
	length, err := r.u64()
	if err != nil {
		return nil, err
	}
	return &ContentLength{SessionID: sid, Length: length}, nil
}

// DelayedVerdict is the REQUEST_DELAYED_VERDICT frame (ngx_cp_io.c:1061-1083).
type DelayedVerdict struct {
	SessionID uint32
}

// Encode serializes the frame.
func (m DelayedVerdict) Encode() []byte {
	var w wire
	w.u16(uint16(DataTypeRequestDelayedVerdict))
	w.u32(m.SessionID)
	return w.buf
}

// ParseDelayedVerdict decodes a REQUEST_DELAYED_VERDICT frame.
func ParseDelayedVerdict(b []byte) (*DelayedVerdict, error) {
	r := &reader{buf: b}
	dt, err := r.u16()
	if err != nil {
		return nil, err
	}
	if dt != uint16(DataTypeRequestDelayedVerdict) {
		return nil, fmt.Errorf("protocol: expected REQUEST_DELAYED_VERDICT, got %d", dt)
	}
	sid, err := r.u32()
	if err != nil {
		return nil, err
	}
	return &DelayedVerdict{SessionID: sid}, nil
}

// Header is a single HTTP header key/value pair.
type Header struct {
	Key   string
	Value string
}

// HeaderBulk is a REQUEST_HEADER or RESPONSE_HEADER bulk
// (ngx_cp_io.c:1139-1310). A bulk carries up to MAX_HEADER_BULK_SIZE headers.
type HeaderBulk struct {
	DataType      DataType
	SessionID     uint32
	IsLastPart    bool
	BulkPartIndex uint8
	Headers       []Header
}

// Encode serializes the bulk.
func (m HeaderBulk) Encode() []byte {
	var w wire
	w.u16(uint16(m.DataType))
	w.u32(m.SessionID)
	if m.IsLastPart {
		w.u8(1)
	} else {
		w.u8(0)
	}
	w.u8(m.BulkPartIndex)
	for _, h := range m.Headers {
		w.str(h.Key)
		w.str(h.Value)
	}
	return w.buf
}

// ParseHeaderBulk decodes a REQUEST_HEADER or RESPONSE_HEADER bulk.
func ParseHeaderBulk(b []byte) (*HeaderBulk, error) {
	r := &reader{buf: b}
	dt, err := r.u16()
	if err != nil {
		return nil, err
	}
	if dt != uint16(DataTypeRequestHeader) && dt != uint16(DataTypeResponseHeader) {
		return nil, fmt.Errorf("protocol: expected REQUEST_HEADER or RESPONSE_HEADER, got %d", dt)
	}
	out := &HeaderBulk{DataType: DataType(dt)}
	if out.SessionID, err = r.u32(); err != nil {
		return nil, err
	}
	last, err := r.u8()
	if err != nil {
		return nil, err
	}
	out.IsLastPart = last != 0
	if out.BulkPartIndex, err = r.u8(); err != nil {
		return nil, err
	}
	for r.remaining() > 0 {
		var h Header
		if h.Key, err = r.str(); err != nil {
			return nil, err
		}
		if h.Value, err = r.str(); err != nil {
			return nil, err
		}
		out.Headers = append(out.Headers, h)
	}
	return out, nil
}

// BodyChunk is a REQUEST_BODY or RESPONSE_BODY chunk (ngx_cp_io.c:1312-1429).
type BodyChunk struct {
	DataType    DataType
	SessionID   uint32
	IsLastChunk bool
	PartCount   uint8
	Data        []byte
}

// Encode serializes the chunk.
func (m BodyChunk) Encode() []byte {
	var w wire
	w.u16(uint16(m.DataType))
	w.u32(m.SessionID)
	if m.IsLastChunk {
		w.u8(1)
	} else {
		w.u8(0)
	}
	w.u8(m.PartCount)
	w.bytes(m.Data)
	return w.buf
}

// ParseBodyChunk decodes a REQUEST_BODY or RESPONSE_BODY chunk.
func ParseBodyChunk(b []byte) (*BodyChunk, error) {
	r := &reader{buf: b}
	dt, err := r.u16()
	if err != nil {
		return nil, err
	}
	if dt != uint16(DataTypeRequestBody) && dt != uint16(DataTypeResponseBody) {
		return nil, fmt.Errorf("protocol: expected REQUEST_BODY or RESPONSE_BODY, got %d", dt)
	}
	out := &BodyChunk{DataType: DataType(dt)}
	if out.SessionID, err = r.u32(); err != nil {
		return nil, err
	}
	last, err := r.u8()
	if err != nil {
		return nil, err
	}
	out.IsLastChunk = last != 0
	if out.PartCount, err = r.u8(); err != nil {
		return nil, err
	}
	if out.Data, err = r.take(r.remaining()); err != nil {
		return nil, err
	}
	return out, nil
}

// KeepAlive is the keep-alive frame sent to the registration-expiration socket
// (§G.3, ngx_http_cp_attachment_module.c:424-466): worker_id, then a
// length-prefixed family/container name.
type KeepAlive struct {
	WorkerID   uint8
	FamilyName string
}

// Encode serializes the frame.
func (k KeepAlive) Encode() []byte {
	var w wire
	w.u8(k.WorkerID)
	w.str8(k.FamilyName)
	return w.buf
}

// ParseKeepAlive decodes a keep-alive frame.
func ParseKeepAlive(b []byte) (*KeepAlive, error) {
	r := &reader{buf: b}
	workerID, err := r.u8()
	if err != nil {
		return nil, err
	}
	name, err := r.str8()
	if err != nil {
		return nil, err
	}
	return &KeepAlive{WorkerID: workerID, FamilyName: name}, nil
}
