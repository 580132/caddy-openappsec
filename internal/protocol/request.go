package protocol

import "fmt"

// RequestStart is the metadata block that opens a request inspection session.
// It mirrors the 22-fragment REQUEST_START layout (ngx_cp_io.c:867-1028):
// data_type, session_id, then ten length-prefixed strings and two ports.
type RequestStart struct {
	SessionID     uint32
	HTTPProtocol  string
	Method        string
	Host          string
	ListeningIP   string
	ListeningPort uint16
	UnparsedURI   string
	ClientIP      string
	ClientPort    uint16
	ParsedHost    string
	ParsedURI     string
	WAFTag        string
}

// Encode serializes the block. Ports are written in network byte order
// (htons, ngx_cp_io.c:970,983); all other fields are little-endian.
func (r RequestStart) Encode() []byte {
	var w wire
	w.u16(uint16(DataTypeRequestStart))
	w.u32(r.SessionID)
	w.str(r.HTTPProtocol)
	w.str(r.Method)
	w.str(r.Host)
	w.str(r.ListeningIP)
	w.port(r.ListeningPort)
	w.str(r.UnparsedURI)
	w.str(r.ClientIP)
	w.port(r.ClientPort)
	w.str(r.ParsedHost)
	w.str(r.ParsedURI)
	w.str(r.WAFTag)
	return w.buf
}

// ParseRequestStart decodes a REQUEST_START block.
func ParseRequestStart(b []byte) (*RequestStart, error) {
	r := &reader{buf: b}
	dt, err := r.u16()
	if err != nil {
		return nil, err
	}
	if dt != uint16(DataTypeRequestStart) {
		return nil, fmt.Errorf("protocol: expected data type REQUEST_START, got %d", dt)
	}
	out := &RequestStart{}
	if out.SessionID, err = r.u32(); err != nil {
		return nil, err
	}
	if out.HTTPProtocol, err = r.str(); err != nil {
		return nil, err
	}
	if out.Method, err = r.str(); err != nil {
		return nil, err
	}
	if out.Host, err = r.str(); err != nil {
		return nil, err
	}
	if out.ListeningIP, err = r.str(); err != nil {
		return nil, err
	}
	if out.ListeningPort, err = r.port(); err != nil {
		return nil, err
	}
	if out.UnparsedURI, err = r.str(); err != nil {
		return nil, err
	}
	if out.ClientIP, err = r.str(); err != nil {
		return nil, err
	}
	if out.ClientPort, err = r.port(); err != nil {
		return nil, err
	}
	if out.ParsedHost, err = r.str(); err != nil {
		return nil, err
	}
	if out.ParsedURI, err = r.str(); err != nil {
		return nil, err
	}
	if out.WAFTag, err = r.str(); err != nil {
		return nil, err
	}
	return out, nil
}
