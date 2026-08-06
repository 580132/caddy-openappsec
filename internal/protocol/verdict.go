package protocol

// Verdict is a parsed engine reply (HttpReplyFromService,
// nano_attachment_common.h:470-475). The payload interpretation depends on
// Kind: INJECT carries Injections, DROP carries a WebResponse, and
// CUSTOM_RESPONSE carries a WebResponse with headers.
type Verdict struct {
	Kind        ServiceVerdict
	SessionID   uint32
	WebResponse *WebResponse
	Injections  []Injection
}

// WebResponse is the HTTP-facing response the engine asks the attachment to
// send for a DROP or CUSTOM_RESPONSE verdict. It is decoded from
// HttpWebResponseData (nano_attachment_common.h:259-278) or
// HttpCustomResponseData (nano_attachment_common.h:281-287).
type WebResponse struct {
	Type             WebResponseType
	StatusCode       uint16
	Title            string
	Body             string
	UUID             string
	RedirectLocation string
	Headers          []Header
}

// Injection is a single modification from an INJECT verdict, decoded from
// HttpInjectData (nano_attachment_common.h:250-257).
type Injection struct {
	InjectionPos    int64
	ModType         ModificationType
	InjectionSize   uint16
	IsHeader        bool
	OrigBufferIndex uint8
	Data            []byte
}

// ParseVerdict decodes an HttpReplyFromService frame.
func ParseVerdict(b []byte) (*Verdict, error) {
	r := &reader{buf: b}
	kind, err := r.u16()
	if err != nil {
		return nil, err
	}
	sid, err := r.u32()
	if err != nil {
		return nil, err
	}
	count, err := r.u8()
	if err != nil {
		return nil, err
	}
	v := &Verdict{Kind: ServiceVerdict(kind), SessionID: sid}
	switch v.Kind {
	case VerdictInject:
		for i := 0; i < int(count); i++ {
			inj, err := parseInjection(r)
			if err != nil {
				return nil, err
			}
			v.Injections = append(v.Injections, *inj)
		}
	case VerdictDrop:
		wr, err := parseWebResponse(r)
		if err != nil {
			return nil, err
		}
		v.WebResponse = wr
	case VerdictCustomResponse:
		wr, err := parseCustomResponse(r)
		if err != nil {
			return nil, err
		}
		v.WebResponse = wr
	}
	return v, nil
}

// Encode serializes the verdict as an HttpReplyFromService frame.
func (v *Verdict) Encode() []byte {
	var w wire
	w.u16(uint16(v.Kind))
	w.u32(v.SessionID)
	switch v.Kind {
	case VerdictInject:
		w.u8(uint8(len(v.Injections)))
		for _, inj := range v.Injections {
			w.i64(inj.InjectionPos)
			w.u32(uint32(inj.ModType))
			w.u16(uint16(len(inj.Data)))
			if inj.IsHeader {
				w.u8(1)
			} else {
				w.u8(0)
			}
			w.u8(inj.OrigBufferIndex)
			w.bytes(inj.Data)
		}
	case VerdictDrop:
		w.u8(1)
		encodeWebResponse(&w, v.WebResponse)
	case VerdictCustomResponse:
		w.u8(1)
		encodeCustomResponse(&w, v.WebResponse)
	default:
		w.u8(0)
	}
	return w.buf
}
