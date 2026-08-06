package protocol

import "fmt"

// parseInjection decodes one HttpInjectData record (16-byte header followed by
// injection_size payload bytes).
func parseInjection(r *reader) (*Injection, error) {
	pos, err := r.i64()
	if err != nil {
		return nil, err
	}
	modType, err := r.u32()
	if err != nil {
		return nil, err
	}
	size, err := r.u16()
	if err != nil {
		return nil, err
	}
	isHeader, err := r.u8()
	if err != nil {
		return nil, err
	}
	origIdx, err := r.u8()
	if err != nil {
		return nil, err
	}
	data, err := r.take(int(size))
	if err != nil {
		return nil, err
	}
	return &Injection{
		InjectionPos:    pos,
		ModType:         ModificationType(modType),
		InjectionSize:   size,
		IsHeader:        isHeader != 0,
		OrigBufferIndex: origIdx,
		Data:            data,
	}, nil
}

// parseWebResponse decodes an HttpWebResponseData record as carried by a DROP
// verdict. For CUSTOM_WEB_RESPONSE / BLOCK_PAGE / RESPONSE_CODE_ONLY the
// payload is [response_code][title_size][body_size][title][body][uuid]; for
// REDIRECT it is [unused_dummy][add_event_id][location_size][location][uuid].
func parseWebResponse(r *reader) (*WebResponse, error) {
	typ, err := r.u8()
	if err != nil {
		return nil, err
	}
	uuidSize, err := r.u8()
	if err != nil {
		return nil, err
	}
	wr := &WebResponse{Type: WebResponseType(typ)}
	switch wr.Type {
	case WebResponseCustom, WebResponseBlockPage, WebResponseCodeOnly:
		if wr.StatusCode, err = r.u16(); err != nil {
			return nil, err
		}
		titleSize, err := r.u8()
		if err != nil {
			return nil, err
		}
		bodySize, err := r.u8()
		if err != nil {
			return nil, err
		}
		title, err := r.take(int(titleSize))
		if err != nil {
			return nil, err
		}
		body, err := r.take(int(bodySize))
		if err != nil {
			return nil, err
		}
		uuid, err := r.take(int(uuidSize))
		if err != nil {
			return nil, err
		}
		wr.Title, wr.Body, wr.UUID = string(title), string(body), string(uuid)
	case WebResponseRedirect:
		if _, err = r.u8(); err != nil { // unused_dummy
			return nil, err
		}
		if _, err = r.u8(); err != nil { // add_event_id
			return nil, err
		}
		locSize, err := r.u16()
		if err != nil {
			return nil, err
		}
		loc, err := r.take(int(locSize))
		if err != nil {
			return nil, err
		}
		uuid, err := r.take(int(uuidSize))
		if err != nil {
			return nil, err
		}
		wr.RedirectLocation, wr.UUID = string(loc), string(uuid)
	default:
		return nil, fmt.Errorf("protocol: unknown web response type %d", typ)
	}
	return wr, nil
}

// parseCustomResponse decodes an HttpCustomResponseData record as carried by a
// CUSTOM_RESPONSE verdict: [response_code][body_size][headers_count] followed
// by one HttpHeaderPackedData per header and the body.
func parseCustomResponse(r *reader) (*WebResponse, error) {
	code, err := r.u16()
	if err != nil {
		return nil, err
	}
	bodySize, err := r.u16()
	if err != nil {
		return nil, err
	}
	headersCount, err := r.u8()
	if err != nil {
		return nil, err
	}
	wr := &WebResponse{Type: WebResponseWithHeaders, StatusCode: code}
	for i := 0; i < int(headersCount); i++ {
		keySize, err := r.u16()
		if err != nil {
			return nil, err
		}
		valSize, err := r.u16()
		if err != nil {
			return nil, err
		}
		key, err := r.take(int(keySize))
		if err != nil {
			return nil, err
		}
		val, err := r.take(int(valSize))
		if err != nil {
			return nil, err
		}
		wr.Headers = append(wr.Headers, Header{Key: string(key), Value: string(val)})
	}
	body, err := r.take(int(bodySize))
	if err != nil {
		return nil, err
	}
	wr.Body = string(body)
	return wr, nil
}

// encodeWebResponse serializes a WebResponse into the HttpWebResponseData
// layout used by DROP verdicts.
func encodeWebResponse(w *wire, wr *WebResponse) {
	w.u8(uint8(wr.Type))
	w.u8(uint8(len(wr.UUID)))
	switch wr.Type {
	case WebResponseCustom, WebResponseBlockPage, WebResponseCodeOnly:
		w.u16(wr.StatusCode)
		w.u8(uint8(len(wr.Title)))
		w.u8(uint8(len(wr.Body)))
		w.bytes([]byte(wr.Title))
		w.bytes([]byte(wr.Body))
		w.bytes([]byte(wr.UUID))
	case WebResponseRedirect:
		w.u8(0) // unused_dummy
		w.u8(0) // add_event_id
		w.u16(uint16(len(wr.RedirectLocation)))
		w.bytes([]byte(wr.RedirectLocation))
		w.bytes([]byte(wr.UUID))
	}
}

// encodeCustomResponse serializes a WebResponse into the HttpCustomResponseData
// layout used by CUSTOM_RESPONSE verdicts.
func encodeCustomResponse(w *wire, wr *WebResponse) {
	w.u16(wr.StatusCode)
	w.u16(uint16(len(wr.Body)))
	w.u8(uint8(len(wr.Headers)))
	for _, h := range wr.Headers {
		w.u16(uint16(len(h.Key)))
		w.u16(uint16(len(h.Value)))
		w.bytes([]byte(h.Key))
		w.bytes([]byte(h.Value))
	}
	w.bytes([]byte(wr.Body))
}
