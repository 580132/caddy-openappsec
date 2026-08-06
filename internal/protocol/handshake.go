package protocol

// Registration is the phase-1 registration frame an attachment sends to the
// engine's registration socket (docs/attachment-protocol.md §G.1,
// nano_initializer.c:534-614):
//
//	[u8 attachment_type][u8 worker_id][u8 workers_amount][u8 family_name_size][family_name]
//
// worker_id is the sender's worker index plus one, and family_name is the
// docker/container id the attachment identifies itself with.
type Registration struct {
	AttachmentType uint8
	WorkerID       uint8
	WorkersAmount  uint8
	FamilyName     string
}

// Encode serializes the frame. FamilyName is written with a uint8 length
// prefix and must be at most 255 bytes.
func (m Registration) Encode() []byte {
	var w wire
	w.u8(m.AttachmentType)
	w.u8(m.WorkerID)
	w.u8(m.WorkersAmount)
	w.str8(m.FamilyName)
	return w.buf
}

// ParseRegistration decodes a phase-1 registration frame.
func ParseRegistration(b []byte) (*Registration, error) {
	r := &reader{buf: b}
	m := &Registration{}
	var err error
	if m.AttachmentType, err = r.u8(); err != nil {
		return nil, err
	}
	if m.WorkerID, err = r.u8(); err != nil {
		return nil, err
	}
	if m.WorkersAmount, err = r.u8(); err != nil {
		return nil, err
	}
	if m.FamilyName, err = r.str8(); err != nil {
		return nil, err
	}
	return m, nil
}

// RegistrationReply is the service's phase-1 reply (§G.1,
// nano_initializer.c:628-658): a uint8 length prefix followed by the
// verdict-signal path the attachment must connect to for phase 2.
type RegistrationReply struct {
	Path string
}

// Encode serializes the reply. Path is written with a uint8 length prefix and
// must be at most 255 bytes (the C receiver rejects paths at
// MAX_SHARED_MEM_PATH_LEN = 128).
func (m RegistrationReply) Encode() []byte {
	var w wire
	w.str8(m.Path)
	return w.buf
}

// ParseRegistrationReply decodes a phase-1 path reply.
func ParseRegistrationReply(b []byte) (*RegistrationReply, error) {
	r := &reader{buf: b}
	path, err := r.str8()
	if err != nil {
		return nil, err
	}
	return &RegistrationReply{Path: path}, nil
}

// CommData is the phase-2 communication frame an attachment sends to the
// verdict-signal socket (§G.2, nano_initializer.c:278-334):
//
//	[u8 uid_size][unique_id][u32 nano_user_id][u32 nano_group_id]
type CommData struct {
	UID     string
	UserID  uint32
	GroupID uint32
}

// Encode serializes the frame. UID is written with a uint8 length prefix and
// must be at most 255 bytes.
func (m CommData) Encode() []byte {
	var w wire
	w.str8(m.UID)
	w.u32(m.UserID)
	w.u32(m.GroupID)
	return w.buf
}

// ParseCommData decodes a phase-2 communication frame.
func ParseCommData(b []byte) (*CommData, error) {
	r := &reader{buf: b}
	m := &CommData{}
	var err error
	if m.UID, err = r.str8(); err != nil {
		return nil, err
	}
	if m.UserID, err = r.u32(); err != nil {
		return nil, err
	}
	if m.GroupID, err = r.u32(); err != nil {
		return nil, err
	}
	return m, nil
}

// Ack is the one-byte acknowledgement the service sends after a successful
// phase-2 handshake (§G.2, nano_initializer.c:391-407). The reference client
// checks only that the byte arrives, never its value. The mock engine also
// replies to keep-alive frames with an Ack so tests can observe that the
// keep-alive was processed.
type Ack struct {
	Value uint8
}

// Encode serializes the acknowledgement.
func (m Ack) Encode() []byte {
	return []byte{m.Value}
}

// ParseAck decodes a one-byte acknowledgement.
func ParseAck(b []byte) (*Ack, error) {
	r := &reader{buf: b}
	v, err := r.u8()
	if err != nil {
		return nil, err
	}
	return &Ack{Value: v}, nil
}
