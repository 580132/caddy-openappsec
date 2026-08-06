package protocol

// DataType identifies the kind of attachment message on the wire. It mirrors
// AttachmentDataType (nano_attachment_common.h:176-190).
type DataType uint16

const (
	DataTypeRequestStart DataType = iota
	DataTypeRequestHeader
	DataTypeRequestBody
	DataTypeRequestEnd
	DataTypeResponseCode
	DataTypeResponseHeader
	DataTypeResponseBody
	DataTypeResponseEnd
	DataTypeContentLength
	DataTypeMetricDataFromPlugin
	DataTypeRequestDelayedVerdict
	DataTypeCount
)

// ServiceVerdict is the engine's verdict for a session. It mirrors
// ServiceVerdict (nano_attachment_common.h:209-224) and is carried in the
// verdict field of HttpReplyFromService.
type ServiceVerdict uint16

const (
	VerdictInspect ServiceVerdict = iota
	VerdictAccept
	VerdictDrop
	VerdictInject
	VerdictIrrelevant
	VerdictReconf
	VerdictDelayed
	VerdictLimitResponseHeaders
	VerdictCustomResponse
)

// ModificationType mirrors HttpModificationType (nano_attachment_common.h:239-248).
type ModificationType uint8

const (
	ModAppend ModificationType = iota
	ModInject
	ModReplace
)

// WebResponseType mirrors NanoWebResponseType (nano_attachment_common.h:44-57).
type WebResponseType uint8

const (
	WebResponseCustom WebResponseType = iota
	WebResponseBlockPage
	WebResponseCodeOnly
	WebResponseRedirect
	WebResponseWithHeaders
	WebResponseNone
)

// CorruptedSessionID is the session id that must never be used
// (nano_attachment_common.h:34).
const CorruptedSessionID uint32 = 0

// InjectPosIrrelevant marks an injection position that carries no meaning
// (nano_attachment_common.h:33).
const InjectPosIrrelevant int64 = -1

// Shared-memory ring queue layout constants (shared_ring_queue.h:26-60). The
// SharedRingQueue struct is packed, so field offsets are contiguous.
const (
	// SharedMemSegmentSize is SHARED_MEMORY_SEGMENT_ENTRY_SIZE.
	SharedMemSegmentSize = 4096
	// SharedMemSegmentSizeBC is SHARED_MEMORY_SEGMENT_ENTRY_SIZE_BC.
	SharedMemSegmentSizeBC = 1024
	// SharedMemQueueNameLen is MAX_ONE_WAY_QUEUE_NAME_LENGTH.
	SharedMemQueueNameLen = 64

	SharedQueueNameOffset     = 0
	SharedQueueOwnerFDOffset  = 64
	SharedQueueUserFDOffset   = 68
	SharedQueueSizeOffset     = 72
	SharedQueueWritePosOffset = 76
	SharedQueueReadPosOffset  = 78
	SharedQueueNumSegOffset   = 80
	// SharedQueueMgmtOffset is the offset of mgmt_segment.
	SharedQueueMgmtOffset = 82
	// SharedQueueDataOffset is the offset of data_segment[0] (82 + 4096).
	SharedQueueDataOffset = SharedQueueMgmtOffset + SharedMemSegmentSize
)

// Ring queue management-segment semantics (shared_ring_queue.c:31-34). The
// management segment is a uint16_t array; each entry stores the size of the
// message starting at that data segment, or one of these magic values.
const (
	// MagicEmptySegment marks a free data segment.
	MagicEmptySegment uint16 = 0xfffe
	// MagicSkipSegment marks a continuation of the previous message.
	MagicSkipSegment uint16 = 0xfffd
	// MaxWriteSize is the upper bound on a single message size.
	MaxWriteSize uint32 = 0xfffc
	// MaxDataSegments is sizeof(DataSegment)/sizeof(uint16_t) = 2048.
	MaxDataSegments uint16 = SharedMemSegmentSize / 2
)
