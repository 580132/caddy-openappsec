package protocol

// SessionAllocator issues session ids for requests sent to the engine.
//
// The nginx reference allocates ids as odd numbers starting at 3
// (ngx_cp_hooks.c:67-83): a per-worker counter is transformed with
// (counter << 1) | 1, which yields 3, 5, 7, ... Odd ids avoid colliding with
// Squid sessions, and 0 (CorruptedSessionID) is reserved. This type is not
// safe for concurrent use; callers with multiple workers must guard it.
type SessionAllocator struct {
	next uint32
}

// NewSessionAllocator returns an allocator whose first id is 3.
func NewSessionAllocator() *SessionAllocator {
	return &SessionAllocator{next: 3}
}

// Allocate returns the next session id.
func (a *SessionAllocator) Allocate() uint32 {
	id := a.next
	a.next += 2
	return id
}

// Reclaim returns id to the allocator so it can be reused. Only the most
// recently allocated id can be reclaimed; reclaiming an older id is a no-op.
func (a *SessionAllocator) Reclaim(id uint32) {
	if id+2 == a.next {
		a.next = id
	}
}
