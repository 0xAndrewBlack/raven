package ntobj

// Additional kernel object types: the message-queue waitable (foundation for the
// win32k input/message system) and the section object (shared
// memory / mapped files).

// MessageQueue is a thread's input/message queue as a waitable object: it is
// signaled while messages are pending. A successful wait does NOT consume a
// message (Win32 MsgWaitForMultipleObjects only reports availability; the thread
// then drains with PeekMessage/GetMessage). The message queue connects this so GetMessage
// blocks correctly instead of spinning.
type MessageQueue struct {
	pending int
}

// NewMessageQueue creates an empty message queue.
func NewMessageQueue() *MessageQueue { return &MessageQueue{} }

func (q *MessageQueue) signaled(uint64) bool { return q.pending > 0 }
func (q *MessageQueue) satisfy(uint64) bool  { return false } // peeked, not consumed by the wait

// Post records that one message was enqueued and wakes waiters. Call via
// Manager.Signal.
func (q *MessageQueue) Post() { q.pending++ }

// PostN records n enqueued messages. Call via Manager.Signal.
func (q *MessageQueue) PostN(n int) {
	if n > 0 {
		q.pending += n
	}
}

// Drain clears the pending count (the thread has dequeued everything) and
// returns how many were pending. Call via Manager.Signal.
func (q *MessageQueue) Drain() int {
	n := q.pending
	q.pending = 0
	return n
}

// Pending returns the number of queued messages (manager lock held).
func (q *MessageQueue) Pending() int { return q.pending }

// Section is a shared-memory / file-mapping object (NtCreateSection). It is a
// reference-counted, possibly named object (so two opens of the same name share
// it) but it is not waitable. The actual page mapping into a view lives in the
// MMU; this carries the kernel-object identity and attributes.
type Section struct {
	Size        uint64 // maximum section size in bytes
	PageProtect uint32 // PAGE_* protection
	FileBacked  bool   // true if backed by a file object, false = pagefile-backed
	FileID      int    // backing file handle/fd when FileBacked (-1 otherwise)
	views       int    // number of mapped views (bookkeeping)
}

// NewSection creates a section payload (use with Manager.Create/CreateNamed).
func NewSection(size uint64, protect uint32, fileBacked bool, fileID int) *Section {
	return &Section{Size: size, PageProtect: protect, FileBacked: fileBacked, FileID: fileID}
}

// AddView/RemoveView track outstanding mapped views (manager lock held).
func (s *Section) AddView() { s.views++ }
func (s *Section) RemoveView() {
	if s.views > 0 {
		s.views--
	}
}

// Views returns the number of outstanding mapped views (manager lock held).
func (s *Section) Views() int { return s.views }
