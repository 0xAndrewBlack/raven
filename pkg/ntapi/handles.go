package ntapi

import (
	"os"
	"sync"
	"time"
)

// HANDLE type for Windows guest.
type Handle uint64

const (
	InvalidHandle Handle = 0xFFFFFFFFFFFFFFFF
)

// HandleObject is any object tracked by the handle table.
type HandleObject interface {
	handleType() string
}

// FileHandle wraps a VFS file descriptor.
type FileHandle struct {
	FD   int
	Path string
}

func (h *FileHandle) handleType() string { return "file" }

// EventHandle is a Win32 event synchronization object.
type EventHandle struct {
	mu        sync.Mutex
	cond      *sync.Cond
	signaled  bool
	autoReset bool
}

// NewEvent creates an EventHandle with the given manual-reset and initial state.
func NewEvent(manualReset, initialState bool) *EventHandle {
	eh := &EventHandle{autoReset: !manualReset}
	if initialState {
		eh.signaled = true
	}
	return eh
}

func (h *EventHandle) handleType() string { return "event" }

func (h *EventHandle) getCond() *sync.Cond {
	if h.cond == nil {
		h.cond = sync.NewCond(&h.mu)
	}
	return h.cond
}

// Set signals the event (SetEvent).
func (h *EventHandle) Set() {
	h.mu.Lock()
	h.signaled = true
	if h.cond != nil {
		h.cond.Broadcast()
	}
	h.mu.Unlock()
}

// Reset clears the event signal (ResetEvent).
func (h *EventHandle) Reset() {
	h.mu.Lock()
	h.signaled = false
	h.mu.Unlock()
}

// IsSignaled returns whether the event is signaled.
// If autoReset is true, it clears the signal after returning true.
func (h *EventHandle) IsSignaled() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.signaled {
		if h.autoReset {
			h.signaled = false
		}
		return true
	}
	return false
}

// WaitTimeout blocks until the event is signaled or the timeout expires.
// Pass d < 0 for INFINITE wait. Returns true if signaled, false on timeout.
func (h *EventHandle) WaitTimeout(d time.Duration) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.signaled {
		if h.autoReset {
			h.signaled = false
		}
		return true
	}
	if d == 0 {
		return false
	}
	c := h.getCond()
	if d < 0 {
		for !h.signaled {
			c.Wait()
		}
		if h.autoReset {
			h.signaled = false
		}
		return true
	}
	// Timed wait: fire a broadcast after the timeout to unblock.
	deadline := time.Now().Add(d)
	go func() {
		time.Sleep(d)
		h.mu.Lock()
		c.Broadcast()
		h.mu.Unlock()
	}()
	for !h.signaled && time.Now().Before(deadline) {
		c.Wait()
	}
	if h.signaled {
		if h.autoReset {
			h.signaled = false
		}
		return true
	}
	return false
}

// WaitChan returns a channel that receives once when the event is signaled.
// Used by WaitForMultipleObjects to fan-in multiple handles with reflect.Select.
func (h *EventHandle) WaitChan() <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		h.WaitTimeout(-1)
		ch <- struct{}{}
	}()
	return ch
}

// MutantHandle is a Win32 mutex object (kernel mutant).
// ReactOS reference: ntoskrnl/ke/mutex.c
type MutantHandle struct {
	mu         sync.Mutex
	cond       *sync.Cond
	ownerTID   uint32 // TID of the thread that owns the mutex (0 = unowned)
	count      int32  // recursion count (>0 = locked)
	abandoned  bool   // set when owning thread exits without releasing
}

func (h *MutantHandle) handleType() string { return "mutant" }

func (h *MutantHandle) getCond() *sync.Cond {
	if h.cond == nil {
		h.cond = sync.NewCond(&h.mu)
	}
	return h.cond
}

// IsSignaled returns true when the mutex is unowned (can be acquired).
func (h *MutantHandle) IsSignaled() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count == 0
}

// WaitTimeout tries to acquire the mutex, blocking up to d.
// Returns WAIT_OBJECT_0 (0), WAIT_ABANDONED (0x80), or WAIT_TIMEOUT (0x102).
// Pass tid = current thread ID, d < 0 for INFINITE.
func (h *MutantHandle) WaitTimeout(tid uint32, d time.Duration) uint32 {
	const (
		waitObject0   = uint32(0x00000000)
		waitAbandoned = uint32(0x00000080)
		waitTimeout   = uint32(0x00000102)
	)
	h.mu.Lock()
	defer h.mu.Unlock()

	// Recursive acquisition by the same thread.
	if h.ownerTID == tid && tid != 0 && h.count > 0 {
		h.count++
		return waitObject0
	}

	// Try non-blocking acquire.
	if h.count == 0 {
		wasAbandoned := h.abandoned
		h.ownerTID = tid
		h.count = 1
		h.abandoned = false
		if wasAbandoned {
			return waitAbandoned
		}
		return waitObject0
	}

	if d == 0 {
		return waitTimeout
	}

	c := h.getCond()
	if d < 0 {
		// INFINITE: block until unowned.
		for h.count != 0 {
			c.Wait()
		}
	} else {
		deadline := time.Now().Add(d)
		go func() {
			time.Sleep(d)
			h.mu.Lock()
			c.Broadcast()
			h.mu.Unlock()
		}()
		for h.count != 0 && time.Now().Before(deadline) {
			c.Wait()
		}
		if h.count != 0 {
			return waitTimeout
		}
	}

	wasAbandoned := h.abandoned
	h.ownerTID = tid
	h.count = 1
	h.abandoned = false
	if wasAbandoned {
		return waitAbandoned
	}
	return waitObject0
}

// Release releases one level of mutex ownership by tid.
// Returns true on success.
func (h *MutantHandle) Release(tid uint32) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.count == 0 || (tid != 0 && h.ownerTID != tid) {
		return false
	}
	h.count--
	if h.count == 0 {
		h.ownerTID = 0
		if h.cond != nil {
			h.cond.Signal()
		}
	}
	return true
}

// Abandon marks the mutex as abandoned (owning thread exited).
func (h *MutantHandle) Abandon() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.count > 0 {
		h.count = 0
		h.ownerTID = 0
		h.abandoned = true
		if h.cond != nil {
			h.cond.Broadcast()
		}
	}
}

// WaitChan returns a channel that fires once when the mutex becomes acquirable.
func (h *MutantHandle) WaitChan(tid uint32) <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		h.WaitTimeout(tid, -1)
		ch <- struct{}{}
	}()
	return ch
}

// SemaphoreHandle is a Win32 semaphore object.
// ReactOS reference: ntoskrnl/ke/semaphor.c
type SemaphoreHandle struct {
	mu       sync.Mutex
	cond     *sync.Cond
	count    int32
	maxCount int32
}

// NewSemaphore creates a semaphore with the given initial and maximum counts.
func NewSemaphore(initial, max int32) *SemaphoreHandle {
	return &SemaphoreHandle{count: initial, maxCount: max}
}

func (h *SemaphoreHandle) handleType() string { return "semaphore" }

func (h *SemaphoreHandle) getCond() *sync.Cond {
	if h.cond == nil {
		h.cond = sync.NewCond(&h.mu)
	}
	return h.cond
}

// WaitTimeout decrements the semaphore count, blocking until count > 0 or timeout.
// Returns WAIT_OBJECT_0 (0) or WAIT_TIMEOUT (0x102).
func (h *SemaphoreHandle) WaitTimeout(d time.Duration) uint32 {
	const (
		waitObject0 = uint32(0x00000000)
		waitTimeout = uint32(0x00000102)
	)
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.count > 0 {
		h.count--
		return waitObject0
	}
	if d == 0 {
		return waitTimeout
	}

	c := h.getCond()
	if d < 0 {
		for h.count == 0 {
			c.Wait()
		}
	} else {
		deadline := time.Now().Add(d)
		go func() {
			time.Sleep(d)
			h.mu.Lock()
			c.Broadcast()
			h.mu.Unlock()
		}()
		for h.count == 0 && time.Now().Before(deadline) {
			c.Wait()
		}
		if h.count == 0 {
			return waitTimeout
		}
	}
	h.count--
	return waitObject0
}

// Release increases the semaphore count by releaseCount.
// Returns the previous count and true on success.
func (h *SemaphoreHandle) Release(releaseCount int32) (int32, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if releaseCount <= 0 || h.count+releaseCount > h.maxCount {
		return 0, false
	}
	prev := h.count
	h.count += releaseCount
	if h.cond != nil {
		if releaseCount == 1 {
			h.cond.Signal()
		} else {
			h.cond.Broadcast()
		}
	}
	return prev, true
}

// WaitChan returns a channel that fires once when the semaphore can be acquired.
func (h *SemaphoreHandle) WaitChan() <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		h.WaitTimeout(-1)
		ch <- struct{}{}
	}()
	return ch
}

// IoCompletionPacket is a single completion notification entry.
type IoCompletionPacket struct {
	CompletionKey    uint64
	Overlapped       uint64
	BytesTransferred uint32
	Status           uint32
}

// IoCompletionPortHandle is a Win32 I/O Completion Port.
// ReactOS reference: ntoskrnl/io/comp.c
type IoCompletionPortHandle struct {
	mu      sync.Mutex
	cond    *sync.Cond
	packets []IoCompletionPacket
	closed  bool
}

func (h *IoCompletionPortHandle) handleType() string { return "iocp" }

func (h *IoCompletionPortHandle) getCond() *sync.Cond {
	if h.cond == nil {
		h.cond = sync.NewCond(&h.mu)
	}
	return h.cond
}

// Post enqueues a completion packet and wakes one waiting goroutine.
func (h *IoCompletionPortHandle) Post(key, overlapped uint64, bytes uint32, status uint32) {
	h.mu.Lock()
	h.packets = append(h.packets, IoCompletionPacket{
		CompletionKey:    key,
		Overlapped:       overlapped,
		BytesTransferred: bytes,
		Status:           status,
	})
	h.getCond().Signal()
	h.mu.Unlock()
}

// Remove dequeues one packet, blocking until available or timeout.
// Returns the packet and true on success, or zero-value + false on timeout.
// Pass d < 0 for INFINITE.
func (h *IoCompletionPortHandle) Remove(d time.Duration) (IoCompletionPacket, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.packets) > 0 {
		pkt := h.packets[0]
		h.packets = h.packets[1:]
		return pkt, true
	}
	if d == 0 {
		return IoCompletionPacket{}, false
	}

	c := h.getCond()
	if d < 0 {
		for len(h.packets) == 0 && !h.closed {
			c.Wait()
		}
	} else {
		deadline := time.Now().Add(d)
		go func() {
			time.Sleep(d)
			h.mu.Lock()
			c.Broadcast()
			h.mu.Unlock()
		}()
		for len(h.packets) == 0 && !h.closed && time.Now().Before(deadline) {
			c.Wait()
		}
	}

	if len(h.packets) == 0 {
		return IoCompletionPacket{}, false
	}
	pkt := h.packets[0]
	h.packets = h.packets[1:]
	return pkt, true
}

// RegistryKeyHandle wraps a registry key reference.
type RegistryKeyHandle struct {
	Hive *RegistryHive
	Key  *RegistryKey
	Path string // full normalized path e.g. HKEY_LOCAL_MACHINE\SOFTWARE\...
}

func (h *RegistryKeyHandle) handleType() string { return "regkey" }

// SectionHandle represents a memory section object.
type SectionHandle struct {
	Size  uint64
	Perms uint8
}

func (h *SectionHandle) handleType() string { return "section" }

// FileMappingHandle represents a Win32 file mapping (CreateFileMapping).
// HostBuf holds the in-memory copy of the file or anonymous buffer.
// FileFD is -1 for anonymous mappings, otherwise a VFS file descriptor.
type FileMappingHandle struct {
	Name    string
	HostBuf []byte
	Size    uint64
	FileFD  int    // -1 for anonymous; VFS fd for file-backed
	Protect uint32
}

func (h *FileMappingHandle) handleType() string { return "filemapping" }

// HeapHandle represents a Win32 heap.
type HeapHandle struct {
	Allocations map[uint64]uint64 // guest address → size
}

func (h *HeapHandle) handleType() string { return "heap" }

// FindHandle is used by FindFirstFileW/FindNextFileW for directory enumeration.
type FindHandle struct {
	Entries []os.DirEntry
	Idx     int
	Dir     string
}

func (f *FindHandle) handleType() string { return "find" }

// ThreadHandle represents a Win32 thread handle.
type ThreadHandle struct {
	TID      int
	Done     chan struct{} // closed when the thread exits
	ExitCode uint32
}

func (h *ThreadHandle) handleType() string { return "thread" }

// GenericHandle is a catch-all handle for objects that don't need special behavior.
type GenericHandle struct {
	Kind string
}

func (h *GenericHandle) handleType() string { return h.Kind }

// HandleTable maps guest HANDLE values to Go objects.
type HandleTable struct {
	mu       sync.RWMutex
	handles  map[Handle]HandleObject
	nextID   Handle
}

// NewHandleTable creates an empty handle table.
// Handles start at 0x100 to avoid collision with pseudo-handles.
func NewHandleTable() *HandleTable {
	return &HandleTable{
		handles: make(map[Handle]HandleObject),
		nextID:  0x100,
	}
}

// Alloc assigns a new handle to the given object.
func (ht *HandleTable) Alloc(obj HandleObject) Handle {
	ht.mu.Lock()
	defer ht.mu.Unlock()
	h := ht.nextID
	ht.nextID += 4 // Windows handles are multiples of 4
	ht.handles[h] = obj
	return h
}

// Get retrieves the object for a handle, or nil if not found.
func (ht *HandleTable) Get(h Handle) HandleObject {
	ht.mu.RLock()
	defer ht.mu.RUnlock()
	return ht.handles[h]
}

// Close removes a handle from the table.
func (ht *HandleTable) Close(h Handle) bool {
	ht.mu.Lock()
	defer ht.mu.Unlock()
	if _, ok := ht.handles[h]; !ok {
		return false
	}
	delete(ht.handles, h)
	return true
}

// GetFile returns the FileHandle for a handle, or nil.
func (ht *HandleTable) GetFile(h Handle) *FileHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	fh, ok := obj.(*FileHandle)
	if !ok {
		return nil
	}
	return fh
}

// GetEvent returns the EventHandle for a handle, or nil.
func (ht *HandleTable) GetEvent(h Handle) *EventHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	eh, ok := obj.(*EventHandle)
	if !ok {
		return nil
	}
	return eh
}

// GetThread returns the ThreadHandle for a handle, or nil.
func (ht *HandleTable) GetThread(h Handle) *ThreadHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	th, ok := obj.(*ThreadHandle)
	if !ok {
		return nil
	}
	return th
}

// GetRegKey returns the RegistryKeyHandle for a handle, or nil.
func (ht *HandleTable) GetRegKey(h Handle) *RegistryKeyHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	rk, ok := obj.(*RegistryKeyHandle)
	if !ok {
		return nil
	}
	return rk
}

// GetHeap returns the HeapHandle for a handle, or nil.
func (ht *HandleTable) GetHeap(h Handle) *HeapHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	hh, ok := obj.(*HeapHandle)
	if !ok {
		return nil
	}
	return hh
}

// GetSection returns the SectionHandle for a handle, or nil.
func (ht *HandleTable) GetSection(h Handle) *SectionHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	sh, ok := obj.(*SectionHandle)
	if !ok {
		return nil
	}
	return sh
}

// GetFileMapping returns the FileMappingHandle for a handle, or nil.
func (ht *HandleTable) GetFileMapping(h Handle) *FileMappingHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	fm, ok := obj.(*FileMappingHandle)
	if !ok {
		return nil
	}
	return fm
}

// GetMutant returns the MutantHandle for a handle, or nil.
func (ht *HandleTable) GetMutant(h Handle) *MutantHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	mh, ok := obj.(*MutantHandle)
	if !ok {
		return nil
	}
	return mh
}

// GetSemaphore returns the SemaphoreHandle for a handle, or nil.
func (ht *HandleTable) GetSemaphore(h Handle) *SemaphoreHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	sh, ok := obj.(*SemaphoreHandle)
	if !ok {
		return nil
	}
	return sh
}

// GetIoCompletion returns the IoCompletionPortHandle for a handle, or nil.
func (ht *HandleTable) GetIoCompletion(h Handle) *IoCompletionPortHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	ic, ok := obj.(*IoCompletionPortHandle)
	if !ok {
		return nil
	}
	return ic
}
