package ntapi

import (
	"os"
	"strings"
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
	HandleType() string
}

// FileHandle wraps a VFS file descriptor.
type FileHandle struct {
	FD            int
	Path          string
	Access        uint32
	DeletePending bool
	DirIndex      int
	DirMask       string
}

func (h *FileHandle) HandleType() string { return "file" }

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

func (h *EventHandle) HandleType() string { return "event" }

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

// Signal is an alias for Set (used by NtFsControlFile pipe completion).
func (h *EventHandle) Signal() { h.Set() }

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
	mu        sync.Mutex
	cond      *sync.Cond
	ownerTID  uint32 // TID of the thread that owns the mutex (0 = unowned)
	count     int32  // recursion count (>0 = locked)
	abandoned bool   // set when owning thread exits without releasing
}

func (h *MutantHandle) HandleType() string { return "mutant" }

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

func (h *SemaphoreHandle) HandleType() string { return "semaphore" }

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

func (h *IoCompletionPortHandle) HandleType() string { return "iocp" }

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

func (h *RegistryKeyHandle) HandleType() string { return "regkey" }

// SectionHandle represents a memory section object.
type SectionHandle struct {
	Size      uint64
	Perms     uint8
	FileFD    int
	Path      string
	ViewSizes map[uint64]uint64
}

func (h *SectionHandle) HandleType() string { return "section" }

// FileMappingHandle represents a Win32 file mapping (CreateFileMapping).
// HostBuf holds the in-memory copy of the file or anonymous buffer.
// FileFD is -1 for anonymous mappings, otherwise a VFS file descriptor.
type FileMappingHandle struct {
	Name    string
	HostBuf []byte
	Size    uint64
	FileFD  int // -1 for anonymous; VFS fd for file-backed
	Protect uint32
}

func (h *FileMappingHandle) HandleType() string { return "filemapping" }

// HeapHandle represents a Win32 heap.
type HeapHandle struct {
	Allocations map[uint64]uint64 // guest address → size
}

func (h *HeapHandle) HandleType() string { return "heap" }

// FindHandle is used by FindFirstFileW/FindNextFileW for directory enumeration.
type FindHandle struct {
	Entries []os.DirEntry
	Idx     int
	Dir     string
}

func (f *FindHandle) HandleType() string { return "find" }

// ThreadHandle represents a Win32 thread handle.
type ThreadHandle struct {
	TID              int
	Done             chan struct{} // closed when the thread exits
	ExitCode         uint32
	Priority         int32
	HideFromDebugger bool
}

func (h *ThreadHandle) HandleType() string { return "thread" }

// NamedPipeHandle represents one end of a named pipe.
// ToServer carries data client→server; ToClient carries data server→client.
type NamedPipeHandle struct {
	Name      string
	ToServer  chan []byte // client writes here, server reads
	ToClient  chan []byte // server writes here, client reads
	Connected bool
	Server    bool
	readBuf   []byte
	mu        sync.Mutex
}

func (h *NamedPipeHandle) HandleType() string { return "named_pipe" }

// NewServerPipe creates a server-side NamedPipeHandle with bidirectional channels.
func NewServerPipe(name string) *NamedPipeHandle {
	return &NamedPipeHandle{
		Name:     name,
		ToServer: make(chan []byte, 64),
		ToClient: make(chan []byte, 64),
		Server:   true,
	}
}

// NewClientPipe creates a client-side handle sharing a server's channels.
func NewClientPipe(server *NamedPipeHandle) *NamedPipeHandle {
	return &NamedPipeHandle{
		Name:      server.Name,
		ToServer:  server.ToServer,
		ToClient:  server.ToClient,
		Server:    false,
		Connected: true,
	}
}

// PipeRead reads up to len(p) bytes, blocking until data arrives.
func (h *NamedPipeHandle) PipeRead(p []byte) int {
	h.mu.Lock()
	if len(h.readBuf) > 0 {
		n := copy(p, h.readBuf)
		h.readBuf = h.readBuf[n:]
		h.mu.Unlock()
		return n
	}
	h.mu.Unlock()
	ch := h.ToServer
	if !h.Server {
		ch = h.ToClient
	}
	select {
	case data, ok := <-ch:
		if !ok {
			return 0
		}
		n := copy(p, data)
		if n < len(data) {
			h.mu.Lock()
			h.readBuf = append(h.readBuf, data[n:]...)
			h.mu.Unlock()
		}
		return n
	case <-time.After(5 * time.Second):
		return 0
	}
}

// PipeWrite sends a copy of data into the pipe. Returns false if channel is full.
func (h *NamedPipeHandle) PipeWrite(data []byte) bool {
	cp := make([]byte, len(data))
	copy(cp, data)
	ch := h.ToClient
	if !h.Server {
		ch = h.ToServer
	}
	select {
	case ch <- cp:
		return true
	default:
		return false
	}
}

// DrainAll discards all buffered data in both directions.
func (h *NamedPipeHandle) DrainAll() {
	h.mu.Lock()
	h.readBuf = nil
	h.mu.Unlock()
	for {
		select {
		case <-h.ToServer:
		default:
			goto dS
		}
	}
dS:
	for {
		select {
		case <-h.ToClient:
		default:
			return
		}
	}
}

// ReadBuf returns a copy of the internal read buffer (for peeking).
func (h *NamedPipeHandle) ReadBuf() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	cp := make([]byte, len(h.readBuf))
	copy(cp, h.readBuf)
	return cp
}

// AvailableBytes returns the number of bytes available to read without blocking.
func (h *NamedPipeHandle) AvailableBytes() int {
	h.mu.Lock()
	buffered := len(h.readBuf)
	h.mu.Unlock()
	ch := h.ToServer
	if !h.Server {
		ch = h.ToClient
	}
	for {
		select {
		case data := <-ch:
			h.mu.Lock()
			h.readBuf = append(h.readBuf, data...)
			buffered = len(h.readBuf)
			h.mu.Unlock()
		default:
			return buffered
		}
	}
}

// TokenHandle is an access token kernel object.
type TokenHandle struct {
	UserSID         []byte
	PrimaryGroupSID []byte
	Groups          [][]byte
	Privileges      map[uint64]bool
	Restricted      bool
	Elevated        bool
	IntegrityLevel  uint32
}

func (h *TokenHandle) HandleType() string { return "token" }

// NewDefaultTokenHandle creates the synthetic process token used by the emulator.
func NewDefaultTokenHandle() *TokenHandle {
	return &TokenHandle{
		UserSID:         []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xF4, 0x01, 0x00, 0x00},
		PrimaryGroupSID: []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0x00, 0x00},
		Groups:          [][]byte{{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0x00, 0x00}},
		Privileges: map[uint64]bool{
			23: true, // SeChangeNotifyPrivilege
			33: true, // SeIncreaseWorkingSetPrivilege
		},
		Restricted:     false,
		Elevated:       true,
		IntegrityLevel: 12288, // high integrity
	}
}

// Clone returns a deep copy of the token state.
func (h *TokenHandle) Clone() *TokenHandle {
	if h == nil {
		return nil
	}
	cp := &TokenHandle{
		Restricted:     h.Restricted,
		Elevated:       h.Elevated,
		IntegrityLevel: h.IntegrityLevel,
	}
	if len(h.UserSID) > 0 {
		cp.UserSID = append([]byte(nil), h.UserSID...)
	}
	if len(h.PrimaryGroupSID) > 0 {
		cp.PrimaryGroupSID = append([]byte(nil), h.PrimaryGroupSID...)
	}
	if len(h.Groups) > 0 {
		cp.Groups = make([][]byte, len(h.Groups))
		for i := range h.Groups {
			cp.Groups[i] = append([]byte(nil), h.Groups[i]...)
		}
	}
	if len(h.Privileges) > 0 {
		cp.Privileges = make(map[uint64]bool, len(h.Privileges))
		for k, v := range h.Privileges {
			cp.Privileges[k] = v
		}
	}
	return cp
}

// SocketHandle wraps a raw OS socket file descriptor for Winsock emulation.
type SocketHandle struct {
	FD         int // OS-level file descriptor
	Family     int // AF_INET, AF_INET6, etc.
	SockType   int // SOCK_STREAM, SOCK_DGRAM, etc.
	Proto      int // IPPROTO_TCP, etc.
	mu         sync.Mutex
	lastWSAErr int32
}

func NewSocketHandle(fd, family, sockType, proto int) *SocketHandle {
	return &SocketHandle{FD: fd, Family: family, SockType: sockType, Proto: proto}
}
func (h *SocketHandle) HandleType() string { return "socket" }

// GetSocket returns the SocketHandle for a handle, or nil.
func (ht *HandleTable) GetSocket(h Handle) *SocketHandle {
	ht.mu.RLock()
	defer ht.mu.RUnlock()
	obj, ok := ht.handles[h]
	if !ok {
		return nil
	}
	s, ok := obj.(*SocketHandle)
	if !ok {
		return nil
	}
	return s
}

// WaitableTimerHandle is a Win32 waitable timer (manual or auto-reset).
type WaitableTimerHandle struct {
	mu          sync.Mutex
	ch          chan struct{}
	cancel      chan struct{}
	manualReset bool
	signaled    bool
}

func NewWaitableTimer(manualReset bool) *WaitableTimerHandle {
	return &WaitableTimerHandle{
		ch:          make(chan struct{}, 1),
		cancel:      make(chan struct{}),
		manualReset: manualReset,
	}
}

func (t *WaitableTimerHandle) HandleType() string { return "waitable_timer" }

// Set arms the timer to fire after 'due' from now (or at absolute time if negative Windows FILETIME).
// period is the recurring period in milliseconds (0 = one-shot).
func (t *WaitableTimerHandle) Set(due time.Duration, period time.Duration) {
	t.mu.Lock()
	// Cancel any existing goroutine
	select {
	case t.cancel <- struct{}{}:
	default:
	}
	t.signaled = false
	t.mu.Unlock()

	go func() {
		select {
		case <-time.After(due):
		case <-t.cancel:
			return
		}
		t.mu.Lock()
		t.signaled = true
		select {
		case t.ch <- struct{}{}:
		default:
		}
		t.mu.Unlock()
		if period > 0 {
			ticker := time.NewTicker(period)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					t.mu.Lock()
					t.signaled = true
					select {
					case t.ch <- struct{}{}:
					default:
					}
					t.mu.Unlock()
				case <-t.cancel:
					return
				}
			}
		}
	}()
}

// Cancel disarms the timer.
func (t *WaitableTimerHandle) Cancel() {
	select {
	case t.cancel <- struct{}{}:
	default:
	}
	t.mu.Lock()
	t.signaled = false
	t.mu.Unlock()
}

// IsSignaled returns whether the timer is currently signaled.
func (t *WaitableTimerHandle) IsSignaled() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.signaled
}

// WaitTimeout waits up to d for the timer to fire.
// Returns WAIT_OBJECT_0=0 or WAIT_TIMEOUT=0x102.
func (t *WaitableTimerHandle) WaitTimeout(d time.Duration) uint32 {
	t.mu.Lock()
	if t.signaled {
		if !t.manualReset {
			t.signaled = false
		}
		t.mu.Unlock()
		return 0 // WAIT_OBJECT_0
	}
	t.mu.Unlock()

	deadline := time.After(d)
	for {
		select {
		case <-t.ch:
			t.mu.Lock()
			t.signaled = true // re-check under lock
			sig := t.signaled
			if !t.manualReset {
				t.signaled = false
			}
			t.mu.Unlock()
			if sig {
				return 0
			}
		case <-deadline:
			return 0x102 // WAIT_TIMEOUT
		}
	}
}

// namedPipeRegistry is a global registry of named pipe server endpoints.
var namedPipeRegistry struct {
	mu    sync.RWMutex
	pipes map[string]*NamedPipeHandle // normalized name → server handle
}

func init() {
	namedPipeRegistry.pipes = make(map[string]*NamedPipeHandle)
}

// RegisterNamedPipe registers a server pipe by normalized name.
func RegisterNamedPipe(name string, h *NamedPipeHandle) {
	namedPipeRegistry.mu.Lock()
	namedPipeRegistry.pipes[strings.ToLower(name)] = h
	namedPipeRegistry.mu.Unlock()
}

// LookupNamedPipe finds a server pipe by normalized name.
func LookupNamedPipe(name string) *NamedPipeHandle {
	namedPipeRegistry.mu.RLock()
	h := namedPipeRegistry.pipes[strings.ToLower(name)]
	namedPipeRegistry.mu.RUnlock()
	return h
}

// UnregisterNamedPipe removes a pipe from the registry.
func UnregisterNamedPipe(name string) {
	namedPipeRegistry.mu.Lock()
	delete(namedPipeRegistry.pipes, strings.ToLower(name))
	namedPipeRegistry.mu.Unlock()
}

// GenericHandle is a catch-all handle for objects that don't need special behavior.
type GenericHandle struct {
	Kind string
}

func (h *GenericHandle) HandleType() string { return h.Kind }

// SymbolicLinkHandle represents an object-manager symbolic link.
type SymbolicLinkHandle struct {
	Name   string
	Target string
}

func (h *SymbolicLinkHandle) HandleType() string { return "symbolic_link" }

// CondVarEntry is a guest CONDITION_VARIABLE backed by a channel.
// Since the guest CPU is single-threaded, Sleep always times out - callers recheck.
type CondVarEntry struct {
	mu      sync.Mutex
	waiters int
	ch      chan struct{}
}

func newCondVarEntry() *CondVarEntry {
	return &CondVarEntry{ch: make(chan struct{}, 64)}
}

// Lock acquires the entry's mutex.
func (c *CondVarEntry) Lock() { c.mu.Lock() }

// Unlock releases the entry's mutex.
func (c *CondVarEntry) Unlock() { c.mu.Unlock() }

// Signal wakes one waiter.
func (c *CondVarEntry) Signal() {
	select {
	case c.ch <- struct{}{}:
	default:
	}
}

// Broadcast wakes all current waiters.
func (c *CondVarEntry) Broadcast() {
	c.mu.Lock()
	n := c.waiters
	c.mu.Unlock()
	for i := 0; i < n; i++ {
		select {
		case c.ch <- struct{}{}:
		default:
		}
	}
}

// Wait blocks until a signal is received. Must be called with Lock held.
func (c *CondVarEntry) Wait() {
	c.waiters++
	c.mu.Unlock()
	<-c.ch
	c.mu.Lock()
	c.waiters--
}

// Sleep waits up to d for a signal and returns true (always - caller rechecks condition).
func (c *CondVarEntry) Sleep(d time.Duration) bool {
	c.mu.Lock()
	c.waiters++
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.waiters--
		c.mu.Unlock()
	}()
	if d <= 0 {
		d = time.Millisecond
	}
	select {
	case <-c.ch:
	case <-time.After(d):
	}
	return true
}

// CondVarTable maps guest CONDITION_VARIABLE addresses to entries.
type CondVarTable struct {
	mu      sync.RWMutex
	entries map[uint64]*CondVarEntry
}

func NewCondVarTable() *CondVarTable {
	return &CondVarTable{entries: make(map[uint64]*CondVarEntry)}
}

// Get returns the entry for addr, creating it if necessary.
func (t *CondVarTable) Get(addr uint64) *CondVarEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.entries[addr]; ok {
		return e
	}
	e := newCondVarEntry()
	t.entries[addr] = e
	return e
}

// GlobalCondVars is the process-wide condition variable table.
var GlobalCondVars = NewCondVarTable()

// ──────────────────────────────────────────────────────────
// KeyedEventHandle - NtCreateKeyedEvent / NtWaitForKeyedEvent / NtReleaseKeyedEvent
//
// Semantics (ReactOS ntoskrnl/ex/keyedevt.c):
//
//	Wait: if a pending release for [key] exists, consume it and return.
//	      Otherwise, block until a release arrives.
//	Release: if a thread is waiting on [key], wake it and return.
//	         Otherwise, block until a waiter arrives.
//	This is a rendezvous primitive - both sides must pair up.
//
// ──────────────────────────────────────────────────────────
type keyedSlot struct {
	ch chan struct{} // buffered(1) channel used as the wake signal
}

// KeyedEventHandle is the NT keyed-event object.
type KeyedEventHandle struct {
	mu        sync.Mutex
	Name      string
	waiters   map[uint64][]chan struct{} // key → list of blocked waiters
	releasers map[uint64][]chan struct{} // key → list of blocked releasers
}

func NewKeyedEvent(name string) *KeyedEventHandle {
	return &KeyedEventHandle{
		Name:      name,
		waiters:   make(map[uint64][]chan struct{}),
		releasers: make(map[uint64][]chan struct{}),
	}
}

func (k *KeyedEventHandle) HandleType() string { return "keyed-event" }

// Wait blocks until a matching Release for key is called (or timeout).
func (k *KeyedEventHandle) Wait(key uint64, timeout time.Duration) uint32 {
	k.mu.Lock()
	// If there's a pending releaser waiting for a taker, consume it.
	if list := k.releasers[key]; len(list) > 0 {
		ch := list[0]
		k.releasers[key] = list[1:]
		k.mu.Unlock()
		ch <- struct{}{} // wake the releaser
		return 0         // STATUS_SUCCESS
	}
	// No releaser yet - enqueue ourselves and block.
	ch := make(chan struct{}, 1)
	k.waiters[key] = append(k.waiters[key], ch)
	k.mu.Unlock()
	if timeout == 0 {
		timeout = 30 * time.Second // cap infinite
	}
	select {
	case <-ch:
		return 0 // STATUS_SUCCESS
	case <-time.After(timeout):
		k.mu.Lock()
		list := k.waiters[key]
		for i, c := range list {
			if c == ch {
				k.waiters[key] = append(list[:i], list[i+1:]...)
				break
			}
		}
		k.mu.Unlock()
		return 0x00000102 // STATUS_TIMEOUT
	}
}

// Release wakes a waiter for key, or blocks until one arrives.
func (k *KeyedEventHandle) Release(key uint64, timeout time.Duration) uint32 {
	k.mu.Lock()
	if list := k.waiters[key]; len(list) > 0 {
		ch := list[0]
		k.waiters[key] = list[1:]
		k.mu.Unlock()
		ch <- struct{}{} // wake the waiter
		return 0
	}
	// No waiter yet - enqueue ourselves.
	ch := make(chan struct{}, 1)
	k.releasers[key] = append(k.releasers[key], ch)
	k.mu.Unlock()
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	select {
	case <-ch:
		return 0
	case <-time.After(timeout):
		k.mu.Lock()
		list := k.releasers[key]
		for i, c := range list {
			if c == ch {
				k.releasers[key] = append(list[:i], list[i+1:]...)
				break
			}
		}
		k.mu.Unlock()
		return 0x00000102
	}
}

// GlobalKeyedEvent is the fallback keyed event (Handle==NULL means use this).
var GlobalKeyedEvent = NewKeyedEvent("CritSecOutOfMemoryEvent")

// JobHandle represents a Win32 Job Object.
type JobHandle struct {
	mu     sync.Mutex
	Name   string
	PIDs   []uint32
	Limits JobLimits
}

// JobLimits holds the configurable limits for a job object.
type JobLimits struct {
	ActiveProcessLimit uint32
	PriorityClass      uint32
	SchedulingClass    uint32
	MaxWorkingSetSize  uint64
	MinWorkingSetSize  uint64
	PerProcessUserTime int64
	PerJobUserTime     int64
	KillOnJobClose     bool
	BreakawayOK        bool
}

func NewJobHandle(name string) *JobHandle {
	return &JobHandle{Name: name}
}

func (j *JobHandle) HandleType() string { return "job" }

// AddProcess adds a process ID to the job.
func (j *JobHandle) AddProcess(pid uint32) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.PIDs = append(j.PIDs, pid)
}

// MailslotHandle represents a Win32 mailslot.
type MailslotHandle struct {
	Name        string
	MaxMsgSize  uint32
	ReadTimeout uint32
	mu          sync.Mutex
	msgs        [][]byte
}

func NewMailslot(name string, maxMsg, readTimeout uint32) *MailslotHandle {
	return &MailslotHandle{
		Name:        name,
		MaxMsgSize:  maxMsg,
		ReadTimeout: readTimeout,
	}
}

func (m *MailslotHandle) HandleType() string { return "mailslot" }

// Write adds a message to the mailslot.
func (m *MailslotHandle) Write(msg []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, msg)
}

// Read removes and returns the next message, or nil.
func (m *MailslotHandle) Read() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.msgs) == 0 {
		return nil
	}
	msg := m.msgs[0]
	m.msgs = m.msgs[1:]
	return msg
}

// Count returns pending message count.
func (m *MailslotHandle) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.msgs)
}

// VEHHandler stores a vectored exception handler registered by the guest.
type VEHHandler struct {
	ID    uint64 // opaque registration handle returned to caller
	Addr  uint64 // guest function pointer
	First bool   // first-chance (first=true) or last-chance
}

// VEHRegistry stores vectored exception handlers for a process.
type VEHRegistry struct {
	mu       sync.Mutex
	handlers []*VEHHandler
	nextID   uint64
}

var GlobalVEH = &VEHRegistry{}
var GlobalVCH = &VEHRegistry{} // vectored continue handlers

// Add registers a handler. first=true means "first in chain".
func (v *VEHRegistry) Add(addr uint64, first bool) uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.nextID++
	if v.nextID == 0 {
		v.nextID = 1
	}
	h := &VEHHandler{ID: v.nextID, Addr: addr, First: first}
	if first {
		v.handlers = append([]*VEHHandler{h}, v.handlers...)
	} else {
		v.handlers = append(v.handlers, h)
	}
	return h.ID
}

// Remove unregisters a handler by its registration handle.
// For compatibility we also accept the raw handler function address.
func (v *VEHRegistry) Remove(handleOrAddr uint64) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i, h := range v.handlers {
		if h.ID == handleOrAddr || h.Addr == handleOrAddr {
			v.handlers = append(v.handlers[:i], v.handlers[i+1:]...)
			return true
		}
	}
	return false
}

// GetAll returns all handlers in order.
func (v *VEHRegistry) GetAll() []*VEHHandler {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]*VEHHandler, len(v.handlers))
	copy(out, v.handlers)
	return out
}

// globalMailslots maps name → mailslot.
var globalMailslots struct {
	mu    sync.RWMutex
	slots map[string]*MailslotHandle
}

func init() {
	globalMailslots.slots = make(map[string]*MailslotHandle)
}

// RegisterMailslot registers a named mailslot.
func RegisterMailslot(name string, m *MailslotHandle) {
	globalMailslots.mu.Lock()
	globalMailslots.slots[strings.ToLower(name)] = m
	globalMailslots.mu.Unlock()
}

// LookupMailslot finds a mailslot by name.
func LookupMailslot(name string) *MailslotHandle {
	globalMailslots.mu.RLock()
	defer globalMailslots.mu.RUnlock()
	return globalMailslots.slots[strings.ToLower(name)]
}

// HandleTable maps guest HANDLE values to Go objects.
type HandleTable struct {
	mu      sync.RWMutex
	handles map[Handle]HandleObject
	nextID  Handle

	// Named object namespace (global across all handles)
	namedMu sync.RWMutex
	named   map[string]Handle // normalized name → handle
	names   map[Handle]string // handle → name (for cleanup on Close)
}

// NewHandleTable creates an empty handle table.
// Handles start at 0x100 to avoid collision with pseudo-handles.
func NewHandleTable() *HandleTable {
	return &HandleTable{
		handles: make(map[Handle]HandleObject),
		nextID:  0x100,
		named:   make(map[string]Handle),
		names:   make(map[Handle]string),
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

// Close removes a handle from the table and cleans up any named mapping.
func (ht *HandleTable) Close(h Handle) bool {
	ht.mu.Lock()
	if _, ok := ht.handles[h]; !ok {
		ht.mu.Unlock()
		return false
	}
	delete(ht.handles, h)
	ht.mu.Unlock()

	// Clean up named mapping if this handle was named.
	ht.namedMu.Lock()
	if name, ok := ht.names[h]; ok {
		delete(ht.named, name)
		delete(ht.names, h)
	}
	ht.namedMu.Unlock()
	return true
}

// NormalizeObjectName strips NT object namespace prefixes and lowercases.
func NormalizeObjectName(name string) string {
	if name == "" {
		return ""
	}
	for _, prefix := range []string{
		`\BaseNamedObjects\`,
		`BaseNamedObjects\`,
		`Local\`,
		`Global\`,
	} {
		if strings.HasPrefix(name, prefix) {
			name = name[len(prefix):]
			break
		}
	}
	return strings.ToLower(name)
}

// AllocNamed registers obj under name, or returns the existing handle if name
// already exists. Returns (handle, true) if newly created, (existing, false)
// if already existed (caller should set ERROR_ALREADY_EXISTS).
func (ht *HandleTable) AllocNamed(name string, obj HandleObject) (Handle, bool) {
	norm := NormalizeObjectName(name)
	if norm == "" {
		return ht.Alloc(obj), true
	}

	ht.namedMu.Lock()
	defer ht.namedMu.Unlock()

	if existing, ok := ht.named[norm]; ok {
		return existing, false
	}

	h := ht.Alloc(obj)
	ht.named[norm] = h
	ht.names[h] = norm
	return h, true
}

// GetNamed returns the handle for a named object, or 0 if not found.
func (ht *HandleTable) GetNamed(name string) Handle {
	norm := NormalizeObjectName(name)
	if norm == "" {
		return 0
	}

	ht.namedMu.RLock()
	defer ht.namedMu.RUnlock()

	if h, ok := ht.named[norm]; ok {
		return h
	}
	return 0
}

// RLock acquires a read lock on the named objects table.
func (ht *HandleTable) RLock() { ht.namedMu.RLock() }

// RUnlock releases the read lock on the named objects table.
func (ht *HandleTable) RUnlock() { ht.namedMu.RUnlock() }

// Count returns the number of open handles.
func (ht *HandleTable) Count() int {
	ht.mu.RLock()
	defer ht.mu.RUnlock()
	return len(ht.handles)
}

// NameOf returns the registered name for a handle, if any.
func (ht *HandleTable) NameOf(h Handle) (string, bool) {
	n, ok := ht.names[h]
	return n, ok
}

// GetNamedPipe returns the NamedPipeHandle for a handle, or nil.
func (ht *HandleTable) GetNamedPipe(h Handle) *NamedPipeHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	np, ok := obj.(*NamedPipeHandle)
	if !ok {
		return nil
	}
	return np
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

// GetToken returns the TokenHandle for a handle, or nil.
func (ht *HandleTable) GetToken(h Handle) *TokenHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	tok, ok := obj.(*TokenHandle)
	if !ok {
		return nil
	}
	return tok
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

// GetTpPool returns the TpPool for a handle, or nil.
func (ht *HandleTable) GetTpPool(h Handle) *TpPool {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	tp, ok := obj.(*TpPool)
	if !ok {
		return nil
	}
	return tp
}

// GetTpWork returns the TpWork for a handle, or nil.
func (ht *HandleTable) GetTpWork(h Handle) *TpWork {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	tw, ok := obj.(*TpWork)
	if !ok {
		return nil
	}
	return tw
}

// GetTpTimer returns the TpTimer for a handle, or nil.
func (ht *HandleTable) GetTpTimer(h Handle) *TpTimer {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	tt, ok := obj.(*TpTimer)
	if !ok {
		return nil
	}
	return tt
}

// GetTpWait returns the TpWait for a handle, or nil.
func (ht *HandleTable) GetTpWait(h Handle) *TpWait {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	tw, ok := obj.(*TpWait)
	if !ok {
		return nil
	}
	return tw
}

// GetTpIo returns the TpIo for a handle, or nil.
func (ht *HandleTable) GetTpIo(h Handle) *TpIo {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	tio, ok := obj.(*TpIo)
	if !ok {
		return nil
	}
	return tio
}

// ======================== TIMER QUEUE TIMERS ========================

// TimerQueueTimer represents a CreateTimerQueueTimer timer.
type TimerQueueTimer struct {
	Callback uint64 // WAITORTIMERCALLBACK guest address
	Param    uint64 // lpParameter
	Period   uint32 // dwPeriod (ms), 0 = one-shot
	StopCh   chan struct{}
	running  bool
	mu       sync.Mutex
}

func (h *TimerQueueTimer) HandleType() string { return "timerqueuetimer" }

// Stop cancels the timer if running.
func (h *TimerQueueTimer) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		close(h.StopCh)
		h.StopCh = make(chan struct{})
		h.running = false
	}
}

// Arm starts the timer goroutine that calls fn after dueTime, then every period.
func (h *TimerQueueTimer) Arm(dueTime time.Duration, fn func()) {
	h.mu.Lock()
	if h.running {
		close(h.StopCh)
		h.StopCh = make(chan struct{})
	}
	h.running = true
	stopCh := h.StopCh
	period := time.Duration(h.Period) * time.Millisecond
	h.mu.Unlock()

	go func() {
		timer := time.NewTimer(dueTime)
		defer timer.Stop()
		select {
		case <-stopCh:
			return
		case <-timer.C:
		}
		fn()
		if period == 0 {
			h.mu.Lock()
			h.running = false
			h.mu.Unlock()
			return
		}
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				fn()
			}
		}
	}()
}

// GetTimerQueueTimer returns the TimerQueueTimer for a handle, or nil.
func (ht *HandleTable) GetTimerQueueTimer(h Handle) *TimerQueueTimer {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	tqt, ok := obj.(*TimerQueueTimer)
	if !ok {
		return nil
	}
	return tqt
}

// GetJob returns the JobHandle for a handle, or nil.
func (ht *HandleTable) GetJob(h Handle) *JobHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	j, ok := obj.(*JobHandle)
	if !ok {
		return nil
	}
	return j
}

// GetKeyedEvent returns the KeyedEventHandle for h, or nil.
func (ht *HandleTable) GetKeyedEvent(h Handle) *KeyedEventHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	ke, ok := obj.(*KeyedEventHandle)
	if !ok {
		return nil
	}
	return ke
}

// GetMailslot returns the MailslotHandle for a handle, or nil.
func (ht *HandleTable) GetMailslot(h Handle) *MailslotHandle {
	obj := ht.Get(h)
	if obj == nil {
		return nil
	}
	m, ok := obj.(*MailslotHandle)
	if !ok {
		return nil
	}
	return m
}

// ======================== CONSOLE STATE ========================

// ConsoleCellAttr is a character cell in the screen buffer.
type ConsoleCellAttr struct {
	Char uint16 // Unicode char
	Attr uint16 // color attribute
}

// ConsoleState holds the emulated console screen buffer.
type ConsoleState struct {
	mu            sync.Mutex
	Width         int
	Height        int
	CursorX       int
	CursorY       int
	Attr          uint16 // current text attribute
	Mode          uint32
	Title         string
	Cells         []ConsoleCellAttr // [y*Width+x]
	CursorVisible bool
	CursorSize    uint32
}

// NewConsoleState creates a default 80x300 console state.
func NewConsoleState() *ConsoleState {
	cs := &ConsoleState{
		Width:         80,
		Height:        300,
		Attr:          0x07, // grey on black
		Mode:          0x0007,
		Title:         "Raven Console",
		CursorVisible: true,
		CursorSize:    25,
	}
	cs.Cells = make([]ConsoleCellAttr, cs.Width*cs.Height)
	for i := range cs.Cells {
		cs.Cells[i] = ConsoleCellAttr{' ', 0x07}
	}
	return cs
}

// Clone returns a deep copy of the console state.
func (cs *ConsoleState) Clone() *ConsoleState {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cp := *cs
	cp.Cells = append([]ConsoleCellAttr(nil), cs.Cells...)
	return &cp
}

// CopyFrom replaces the console contents and metadata with src.
func (cs *ConsoleState) CopyFrom(src *ConsoleState) {
	if src == nil {
		return
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.Width = src.Width
	cs.Height = src.Height
	cs.CursorX = src.CursorX
	cs.CursorY = src.CursorY
	cs.Attr = src.Attr
	cs.Mode = src.Mode
	cs.Title = src.Title
	cs.CursorVisible = src.CursorVisible
	cs.CursorSize = src.CursorSize
	cs.Cells = append(cs.Cells[:0], src.Cells...)
	if len(cs.Cells) != src.Width*src.Height {
		cs.Cells = make([]ConsoleCellAttr, len(src.Cells))
		copy(cs.Cells, src.Cells)
	}
}

// GlobalConsole is the process-wide console state.
var GlobalConsole = NewConsoleState()

// ConsoleScreenBufferHandle represents a separate console screen buffer.
type ConsoleScreenBufferHandle struct {
	State *ConsoleState
}

func (h *ConsoleScreenBufferHandle) HandleType() string { return "console_screen_buffer" }

// NewConsoleScreenBuffer creates a screen buffer backed by its own console state.
func NewConsoleScreenBuffer() *ConsoleScreenBufferHandle {
	return &ConsoleScreenBufferHandle{State: NewConsoleState()}
}

// Cell returns the cell at (x,y), or nil if out of bounds.
func (cs *ConsoleState) Cell(x, y int) *ConsoleCellAttr {
	if x < 0 || x >= cs.Width || y < 0 || y >= cs.Height {
		return nil
	}
	return &cs.Cells[y*cs.Width+x]
}

// FillAttr fills nCells cells starting at (x,y) with attribute attr.
func (cs *ConsoleState) FillAttr(x, y, n int, attr uint16) int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	wrote := 0
	for i := 0; i < n; i++ {
		cx := x + i
		cy := y + cx/cs.Width
		cx = cx % cs.Width
		if c := cs.Cell(cx, cy); c != nil {
			c.Attr = attr
			wrote++
		}
	}
	return wrote
}

// FillChar fills nCells cells starting at (x,y) with character ch.
func (cs *ConsoleState) FillChar(x, y, n int, ch uint16, attr uint16) int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	wrote := 0
	for i := 0; i < n; i++ {
		cx := (x + i) % cs.Width
		cy := y + (x+i)/cs.Width
		if c := cs.Cell(cx, cy); c != nil {
			c.Char = ch
			c.Attr = attr
			wrote++
		}
	}
	return wrote
}

// Scroll scrolls the rectangle [left,top,right,bottom] by dx,dy.
// Vacated cells are filled with fillChar/fillAttr.
func (cs *ConsoleState) Scroll(left, top, right, bottom, dx, dy int, fillCh uint16, fillAttr uint16) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	// Copy cells
	tmp := make([]ConsoleCellAttr, cs.Width*cs.Height)
	copy(tmp, cs.Cells)
	for y := top; y <= bottom; y++ {
		for x := left; x <= right; x++ {
			nx, ny := x+dx, y+dy
			if nx >= left && nx <= right && ny >= top && ny <= bottom {
				if src := cs.Cell(x, y); src != nil {
					if dst := cs.Cell(nx, ny); dst != nil {
						*dst = *src
					}
				}
			}
		}
	}
	// Fill vacated area
	for y := top; y <= bottom; y++ {
		for x := left; x <= right; x++ {
			ox, oy := x-dx, y-dy
			if ox < left || ox > right || oy < top || oy > bottom {
				if c := cs.Cell(x, y); c != nil {
					*c = ConsoleCellAttr{fillCh, fillAttr}
				}
			}
		}
	}
}
