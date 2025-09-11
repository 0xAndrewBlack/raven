package ntapi

import (
	"os"
	"sync"
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
	signaled  bool
	autoReset bool
	waiters   chan struct{}
}

func (h *EventHandle) handleType() string { return "event" }

// Set signals the event (SetEvent).
func (h *EventHandle) Set() {
	h.mu.Lock()
	h.signaled = true
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

// MutantHandle is a Win32 mutex object.
type MutantHandle struct {
	mu       sync.Mutex
	ownerTID uint32
	count    int32
}

func (h *MutantHandle) handleType() string { return "mutant" }

// RegistryKeyHandle wraps a registry key reference.
type RegistryKeyHandle struct {
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
// BaseAddr is the allocated guest memory; Size is the mapping size.
// FileFD is -1 for anonymous mappings, otherwise a VFS file descriptor.
type FileMappingHandle struct {
	BaseAddr uint64
	Size     uint64
	FileFD   int
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
	TID int
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
