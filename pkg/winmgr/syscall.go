package winmgr

import "sync"

// Number-indexed syscall dispatch .
//
// Real ntdll/win32u stubs issue `syscall` with a numeric service index, not a
// name. To run real DLLs the kernel side must dispatch by NUMBER, on a table
// pinned to a fixed ReactOS revision (the name-based RegisterWin32kHandler path
// stays for synthetic stubs). This is that table: index -> {name, handler}.
//
// The indices below are PLACEHOLDERS structured like the ReactOS shadow SSDT;
// they MUST be regenerated from the pinned ReactOS build's win32k service table
// before running real DLLs . The dispatch
// machinery itself is final and tested.

// SyscallFn handles one numbered syscall: args are the raw register/stack
// arguments already marshalled by the trap layer; the return is the NTSTATUS or
// value placed in RAX.
type SyscallFn func(args []uint64) uint64

type syscallEntry struct {
	name string
	fn   SyscallFn
}

// SyscallTable maps service indices to handlers for one service table (the
// native Nt* table or the win32k shadow NtUser*/NtGdi* table).
type SyscallTable struct {
	mu      sync.RWMutex
	entries map[uint32]syscallEntry
	byName  map[string]uint32
}

// NewSyscallTable creates an empty table.
func NewSyscallTable() *SyscallTable {
	return &SyscallTable{entries: make(map[uint32]syscallEntry), byName: make(map[string]uint32)}
}

// Register binds a service index to a named handler. Re-registering an index
// replaces it. Panics on a name/index already mapped to a different pair only in
// tests; here it simply overwrites for flexibility during bring-up.
func (t *SyscallTable) Register(index uint32, name string, fn SyscallFn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[index] = syscallEntry{name: name, fn: fn}
	t.byName[name] = index
}

// IndexOf returns the service index registered for a name (ok=false if absent).
func (t *SyscallTable) IndexOf(name string) (uint32, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	i, ok := t.byName[name]
	return i, ok
}

// NameOf returns the name registered for an index (for tracing).
func (t *SyscallTable) NameOf(index uint32) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.entries[index]
	if !ok {
		return "", false
	}
	return e.name, true
}

// Dispatch invokes the handler for index with args. ok=false (and STATUS_NOT_
// IMPLEMENTED) if the index is unbound.
func (t *SyscallTable) Dispatch(index uint32, args []uint64) (ret uint64, ok bool) {
	t.mu.RLock()
	e, found := t.entries[index]
	t.mu.RUnlock()
	if !found {
		return 0xC0000002, false // STATUS_NOT_IMPLEMENTED
	}
	return e.fn(args), true
}

// Count returns the number of registered services (diagnostics).
func (t *SyscallTable) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}
