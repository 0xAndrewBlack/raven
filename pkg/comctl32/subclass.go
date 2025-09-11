package comctl32

import "sync"

// Window subclassing (SetWindowSubclass / DefSubclassProc / RemoveWindowSubclass)
// ReactOS: comctl32/subclass.c

// SubclassProc is the callback signature for a window subclass procedure.
// In the emulator context we store the guest function pointer address.
type SubclassEntry struct {
	PfnSubclass uint64 // guest function pointer
	UIDSubclass uint32 // caller-supplied ID
	DwRefData   uint64 // caller-supplied ref data
}

var (
	subclassMu sync.Mutex
	// subclassChain maps hwnd → ordered list of subclass entries (most-recent first)
	subclassChain = map[uint64][]SubclassEntry{}
)

// SetWindowSubclass installs a subclass callback on hwnd.
// Returns true on success.
func SetWindowSubclass(hwnd uint64, pfnSubclass uint64, uIDSubclass uint32, dwRefData uint64) bool {
	subclassMu.Lock()
	defer subclassMu.Unlock()
	chain := subclassChain[hwnd]
	// If already present with same pfn+id, update refData
	for i, e := range chain {
		if e.PfnSubclass == pfnSubclass && e.UIDSubclass == uIDSubclass {
			chain[i].DwRefData = dwRefData
			subclassChain[hwnd] = chain
			return true
		}
	}
	// Prepend new entry (newest → highest priority)
	subclassChain[hwnd] = append([]SubclassEntry{{pfnSubclass, uIDSubclass, dwRefData}}, chain...)
	return true
}

// RemoveWindowSubclass removes a specific subclass.
func RemoveWindowSubclass(hwnd uint64, pfnSubclass uint64, uIDSubclass uint32) bool {
	subclassMu.Lock()
	defer subclassMu.Unlock()
	chain := subclassChain[hwnd]
	for i, e := range chain {
		if e.PfnSubclass == pfnSubclass && e.UIDSubclass == uIDSubclass {
			subclassChain[hwnd] = append(chain[:i], chain[i+1:]...)
			return true
		}
	}
	return false
}

// GetWindowSubclass retrieves refData for a subclass entry.
// Returns (refData, true) or (0, false).
func GetWindowSubclass(hwnd uint64, pfnSubclass uint64, uIDSubclass uint32) (uint64, bool) {
	subclassMu.Lock()
	defer subclassMu.Unlock()
	for _, e := range subclassChain[hwnd] {
		if e.PfnSubclass == pfnSubclass && e.UIDSubclass == uIDSubclass {
			return e.DwRefData, true
		}
	}
	return 0, false
}

// GetSubclassChain returns the subclass chain for hwnd (snapshot, caller must not modify).
func GetSubclassChain(hwnd uint64) []SubclassEntry {
	subclassMu.Lock()
	defer subclassMu.Unlock()
	src := subclassChain[hwnd]
	if len(src) == 0 {
		return nil
	}
	out := make([]SubclassEntry, len(src))
	copy(out, src)
	return out
}

// RemoveAllSubclasses removes all subclass entries for hwnd (called on window destroy).
func RemoveAllSubclasses(hwnd uint64) {
	subclassMu.Lock()
	defer subclassMu.Unlock()
	delete(subclassChain, hwnd)
}
