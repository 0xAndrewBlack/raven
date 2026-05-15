//go:build guest_windows

package comctl32

import (
	"sync"
	"sync/atomic"
)

// SubclassEntry identifies a guest subclass procedure.
type SubclassEntry struct {
	PfnSubclass uint64
	UIDSubclass uint64
	DwRefData   uint64
	Token       uint64
}

type windowSubclasses struct {
	mu      sync.RWMutex
	entries []SubclassEntry
}

var (
	subclassWindows sync.Map
	subclassToken   atomic.Uint64
)

func subclassesForWindow(hwnd uint64, create bool) *windowSubclasses {
	if state, ok := subclassWindows.Load(hwnd); ok {
		return state.(*windowSubclasses)
	}
	if !create {
		return nil
	}
	state := new(windowSubclasses)
	actual, _ := subclassWindows.LoadOrStore(hwnd, state)
	return actual.(*windowSubclasses)
}

// SetWindowSubclass installs a subclass callback on hwnd.
func SetWindowSubclass(hwnd, pfnSubclass, uIDSubclass, dwRefData uint64) bool {
	if hwnd == 0 || pfnSubclass == 0 {
		return false
	}
	state := subclassesForWindow(hwnd, true)
	state.mu.Lock()
	defer state.mu.Unlock()

	for i, entry := range state.entries {
		if entry.PfnSubclass == pfnSubclass && entry.UIDSubclass == uIDSubclass {
			state.entries[i].DwRefData = dwRefData
			return true
		}
	}
	entry := SubclassEntry{
		PfnSubclass: pfnSubclass,
		UIDSubclass: uIDSubclass,
		DwRefData:   dwRefData,
		Token:       subclassToken.Add(1),
	}
	state.entries = append([]SubclassEntry{entry}, state.entries...)
	return true
}

// RemoveWindowSubclass removes a specific subclass.
func RemoveWindowSubclass(hwnd, pfnSubclass, uIDSubclass uint64) bool {
	state := subclassesForWindow(hwnd, false)
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	for i, entry := range state.entries {
		if entry.PfnSubclass == pfnSubclass && entry.UIDSubclass == uIDSubclass {
			copy(state.entries[i:], state.entries[i+1:])
			state.entries = state.entries[:len(state.entries)-1]
			return true
		}
	}
	return false
}

// GetWindowSubclass retrieves refData for a subclass entry.
func GetWindowSubclass(hwnd, pfnSubclass, uIDSubclass uint64) (uint64, bool) {
	state := subclassesForWindow(hwnd, false)
	if state == nil {
		return 0, false
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	for _, entry := range state.entries {
		if entry.PfnSubclass == pfnSubclass && entry.UIDSubclass == uIDSubclass {
			return entry.DwRefData, true
		}
	}
	return 0, false
}

// GetSubclassChain returns a stable newest-first dispatch snapshot.
func GetSubclassChain(hwnd uint64) []SubclassEntry {
	state := subclassesForWindow(hwnd, false)
	if state == nil {
		return nil
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	if len(state.entries) == 0 {
		return nil
	}
	out := make([]SubclassEntry, len(state.entries))
	copy(out, state.entries)
	return out
}

// CurrentSubclass resolves a snapshot entry against the live registration.
func CurrentSubclass(hwnd, token uint64) (SubclassEntry, bool) {
	state := subclassesForWindow(hwnd, false)
	if state == nil {
		return SubclassEntry{}, false
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	for _, entry := range state.entries {
		if entry.Token == token {
			return entry, true
		}
	}
	return SubclassEntry{}, false
}

func HasWindowSubclass(hwnd uint64) bool {
	state := subclassesForWindow(hwnd, false)
	if state == nil {
		return false
	}
	state.mu.RLock()
	hasEntries := len(state.entries) != 0
	state.mu.RUnlock()
	return hasEntries
}

// RemoveAllSubclasses clears callbacks retained by a destroyed window.
func RemoveAllSubclasses(hwnd uint64) {
	if state, ok := subclassWindows.LoadAndDelete(hwnd); ok {
		window := state.(*windowSubclasses)
		window.mu.Lock()
		window.entries = nil
		window.mu.Unlock()
	}
}
