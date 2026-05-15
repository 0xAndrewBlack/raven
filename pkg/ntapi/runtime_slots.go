//go:build guest_windows

package ntapi

import "sync"

type processRuntimeSlotKey struct {
	namespace string
	key       uint64
}

type processRuntimeSlots struct {
	mu     sync.Mutex
	values map[processRuntimeSlotKey]uint64
}

var processRuntimeSlotsInit sync.Mutex

func (state *ProcessState) SetGuestCallTrampoline(trampoline *DllMainTrampoline) {
	if state == nil {
		return
	}
	processRuntimeSlotsInit.Lock()
	state.guestCallTrampoline = trampoline
	processRuntimeSlotsInit.Unlock()
}

func (state *ProcessState) GetOrCreateGuestCallTrampoline(create func() *DllMainTrampoline) *DllMainTrampoline {
	if state == nil || create == nil {
		return nil
	}
	processRuntimeSlotsInit.Lock()
	if state.guestCallTrampoline == nil {
		state.guestCallTrampoline = create()
	}
	trampoline := state.guestCallTrampoline
	processRuntimeSlotsInit.Unlock()
	return trampoline
}

func (state *ProcessState) runtimePointerSlots() *processRuntimeSlots {
	if state == nil {
		return nil
	}
	processRuntimeSlotsInit.Lock()
	if state.runtimeSlots == nil {
		state.runtimeSlots = &processRuntimeSlots{
			values: make(map[processRuntimeSlotKey]uint64),
		}
	}
	slots := state.runtimeSlots
	processRuntimeSlotsInit.Unlock()
	return slots
}

// RuntimePointer returns a process-owned guest address without creating it.
func (state *ProcessState) RuntimePointer(namespace string, key uint64) uint64 {
	if namespace == "" {
		return 0
	}
	slots := state.runtimePointerSlots()
	if slots == nil {
		return 0
	}
	slots.mu.Lock()
	value := slots.values[processRuntimeSlotKey{namespace: namespace, key: key}]
	slots.mu.Unlock()
	return value
}

// SwapRuntimePointer replaces a process-owned guest address and returns the
// previous value.
func (state *ProcessState) SwapRuntimePointer(namespace string, key, value uint64) uint64 {
	if namespace == "" {
		return 0
	}
	slots := state.runtimePointerSlots()
	if slots == nil {
		return 0
	}
	slotKey := processRuntimeSlotKey{namespace: namespace, key: key}
	slots.mu.Lock()
	previous := slots.values[slotKey]
	if value == 0 {
		delete(slots.values, slotKey)
	} else {
		slots.values[slotKey] = value
	}
	slots.mu.Unlock()
	return previous
}

// GetOrCreateRuntimePointer stores process-owned guest addresses without
// extending the lifetime of the process or its MMU through a global cache.
func (state *ProcessState) GetOrCreateRuntimePointer(namespace string, key uint64, create func() uint64) uint64 {
	if state == nil || namespace == "" || create == nil {
		return 0
	}

	slots := state.runtimePointerSlots()

	slotKey := processRuntimeSlotKey{namespace: namespace, key: key}
	slots.mu.Lock()
	defer slots.mu.Unlock()
	if value := slots.values[slotKey]; value != 0 {
		return value
	}
	value := create()
	if value != 0 {
		slots.values[slotKey] = value
	}
	return value
}
