//go:build guest_windows

package ntapi

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestProcessRuntimePointersAreStableAndConcurrent(t *testing.T) {
	state := &ProcessState{}
	var allocations atomic.Uint32
	create := func() uint64 {
		allocations.Add(1)
		return 0x12345000
	}

	const workers = 16
	results := make(chan uint64, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- state.GetOrCreateRuntimePointer("test", 7, create)
		}()
	}
	group.Wait()
	close(results)

	for result := range results {
		if result != 0x12345000 {
			t.Fatalf("runtime pointer = %#x", result)
		}
	}
	if got := allocations.Load(); got != 1 {
		t.Fatalf("runtime pointer allocated %d times", got)
	}
	if other := state.GetOrCreateRuntimePointer("test", 8, func() uint64 { return 0x12346000 }); other != 0x12346000 {
		t.Fatalf("second runtime pointer = %#x", other)
	}
	if got := state.RuntimePointer("test", 7); got != 0x12345000 {
		t.Fatalf("stored runtime pointer = %#x", got)
	}
	if got := state.RuntimePointer("missing", 7); got != 0 {
		t.Fatalf("missing runtime pointer = %#x", got)
	}
	if old := state.SwapRuntimePointer("test", 7, 0x12347000); old != 0x12345000 {
		t.Fatalf("replaced runtime pointer was %#x", old)
	}
	if got := state.RuntimePointer("test", 7); got != 0x12347000 {
		t.Fatalf("replaced runtime pointer = %#x", got)
	}
	if old := state.SwapRuntimePointer("test", 7, 0); old != 0x12347000 || state.RuntimePointer("test", 7) != 0 {
		t.Fatalf("removed runtime pointer old=%#x current=%#x", old, state.RuntimePointer("test", 7))
	}

	trampoline := &DllMainTrampoline{Addr: 0x76540000}
	if got := state.GetOrCreateGuestCallTrampoline(func() *DllMainTrampoline { return trampoline }); got != trampoline {
		t.Fatalf("guest trampoline = %#v", got)
	}
	if got := state.GetOrCreateGuestCallTrampoline(func() *DllMainTrampoline {
		t.Fatal("guest trampoline created twice")
		return nil
	}); got != trampoline {
		t.Fatalf("reused guest trampoline = %#v", got)
	}
}
