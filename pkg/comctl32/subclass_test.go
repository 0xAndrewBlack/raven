//go:build guest_windows

package comctl32

import (
	"sync"
	"testing"
)

func TestSubclassChainNewestFirstAndUpdatesRefData(t *testing.T) {
	const hwnd = 0x51001
	t.Cleanup(func() { RemoveAllSubclasses(hwnd) })

	if SetWindowSubclass(0, 1, 1, 1) || SetWindowSubclass(hwnd, 0, 1, 1) {
		t.Fatal("invalid subclass registration succeeded")
	}
	if !SetWindowSubclass(hwnd, 0x1000, 0x100000001, 0x200000002) {
		t.Fatal("first registration failed")
	}
	if !SetWindowSubclass(hwnd, 0x2000, 2, 3) {
		t.Fatal("second registration failed")
	}

	chain := GetSubclassChain(hwnd)
	if len(chain) != 2 || chain[0].PfnSubclass != 0x2000 || chain[1].PfnSubclass != 0x1000 {
		t.Fatalf("subclass order = %#v", chain)
	}
	firstToken := chain[1].Token
	if !SetWindowSubclass(hwnd, 0x1000, 0x100000001, 0x300000003) {
		t.Fatal("registration update failed")
	}
	updated, ok := CurrentSubclass(hwnd, firstToken)
	if !ok || updated.DwRefData != 0x300000003 || updated.Token != firstToken {
		t.Fatalf("updated entry = %#v, ok=%v", updated, ok)
	}
	if ref, ok := GetWindowSubclass(hwnd, 0x1000, 0x100000001); !ok || ref != 0x300000003 {
		t.Fatalf("GetWindowSubclass = %#x, %v", ref, ok)
	}
}

func TestRemovedSnapshotEntryDoesNotMatchReaddedSubclass(t *testing.T) {
	const hwnd = 0x51002
	t.Cleanup(func() { RemoveAllSubclasses(hwnd) })

	SetWindowSubclass(hwnd, 0x1000, 7, 8)
	snapshot := GetSubclassChain(hwnd)
	if !RemoveWindowSubclass(hwnd, 0x1000, 7) {
		t.Fatal("RemoveWindowSubclass failed")
	}
	if _, ok := CurrentSubclass(hwnd, snapshot[0].Token); ok {
		t.Fatal("removed registration remained live")
	}
	SetWindowSubclass(hwnd, 0x1000, 7, 9)
	if current := GetSubclassChain(hwnd); current[0].Token == snapshot[0].Token {
		t.Fatal("re-added registration reused its dispatch identity")
	}
}

func TestSubclassWindowsMutateIndependently(t *testing.T) {
	const windows = 32
	var wg sync.WaitGroup
	for i := 0; i < windows; i++ {
		hwnd := uint64(0x52000 + i)
		t.Cleanup(func() { RemoveAllSubclasses(hwnd) })
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := uint64(1); id <= 100; id++ {
				if !SetWindowSubclass(hwnd, 0x1000+id, id, id<<32|id) {
					t.Errorf("SetWindowSubclass(%#x, %d) failed", hwnd, id)
					return
				}
			}
			for id := uint64(1); id <= 100; id++ {
				if !RemoveWindowSubclass(hwnd, 0x1000+id, id) {
					t.Errorf("RemoveWindowSubclass(%#x, %d) failed", hwnd, id)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestRemoveAllSubclassesClearsLiveEntries(t *testing.T) {
	const hwnd = 0x51003
	SetWindowSubclass(hwnd, 0x1000, 1, 2)
	RemoveAllSubclasses(hwnd)
	if HasWindowSubclass(hwnd) || GetSubclassChain(hwnd) != nil {
		t.Fatal("destroy cleanup retained subclass callbacks")
	}
}
