package thread

import (
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestThreadDoneSurvivesIndependentLookups(t *testing.T) {
	mem := mmu.New()
	start := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	stack := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
	if err := mem.Write8(start, 0xc3); err != nil {
		t.Fatal(err)
	}

	manager := NewManager(mem, nil)
	cpu := x64.New(mem)
	manager.MainThread(cpu)
	tid, done, err := manager.CloneWin32Thread(cpu, start, 0, stack, 4096, 0)
	if err != nil {
		t.Fatal(err)
	}
	lookup, ok := manager.ThreadDone(tid)
	if !ok {
		t.Fatal("thread completion signal was not registered")
	}
	if lookup != done {
		t.Fatal("thread lookup returned a different completion signal")
	}
	select {
	case <-lookup:
	case <-time.After(time.Second):
		t.Fatal("thread completion signal was never closed")
	}
}
