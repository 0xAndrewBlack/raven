//go:build guest_windows

package main

import (
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestDialogSurfaceMutexReentersForOwnerAndExcludesOtherCPU(t *testing.T) {
	var mutex dialogSurfaceMutex
	mem := mmu.New()
	owner := x64.New(mem)
	other := x64.New(mem)

	mutex.Lock(owner)
	mutex.Lock(owner)
	mutex.Transfer(owner, other)
	mutex.Lock(other)
	mutex.Unlock(other)
	mutex.Transfer(other, owner)
	acquired := make(chan struct{})
	released := make(chan struct{})
	go func() {
		mutex.Lock(other)
		close(acquired)
		mutex.Unlock(other)
		close(released)
	}()

	select {
	case <-acquired:
		t.Fatal("second CPU acquired a recursively held dialog surface")
	case <-time.After(20 * time.Millisecond):
	}
	mutex.Unlock(owner)
	select {
	case <-acquired:
		t.Fatal("second CPU acquired before the outer lock was released")
	case <-time.After(20 * time.Millisecond):
	}
	mutex.Unlock(owner)
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("second CPU did not acquire the released dialog surface")
	}
}

func TestDialogSurfaceMutexTransferMovesRecursiveDepth(t *testing.T) {
	var mutex dialogSurfaceMutex
	mem := mmu.New()
	owner := x64.New(mem)
	callback := x64.New(mem)

	mutex.Lock(owner)
	mutex.Lock(owner)
	mutex.Lock(owner)
	mutex.Transfer(owner, callback)
	mutex.Unlock(callback)
	mutex.Unlock(callback)
	mutex.Unlock(callback)

	mutex.Lock(owner)
	mutex.Unlock(owner)
}

func TestSyncStackIsScopedToGuestCPU(t *testing.T) {
	hctx := &HandlerCtx{}
	mem := mmu.New()
	first := &ntapi.TrapContext{CPU: x64.New(mem)}
	second := &ntapi.TrapContext{CPU: x64.New(mem)}

	firstStack := hctx.syncStack(first)
	secondStack := hctx.syncStack(second)
	*firstStack = append(*firstStack, syncDispatchFrame{retAddr: 0x1111})
	*secondStack = append(*secondStack, syncDispatchFrame{retAddr: 0x2222})

	if got := (*hctx.syncStack(first))[0].retAddr; got != 0x1111 {
		t.Fatalf("first CPU return address = %#x, want %#x", got, uint64(0x1111))
	}
	if got := (*hctx.syncStack(second))[0].retAddr; got != 0x2222 {
		t.Fatalf("second CPU return address = %#x, want %#x", got, uint64(0x2222))
	}
	if firstStack == secondStack {
		t.Fatal("guest CPUs share a synchronous dispatch stack")
	}
}

func TestWindowCPUTracksCreator(t *testing.T) {
	hctx := &HandlerCtx{}
	cpu := x64.New(mmu.New())

	hctx.setWindowCPU(0x50001, cpu)
	if got := hctx.windowCPU(0x50001); got != cpu {
		t.Fatalf("window CPU = %p, want %p", got, cpu)
	}
	hctx.clearWindowCPU(0x50001)
	if got := hctx.windowCPU(0x50001); got != nil {
		t.Fatalf("destroyed window retained CPU %p", got)
	}
}
