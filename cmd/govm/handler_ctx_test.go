//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

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
