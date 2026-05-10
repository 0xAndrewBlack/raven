//go:build guest_windows

package main

import (
	"sync"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestModalDialogLoopTargetPrefersActiveDialog(t *testing.T) {
	const (
		dialogRSP = uint64(0x1100)
		pumpPC    = uint64(0x2200)
		messageSP = uint64(0x3300)
		messagePC = uint64(0x4400)
	)

	gotSP, gotPC := modalDialogLoopTarget(dialogRSP, pumpPC, messageSP, messagePC)
	if gotSP != dialogRSP || gotPC != pumpPC {
		t.Fatalf("target = (0x%x, 0x%x), want (0x%x, 0x%x)", gotSP, gotPC, dialogRSP, pumpPC)
	}
}

func TestModalDialogLoopTargetFallsBackToMessageLoop(t *testing.T) {
	const (
		messageSP = uint64(0x3300)
		messagePC = uint64(0x4400)
	)

	gotSP, gotPC := modalDialogLoopTarget(0, 0x2200, messageSP, messagePC)
	if gotSP != messageSP || gotPC != messagePC {
		t.Fatalf("target = (0x%x, 0x%x), want (0x%x, 0x%x)", gotSP, gotPC, messageSP, messagePC)
	}
}

func TestModalPumpEntrySPPreservesCallbackStack(t *testing.T) {
	const callSP = uint64(0x1000)

	if got := modalPumpEntrySP(callSP, true); got != callSP {
		t.Fatalf("PE32 pump stack = 0x%x, want 0x%x", got, callSP)
	}
	if got := modalPumpEntrySP(callSP, false); got != callSP-0x28 {
		t.Fatalf("PE64 pump stack = 0x%x, want 0x%x", got, callSP-0x28)
	}
}

func TestModalMessageWndProcUsesMessageWindow(t *testing.T) {
	const (
		dialog     = uint64(0x5001)
		dialogProc = uint64(0x140001000)
		owner      = uint64(0x5002)
		ownerProc  = uint64(0x140002000)
	)
	wndProcs := map[uint64]uint64{dialog: dialogProc, owner: ownerProc}

	if got := modalMessageWndProc(dialog, dialogProc, dialog, wndProcs); got != dialogProc {
		t.Fatalf("dialog proc = 0x%x, want 0x%x", got, dialogProc)
	}
	if got := modalMessageWndProc(dialog, dialogProc, owner, wndProcs); got != ownerProc {
		t.Fatalf("owner proc = 0x%x, want 0x%x", got, ownerProc)
	}
	if got := modalMessageWndProc(dialog, dialogProc, 0x5003, wndProcs); got != 0 {
		t.Fatalf("unknown proc = 0x%x, want 0", got)
	}
}

func TestModalInputClassificationExcludesProgrammaticCommands(t *testing.T) {
	for _, message := range []uint32{0x0100, 0x0104, 0x0201, 0x00A1} {
		if !isModalInputMessage(message) {
			t.Fatalf("message %#x was not classified as input", message)
		}
	}
	for _, message := range []uint32{0x000A, 0x001F, 0x0111, 0x0112, 0x0312, 0x0319} {
		if isModalInputMessage(message) {
			t.Fatalf("programmatic message %#x was classified as input", message)
		}
	}
}

func TestDisabledWindowInModalHierarchyStopsAtDialogRoot(t *testing.T) {
	parents := map[uint64]uint64{
		0x502: 0x501,
		0x501: 0x500,
	}
	parent := func(hwnd uint64) (uint64, bool) {
		value, ok := parents[hwnd]
		return value, ok
	}

	if !disabledWindowInHierarchy(0x502, 0x501,
		func(hwnd uint64) bool { return hwnd == 0x502 }, parent) {
		t.Fatal("disabled dialog control accepted input")
	}
	if disabledWindowInHierarchy(0x501, 0x501,
		func(hwnd uint64) bool { return hwnd == 0x500 }, parent) {
		t.Fatal("disabled modal owner leaked through the dialog root")
	}
	if !disabledWindowInHierarchy(0x500, 0x501,
		func(hwnd uint64) bool { return hwnd == 0x500 }, parent) {
		t.Fatal("disabled owner accepted input")
	}
}

func TestModalOwnerRegistryKeepsOwnerDisabledUntilLastDialogCloses(t *testing.T) {
	var owners modalOwnerRegistry
	disabled := false
	disableCalls := 0
	enableCalls := 0
	acquire := func() {
		owners.acquire(0x5000, func() bool { return disabled }, func() {
			disabled = true
			disableCalls++
		})
	}
	release := func() {
		owners.release(0x5000, func() {
			disabled = false
			enableCalls++
		})
	}

	acquire()
	acquire()
	release()
	if !disabled || disableCalls != 1 || enableCalls != 0 {
		t.Fatalf("owner restored too early: disabled=%t disable=%d enable=%d", disabled, disableCalls, enableCalls)
	}
	release()
	if disabled || disableCalls != 1 || enableCalls != 1 {
		t.Fatalf("owner was not restored: disabled=%t disable=%d enable=%d", disabled, disableCalls, enableCalls)
	}
}

func TestModalOwnerRegistryPreservesInitiallyDisabledOwner(t *testing.T) {
	var owners modalOwnerRegistry
	disableCalls := 0
	enableCalls := 0
	owners.acquire(0x5000, func() bool { return true }, func() { disableCalls++ })
	owners.release(0x5000, func() { enableCalls++ })
	if disableCalls != 0 || enableCalls != 0 {
		t.Fatalf("initially disabled owner changed: disable=%d enable=%d", disableCalls, enableCalls)
	}
}

func TestGuestNonvolatileRegistersRoundTrip(t *testing.T) {
	cpu := x64.New(mmu.New())
	registers := []int{3, 5, 6, 7, 12, 13, 14, 15}
	for index, register := range registers {
		cpu.WriteReg(register, uint64(0x100+index))
	}
	state := captureGuestNonvolatileRegisters(cpu, false)
	for _, register := range registers {
		cpu.WriteReg(register, 0)
	}

	restoreGuestNonvolatileRegisters(cpu, state)

	for index, register := range registers {
		want := uint64(0x100 + index)
		if got := cpu.ReadReg(register); got != want {
			t.Fatalf("register %d = 0x%x, want 0x%x", register, got, want)
		}
	}
}

func TestEndDialogDefersCompletionUntilDialogProcReturns(t *testing.T) {
	entries := []modalDlgEntry{{hwnd: 0x5001, result: 0xFFFFFFFF}}

	if !markModalDialogEnded(entries, 0x5001, 6) {
		t.Fatal("modal dialog was not found")
	}
	if !entries[0].ended || entries[0].result != 6 {
		t.Fatalf("entry = {ended:%t result:%d}, want {ended:true result:6}", entries[0].ended, entries[0].result)
	}
	if markModalDialogEnded(entries, 0x5002, 7) {
		t.Fatal("unknown modal dialog was marked complete")
	}
}

func TestModalDialogRegistryIsolatesGuestCPUs(t *testing.T) {
	firstCPU := x64.New(mmu.New())
	secondCPU := x64.New(mmu.New())
	var dialogs modalDialogRegistry
	dialogs.push(firstCPU, modalDlgEntry{hwnd: 0x5001})
	dialogs.push(secondCPU, modalDlgEntry{hwnd: 0x5002})

	if dialogs.markEnded(secondCPU, 0x5001, 6) {
		t.Fatal("dialog from another guest CPU was marked complete")
	}
	if !dialogs.markEnded(firstCPU, 0x5001, 6) {
		t.Fatal("dialog on the owning guest CPU was not marked complete")
	}
	if entry, ok := dialogs.top(secondCPU); !ok || entry.hwnd != 0x5002 || entry.ended {
		t.Fatalf("second CPU dialog = %+v, present=%t", entry, ok)
	}
	entry, ok := dialogs.takeEnded(firstCPU, 0x5001)
	if !ok || entry.result != 6 {
		t.Fatalf("completed dialog = %+v, present=%t", entry, ok)
	}
	if _, ok := dialogs.top(firstCPU); ok {
		t.Fatal("completed dialog remained on its CPU stack")
	}
}

func TestModalDialogRegistryConcurrentAccess(t *testing.T) {
	cpu := x64.New(mmu.New())
	var dialogs modalDialogRegistry
	dialogs.push(cpu, modalDlgEntry{hwnd: 0x5001})

	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			dialogs.top(cpu)
			dialogs.markEnded(cpu, 0x5001, 6)
		}()
	}
	wait.Wait()

	entry, ok := dialogs.takeEnded(cpu, 0x5001)
	if !ok || !entry.ended || entry.result != 6 {
		t.Fatalf("completed dialog = %+v, present=%t", entry, ok)
	}
}
