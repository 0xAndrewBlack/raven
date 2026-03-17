//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestWin32kBridgeCreateWindow(t *testing.T) {
	b := newWin32kBridge(mmu.New(), 800, 600)
	if c := b.table.Count(); c == 0 {
		t.Fatalf("syscall table empty (count=%d)", c)
	}
	ret, name, ok := b.dispatch(sysNtUserCreateWindow, []uint64{0x10000000, 30, 40, 0x00C80064})
	if !ok {
		t.Fatalf("dispatch failed for 0x%x (name=%q)", sysNtUserCreateWindow, name)
	}
	if ret < 0x10010 {
		t.Fatalf("CreateWindow returned non-HWND 0x%x", ret)
	}
	// WindowFromPoint inside the window returns the same HWND.
	hwnd, _, _ := b.dispatch(sysNtUserWindowFromPt, []uint64{50, 60})
	if hwnd != ret {
		t.Fatalf("WindowFromPoint=0x%x want 0x%x", hwnd, ret)
	}
}
