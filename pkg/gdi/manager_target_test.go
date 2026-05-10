//go:build guest_windows

package gdi

import "testing"

func TestAllocTargetDCUsesIndependentSurface(t *testing.T) {
	manager := NewManager()
	manager.Screen = NewSurface(4, 4)
	target := NewSurface(8, 6)

	handle, dc := manager.AllocTargetDC(target)
	t.Cleanup(func() { manager.DeleteDC(handle) })
	dc.FillRect(0, 0, 1, 1, 0x123456)

	if got := target.GetPixel(0, 0); got != 0x123456 {
		t.Fatalf("target pixel = %#x, want %#x", got, uint32(0x123456))
	}
	if got := manager.Screen.GetPixel(0, 0); got != 0 {
		t.Fatalf("primary screen pixel = %#x, want untouched", got)
	}
}
