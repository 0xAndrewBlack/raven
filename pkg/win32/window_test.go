//go:build guest_windows

package win32

import "testing"

func TestManagerSetParentPreservesScreenRect(t *testing.T) {
	manager := &Manager{windows: make(map[uint64]*Window)}
	wnd := manager.Create(2, "child", 30, 40, 100, 80, WS_CHILD, 0, 1)

	oldParent, ok := manager.SetParent(2, 3)
	if !ok || oldParent != 1 {
		t.Fatalf("SetParent = (%d, %v), want (1, true)", oldParent, ok)
	}
	if wnd.Parent != 3 || wnd.RcWindow != (Rect{30, 40, 130, 120}) {
		t.Fatalf("window after SetParent = %+v", wnd)
	}
}

func TestManagerParentAndDisabledState(t *testing.T) {
	manager := &Manager{windows: make(map[uint64]*Window)}
	manager.Create(0x100, "parent", 0, 0, 100, 100, WS_VISIBLE|WS_DISABLED, 0, 0)
	manager.Create(0x101, "child", 0, 0, 20, 20, WS_CHILD|WS_VISIBLE, 0, 0x100)

	if parent, ok := manager.Parent(0x101); !ok || parent != 0x100 {
		t.Fatalf("Parent = %#x, present=%t", parent, ok)
	}
	if wasDisabled, ok := manager.SetDisabled(0x100, false); !ok || !wasDisabled {
		t.Fatalf("SetDisabled enable = wasDisabled:%t present:%t", wasDisabled, ok)
	}
	if style := manager.GetLong(0x100, GWL_STYLE); style&WS_DISABLED != 0 {
		t.Fatalf("enabled style = %#x", style)
	}
	if wasDisabled, ok := manager.SetDisabled(0x100, true); !ok || wasDisabled {
		t.Fatalf("SetDisabled disable = wasDisabled:%t present:%t", wasDisabled, ok)
	}
	if style := manager.GetLong(0x100, GWL_STYLE); style&WS_DISABLED == 0 {
		t.Fatalf("disabled style = %#x", style)
	}
}
