package winmgr

import "testing"

func newMgrWithClass(t *testing.T) *Manager {
	t.Helper()
	m := New()
	m.RegisterClass(&Class{Name: "Btn", WndProc: 0x1000})
	return m
}

func TestRegisterAndCreate(t *testing.T) {
	m := newMgrWithClass(t)
	if m.FindClass("Btn") == nil {
		t.Fatal("class not found after register")
	}
	w := m.CreateWindow(CreateWindowParams{ClassName: "Btn", Title: "Hi", Style: WS_VISIBLE, W: 100, H: 40})
	if w == nil || w.Handle == 0 {
		t.Fatal("CreateWindow failed")
	}
	if m.Get(w.Handle) != w {
		t.Fatal("Get did not return the created window")
	}
	if w.WndProc != 0x1000 {
		t.Fatal("window did not inherit class WndProc")
	}
	if m.CreateWindow(CreateWindowParams{ClassName: "Missing"}) != nil {
		t.Fatal("CreateWindow with unknown class should return nil")
	}
}

func TestParentChildAndDestroy(t *testing.T) {
	m := newMgrWithClass(t)
	top := m.CreateWindow(CreateWindowParams{ClassName: "Btn", Style: WS_VISIBLE, W: 200, H: 200})
	c1 := m.CreateWindow(CreateWindowParams{ClassName: "Btn", Style: WS_CHILD | WS_VISIBLE, Parent: top.Handle, W: 50, H: 20})
	c2 := m.CreateWindow(CreateWindowParams{ClassName: "Btn", Style: WS_CHILD | WS_VISIBLE, Parent: top.Handle, W: 50, H: 20})
	if m.GetParent(c1.Handle) != top.Handle {
		t.Fatal("child parent wrong")
	}
	// c2 created last -> front of child z-order -> GW_CHILD returns c2.
	if m.GetWindow(top.Handle, GW_CHILD) != c2.Handle {
		t.Fatal("GW_CHILD should be the top-most (last-created) child")
	}
	// Destroying the parent destroys children.
	m.DestroyWindow(top.Handle)
	if m.Get(c1.Handle) != nil || m.Get(c2.Handle) != nil || m.Get(top.Handle) != nil {
		t.Fatal("destroy did not recurse to children")
	}
}

func TestZOrderAndSetWindowPos(t *testing.T) {
	m := newMgrWithClass(t)
	a := m.CreateWindow(CreateWindowParams{ClassName: "Btn", Style: WS_VISIBLE, W: 10, H: 10})
	b := m.CreateWindow(CreateWindowParams{ClassName: "Btn", Style: WS_VISIBLE, W: 10, H: 10})
	cc := m.CreateWindow(CreateWindowParams{ClassName: "Btn", Style: WS_VISIBLE, W: 10, H: 10})
	// Creation order a,b,c -> z-order front..back = c,b,a.
	if z := m.TopLevelZOrder(false); z[0] != cc.Handle || z[2] != a.Handle {
		t.Fatalf("initial z-order wrong: %v", z)
	}
	// Bring a to top.
	m.SetWindowPos(a.Handle, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOSIZE)
	if m.TopLevelZOrder(false)[0] != a.Handle {
		t.Fatal("SetWindowPos HWND_TOP did not raise window")
	}
	// Send a to bottom.
	m.SetWindowPos(a.Handle, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOSIZE)
	z := m.TopLevelZOrder(false)
	if z[len(z)-1] != a.Handle {
		t.Fatal("SetWindowPos HWND_BOTTOM did not lower window")
	}
	// Move/size.
	m.SetWindowPos(b.Handle, HWND_TOP, 5, 6, 30, 40, 0)
	r, _ := m.WindowRect(b.Handle)
	if r != (Rect{5, 6, 35, 46}) {
		t.Fatalf("rect after SetWindowPos = %+v", r)
	}
}

func TestClientRect(t *testing.T) {
	m := newMgrWithClass(t)
	w := m.CreateWindow(CreateWindowParams{ClassName: "Btn", Style: WS_VISIBLE | WS_CAPTION, X: 0, Y: 0, W: 200, H: 100})
	cr, _ := m.ClientRect(w.Handle)
	// 200x100 minus 2*border and caption.
	if cr.Width() != 200-2*borderW || cr.Height() != 100-2*borderW-captionH {
		t.Fatalf("client rect = %+v", cr)
	}
}

func TestWindowFromPointZOrder(t *testing.T) {
	m := newMgrWithClass(t)
	// Two overlapping top-level windows; the top-most in z-order wins.
	lo := m.CreateWindow(CreateWindowParams{ClassName: "Btn", Style: WS_VISIBLE, X: 0, Y: 0, W: 100, H: 100})
	hi := m.CreateWindow(CreateWindowParams{ClassName: "Btn", Style: WS_VISIBLE, X: 50, Y: 50, W: 100, H: 100})
	if got := m.WindowFromPoint(60, 60); got != hi.Handle {
		t.Fatalf("overlap hit = %v, want hi", got)
	}
	if got := m.WindowFromPoint(10, 10); got != lo.Handle {
		t.Fatalf("non-overlap hit = %v, want lo", got)
	}
	// A child is returned over its parent.
	ch := m.CreateWindow(CreateWindowParams{ClassName: "Btn", Style: WS_CHILD | WS_VISIBLE, Parent: hi.Handle, X: 55, Y: 55, W: 20, H: 20})
	if got := m.WindowFromPoint(60, 60); got != ch.Handle {
		t.Fatalf("child hit = %v, want child", got)
	}
	// Invisible windows are skipped.
	m.ShowWindow(ch.Handle, false)
	if got := m.WindowFromPoint(60, 60); got != hi.Handle {
		t.Fatalf("hidden child should be skipped, got %v", got)
	}
}

func TestGetSetWindowLong(t *testing.T) {
	m := newMgrWithClass(t)
	w := m.CreateWindow(CreateWindowParams{ClassName: "Btn", Style: WS_VISIBLE, W: 10, H: 10})
	if m.GetWindowLong(w.Handle, GWL_STYLE) != uint64(WS_VISIBLE) {
		t.Fatal("GWL_STYLE wrong")
	}
	prev := m.SetWindowLong(w.Handle, GWLP_USERDATA, 0xCAFE)
	if prev != 0 || m.GetWindowLong(w.Handle, GWLP_USERDATA) != 0xCAFE {
		t.Fatal("userdata round-trip failed")
	}
	m.SetWindowLong(w.Handle, GWL_WNDPROC, 0x2000)
	if m.GetWindowLong(w.Handle, GWL_WNDPROC) != 0x2000 {
		t.Fatal("wndproc subclass failed")
	}
}

func TestFindWindow(t *testing.T) {
	m := newMgrWithClass(t)
	m.CreateWindow(CreateWindowParams{ClassName: "Btn", Title: "Alpha", Style: WS_VISIBLE, W: 1, H: 1})
	if m.FindWindow("Btn", "Alpha") == 0 {
		t.Fatal("FindWindow by class+title failed")
	}
	if m.FindWindow("", "Alpha") == 0 {
		t.Fatal("FindWindow by title failed")
	}
	if m.FindWindow("Btn", "Nope") != 0 {
		t.Fatal("FindWindow should not match wrong title")
	}
}

func TestAtomTable(t *testing.T) {
	at := NewAtomTable(0xC000)
	id1 := at.Add("WM_MY_MESSAGE")
	id2 := at.Add("WM_MY_MESSAGE")
	if id1 != id2 {
		t.Fatal("same name should give same atom id")
	}
	if at.Find("WM_MY_MESSAGE") != id1 || at.Name(id1) != "WM_MY_MESSAGE" {
		t.Fatal("atom lookup round-trip failed")
	}
	at.Delete(id1) // ref 2 -> 1
	if at.Find("WM_MY_MESSAGE") == 0 {
		t.Fatal("atom removed too early")
	}
	at.Delete(id1) // -> 0, removed
	if at.Find("WM_MY_MESSAGE") != 0 {
		t.Fatal("atom not removed at refcount 0")
	}
}

func TestSyscallTableDispatch(t *testing.T) {
	tbl := NewSyscallTable()
	tbl.Register(0x1000, "NtUserGetMessage", func(a []uint64) uint64 { return a[0] + 1 })
	if i, ok := tbl.IndexOf("NtUserGetMessage"); !ok || i != 0x1000 {
		t.Fatal("IndexOf failed")
	}
	if n, _ := tbl.NameOf(0x1000); n != "NtUserGetMessage" {
		t.Fatal("NameOf failed")
	}
	if r, ok := tbl.Dispatch(0x1000, []uint64{41}); !ok || r != 42 {
		t.Fatalf("dispatch = %d ok=%v", r, ok)
	}
	if r, ok := tbl.Dispatch(0x9999, nil); ok || r != 0xC0000002 {
		t.Fatalf("unbound dispatch = %#x ok=%v, want STATUS_NOT_IMPLEMENTED", r, ok)
	}
}
