//go:build guest_windows

package main

import (
	"sync"
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/win32"
)

func TestIsRegisteredWindowUsesGlobalAuthority(t *testing.T) {
	const (
		mainHWND = uint64(0x7f100001)
		hwnd     = uint64(0x7f100002)
	)
	if isRegisteredWindow(0, mainHWND) {
		t.Fatal("null handle reported as registered")
	}
	if !isRegisteredWindow(desktopWindowHandle, mainHWND) {
		t.Fatal("desktop handle reported as invalid")
	}
	if !isRegisteredWindow(mainHWND, mainHWND) {
		t.Fatal("main window handle reported as invalid")
	}

	win32.Global.Create(hwnd, "test", 0, 0, 10, 10, 0, 0, 0)
	if !isRegisteredWindow(hwnd, mainHWND) {
		t.Fatal("global window reported as invalid")
	}
	win32.Global.Destroy(hwnd)
	if isRegisteredWindow(hwnd, mainHWND) {
		t.Fatal("destroyed global window reported as registered")
	}
}

func TestIsRegisteredWindowConcurrentLifecycle(t *testing.T) {
	const hwnd = uint64(0x7f100003)
	defer win32.Global.Destroy(hwnd)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 1000 {
				_ = isRegisteredWindow(hwnd, 0)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for range 1000 {
			win32.Global.Create(hwnd, "test", 0, 0, 10, 10, 0, 0, 0)
			win32.Global.Destroy(hwnd)
		}
	}()
	close(start)
	wg.Wait()
}

func TestOverlappingGuestSiblings(t *testing.T) {
	const parent = uint64(10)
	children := map[uint64]*controlState{
		20: {
			className:  "SysTabControl32",
			parentHWND: parent,
			x:          0,
			y:          20,
			w:          200,
			h:          180,
			style:      win32.WS_CLIPSIBLINGS,
			visible:    true,
		},
		21: {className: "Scintilla", parentHWND: parent, x: 2, y: 45, w: 196, h: 150, visible: true},
		22: {className: "Scintilla", parentHWND: parent, x: 210, y: 45, w: 50, h: 50, visible: true},
		23: {className: "Scintilla", parentHWND: parent, x: 2, y: 45, w: 196, h: 150},
		24: {className: "Scintilla", parentHWND: 99, x: 2, y: 45, w: 196, h: 150, visible: true},
		25: {className: "Button", parentHWND: parent, x: 2, y: 45, w: 196, h: 150, visible: true},
	}
	wndProcs := map[uint64]uint64{21: 1, 22: 1, 23: 1, 24: 1, 25: 1}
	order := []uint64{21, 25, 20, 22, 23, 24}

	got := overlappingGuestSiblings(20, children, wndProcs, order)
	if len(got) != 1 || got[0] != 21 {
		t.Fatalf("overlapping siblings = %#v, want [21]", got)
	}
	children[20].style &^= win32.WS_CLIPSIBLINGS
	if got := overlappingGuestSiblings(20, children, wndProcs, order); len(got) != 0 {
		t.Fatalf("siblings without WS_CLIPSIBLINGS = %#v", got)
	}
	children[20].style |= win32.WS_CLIPSIBLINGS
	children[20].className = "Scintilla"
	if got := overlappingGuestSiblings(20, children, wndProcs, order); len(got) != 0 {
		t.Fatalf("siblings after custom control paint = %#v", got)
	}
}

func TestWindowIsDescendantOrSelf(t *testing.T) {
	children := map[uint64]*controlState{
		11: {parentHWND: 10},
		12: {parentHWND: 11},
		20: {parentHWND: 21},
		30: {parentHWND: 30},
	}
	for _, test := range []struct {
		hwnd uint64
		root uint64
		want bool
	}{
		{hwnd: 10, root: 10, want: true},
		{hwnd: 12, root: 10, want: true},
		{hwnd: 12, root: 11, want: true},
		{hwnd: 11, root: 12, want: false},
		{hwnd: 20, root: 10, want: false},
		{hwnd: 30, root: 10, want: false},
	} {
		if got := windowIsDescendantOrSelf(test.hwnd, test.root, children); got != test.want {
			t.Errorf("windowIsDescendantOrSelf(%d, %d) = %t, want %t",
				test.hwnd, test.root, got, test.want)
		}
	}
}

func TestWindowCleanupIncludesGlobalOnlyRoot(t *testing.T) {
	const (
		root    = uint64(0x7f100004)
		child   = uint64(0x7f100005)
		sibling = uint64(0x7f100006)
	)
	win32.Global.Create(root, "root", 0, 0, 10, 10, 0, 0, 0)
	defer win32.Global.Destroy(root)

	children := map[uint64]*controlState{
		child:   {parentHWND: root},
		sibling: {parentHWND: 0x7f100007},
	}
	var disabled windowDisabledRegistry
	disabled.set(root, true)

	handles := windowCleanupHandles(root, children)
	found := make(map[uint64]bool, len(handles))
	for _, hwnd := range handles {
		found[hwnd] = true
		cleanupWindowRegistration(hwnd, &disabled)
	}
	if !found[root] || !found[child] {
		t.Fatalf("cleanup handles = %#v, want root and child", handles)
	}
	if found[sibling] {
		t.Fatalf("cleanup handles = %#v, contains unrelated sibling", handles)
	}
	if win32.Global.Get(root) != nil {
		t.Fatal("global-only root survived cleanup")
	}
	if _, ok := disabled.get(root); ok {
		t.Fatal("disabled override survived cleanup")
	}
}

func TestRegisterGlobalWindowMakesOwnedDialogKnown(t *testing.T) {
	const hwnd = uint64(0x7f100008)
	defer win32.Global.Destroy(hwnd)

	state := &controlState{
		className:  "dialog",
		parentHWND: desktopWindowHandle,
		w:          380,
		h:          130,
		visible:    true,
	}
	if !registerGlobalWindow(hwnd, state) {
		t.Fatal("owned dialog was not registered")
	}
	if !isRegisteredWindow(hwnd, 0) {
		t.Fatal("registered owned dialog reported as invalid")
	}
	if registerGlobalWindow(hwnd, state) {
		t.Fatal("existing owned dialog was registered twice")
	}
}

func TestRegisterGlobalWindowConcurrentLifecycle(t *testing.T) {
	const hwnd = uint64(0x7f100009)
	defer win32.Global.Destroy(hwnd)

	state := &controlState{className: "dialog", w: 380, h: 130, visible: true}
	var lifecycle sync.Mutex
	var registered int
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			lifecycle.Lock()
			if registerGlobalWindow(hwnd, state) {
				registered++
			}
			lifecycle.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if registered != 1 {
		t.Fatalf("global registrations = %d, want 1", registered)
	}
}

func TestChangeWindowEnabledRejectsInvalidHandleWithoutMessages(t *testing.T) {
	var messages []queuedMsg
	wasDisabled, present := changeWindowEnabled(
		0x7f10000a,
		false,
		true,
		func(uint64, bool) (bool, bool) {
			return false, false
		},
		func(hwnd uint64, message uint32, wParam uint64) {
			messages = append(messages, queuedMsg{hwnd: hwnd, message: message, wParam: wParam})
		},
	)
	if wasDisabled || present {
		t.Fatalf("invalid result = (wasDisabled:%t present:%t)", wasDisabled, present)
	}
	if len(messages) != 0 {
		t.Fatalf("invalid handle queued messages: %#v", messages)
	}
}

func TestChangeWindowEnabledNotifiesValidStateChange(t *testing.T) {
	var messages []queuedMsg
	wasDisabled, present := changeWindowEnabled(
		0x7f10000b,
		false,
		true,
		func(uint64, bool) (bool, bool) {
			return false, true
		},
		func(hwnd uint64, message uint32, wParam uint64) {
			messages = append(messages, queuedMsg{hwnd: hwnd, message: message, wParam: wParam})
		},
	)
	if wasDisabled || !present {
		t.Fatalf("valid result = (wasDisabled:%t present:%t)", wasDisabled, present)
	}
	if len(messages) != 2 || messages[0].message != 0x001F ||
		messages[1].message != 0x000A || messages[1].wParam != 0 {
		t.Fatalf("disable messages = %#v", messages)
	}
}

func TestWin32MessageMatches(t *testing.T) {
	isDescendant := func(hwnd, ancestor uint64) bool {
		return hwnd == 3 && ancestor == 1
	}
	tests := []struct {
		name                   string
		message                uint32
		hwnd, hwndFilter       uint64
		minMessage, maxMessage uint32
		want                   bool
	}{
		{name: "unfiltered", message: 0x000F, hwnd: 2, want: true},
		{name: "message in range", message: 0x0102, hwnd: 2, minMessage: 0x0100, maxMessage: 0x0108, want: true},
		{name: "message outside range", message: 0x000F, hwnd: 2, minMessage: 0x0100, maxMessage: 0x0108},
		{name: "exact window", message: 0x000F, hwnd: 2, hwndFilter: 2, want: true},
		{name: "different window", message: 0x000F, hwnd: 2, hwndFilter: 1},
		{name: "descendant window", message: 0x000F, hwnd: 3, hwndFilter: 1, want: true},
		{name: "thread message", message: 0x0400, hwnd: 0, hwndFilter: ^uint64(0), want: true},
		{name: "window message excluded by thread filter", message: 0x0400, hwnd: 2, hwndFilter: ^uint64(0)},
		{name: "quit bypasses filters", message: 0x0012, hwnd: 2, hwndFilter: 1, minMessage: 0x0100, maxMessage: 0x0108, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := win32MessageMatches(tt.message, tt.hwnd, tt.hwndFilter, tt.minMessage, tt.maxMessage, isDescendant)
			if got != tt.want {
				t.Fatalf("match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuiltinMessageNeedsCommit(t *testing.T) {
	for _, message := range []uint32{0x000F, 0x0014, 0x0085} {
		if !builtinMessageNeedsCommit(message) {
			t.Fatalf("message %#x did not request a commit", message)
		}
	}
	if builtinMessageNeedsCommit(0x0113) {
		t.Fatal("WM_TIMER requested an unchanged frame commit")
	}
}

func TestWindowPosNeedsRepaint(t *testing.T) {
	if !windowPosNeedsRepaint(0x0014, true) {
		t.Fatal("visible deferred window did not request repaint")
	}
	if windowPosNeedsRepaint(0x0014|0x0008, true) {
		t.Fatal("SWP_NOREDRAW requested repaint")
	}
	if windowPosNeedsRepaint(0x0014, false) {
		t.Fatal("hidden window requested repaint")
	}
	if !windowPosParentNeedsRepaint(0x0014, true, false) {
		t.Fatal("hiding a visible window did not repaint its parent")
	}
	if windowPosParentNeedsRepaint(0x0014|0x0008, true, false) {
		t.Fatal("SWP_NOREDRAW repainted the parent")
	}
	if windowPosParentNeedsRepaint(0x0014, false, false) {
		t.Fatal("unchanged hidden window repainted its parent")
	}
}

func TestLeftClickTracker(t *testing.T) {
	start := time.Unix(100, 0)
	var tracker leftClickTracker

	if got := tracker.press(start, 10, 20, 30, 0x0008, 500*time.Millisecond); got != 0x0201 {
		t.Fatalf("first press = %#x, want WM_LBUTTONDOWN", got)
	}
	if got := tracker.press(start.Add(200*time.Millisecond), 10, 21, 29, 0x0008, 500*time.Millisecond); got != 0x0203 {
		t.Fatalf("second press = %#x, want WM_LBUTTONDBLCLK", got)
	}
	if got := tracker.press(start.Add(300*time.Millisecond), 10, 20, 30, 0x0008, 500*time.Millisecond); got != 0x0201 {
		t.Fatalf("press after double click = %#x, want WM_LBUTTONDOWN", got)
	}
}

func TestLeftClickTrackerRejectsNonMatchingPress(t *testing.T) {
	tests := []struct {
		name       string
		hwnd       uint64
		x          int32
		y          int32
		classStyle uint32
		delay      time.Duration
	}{
		{name: "class without double clicks", hwnd: 10, x: 20, y: 30, delay: 100 * time.Millisecond},
		{name: "different window", hwnd: 11, x: 20, y: 30, classStyle: 0x0008, delay: 100 * time.Millisecond},
		{name: "outside horizontal tolerance", hwnd: 10, x: 23, y: 30, classStyle: 0x0008, delay: 100 * time.Millisecond},
		{name: "outside vertical tolerance", hwnd: 10, x: 20, y: 33, classStyle: 0x0008, delay: 100 * time.Millisecond},
		{name: "too late", hwnd: 10, x: 20, y: 30, classStyle: 0x0008, delay: 501 * time.Millisecond},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			start := time.Unix(100, 0)
			tracker := leftClickTracker{hwnd: 10, x: 20, y: 30, at: start}
			if got := tracker.press(start.Add(test.delay), test.hwnd, test.x, test.y, test.classStyle, 500*time.Millisecond); got != 0x0201 {
				t.Fatalf("press = %#x, want WM_LBUTTONDOWN", got)
			}
		})
	}
}

func TestNormalizeDoubleClickTime(t *testing.T) {
	tests := []struct {
		value uint32
		want  uint32
	}{
		{value: 0, want: 500},
		{value: 1, want: 1},
		{value: 5000, want: 5000},
		{value: 5001, want: 5000},
	}
	for _, test := range tests {
		if got := normalizeDoubleClickTime(test.value); got != test.want {
			t.Fatalf("normalizeDoubleClickTime(%d) = %d, want %d", test.value, got, test.want)
		}
	}
}

func TestDecodePointArgsPreservesSignedCoordinates(t *testing.T) {
	wantX, wantY := int32(-12), int32(-34)
	x64, y64 := decodePointArgs(uint64(uint32(wantX))|uint64(uint32(wantY))<<32, 0, false)
	if x64 != wantX || y64 != wantY {
		t.Fatalf("x64 decodePointArgs = (%d,%d), want (%d,%d)", x64, y64, wantX, wantY)
	}
	x86, y86 := decodePointArgs(uint64(uint32(wantX)), uint64(uint32(wantY)), true)
	if x86 != wantX || y86 != wantY {
		t.Fatalf("x86 decodePointArgs = (%d,%d), want (%d,%d)", x86, y86, wantX, wantY)
	}
}

func TestChildWindowAtPointHonorsFlagsAndZOrder(t *testing.T) {
	const parent = uint64(10)
	children := map[uint64]*controlState{
		20: {parentHWND: parent, x: 100, y: 200, w: 80, h: 40, visible: true},
		21: {parentHWND: parent, x: 100, y: 200, w: 80, h: 40, visible: true},
		22: {parentHWND: parent, x: 200, y: 200, w: 80, h: 40},
		23: {parentHWND: parent, x: 300, y: 200, w: 80, h: 40, visible: true, style: 0x08000000},
		24: {parentHWND: parent, x: 400, y: 200, w: 80, h: 40, visible: true, exStyle: 0x00000020},
		25: {parentHWND: parent, x: 500, y: 200, w: 80, h: 40, visible: true},
		26: {parentHWND: parent, x: 500, y: 200, w: 80, h: 40, visible: true, className: "button", style: 7},
	}
	order := []uint64{26, 25, 24, 23, 22, 21, 20}

	if got := childWindowAtPoint(children, order, parent, 110, 210, 0); got != 21 {
		t.Fatalf("overlap hit = %d, want topmost window 21", got)
	}
	if got := childWindowAtPoint(children, order, parent, 210, 210, 0); got != 22 {
		t.Fatalf("hidden hit without skip flag = %d, want 22", got)
	}
	if got := childWindowAtPoint(children, order, parent, 210, 210, cwpSkipInvisible); got != 0 {
		t.Fatalf("hidden hit with skip flag = %d, want 0", got)
	}
	if got := childWindowAtPoint(children, order, parent, 310, 210, cwpSkipDisabled); got != 0 {
		t.Fatalf("disabled hit with skip flag = %d, want 0", got)
	}
	if got := childWindowAtPoint(children, order, parent, 410, 210, cwpSkipTransparent); got != 0 {
		t.Fatalf("transparent hit with skip flag = %d, want 0", got)
	}
	if got := childWindowAtPoint(children, order, parent, 510, 210, cwpSkipHitTestTransparent); got != 25 {
		t.Fatalf("group box transparent hit = %d, want underlying child 25", got)
	}
	isolated := map[uint64]*controlState{26: children[26]}
	if got := childWindowAtPoint(isolated, []uint64{26}, parent, 510, 210,
		cwpSkipHitTestTransparent|cwpReturnHitTestFallback); got != 26 {
		t.Fatalf("isolated group box hit = %d, want fallback 26", got)
	}
}

func TestDeepestVisibleWindowAtPoint(t *testing.T) {
	children := map[uint64]*controlState{
		20: {parentHWND: 10, x: 100, y: 200, w: 100, h: 100, visible: true},
		30: {parentHWND: 20, x: 120, y: 220, w: 40, h: 40, visible: true},
		31: {parentHWND: 30, x: 125, y: 225, w: 10, h: 10},
		32: {parentHWND: 30, x: 125, y: 225, w: 10, h: 10, visible: true, className: "static"},
	}
	order := []uint64{32, 31, 30, 20}
	if got := deepestVisibleWindowAtPoint(children, order, 10, 130, 230); got != 30 {
		t.Fatalf("deepest visible hit = %d, want 30", got)
	}
	if got := deepestVisibleWindowAtPoint(children, order, 10, 170, 270); got != 20 {
		t.Fatalf("parent-only hit = %d, want 20", got)
	}
}

func TestWindowFromPointUsesZOrderAndGlobalTopLevels(t *testing.T) {
	const first, second = uint64(0x7f000001), uint64(0x7f000002)
	win32.Global.Create(first, "first", 10, 20, 100, 100, win32.WS_VISIBLE, 0, 0)
	win32.Global.Create(second, "second", 10, 20, 100, 100, win32.WS_VISIBLE, 0, 0)
	defer win32.Global.Destroy(first)
	defer win32.Global.Destroy(second)

	if got := windowFromPoint(nil, []uint64{first, second}, 0, win32.Rect{}, 30, 40); got != first {
		t.Fatalf("front hit = 0x%x, want 0x%x", got, first)
	}
	if got := windowFromPoint(nil, []uint64{second, first}, 0, win32.Rect{}, 30, 40); got != second {
		t.Fatalf("reordered hit = 0x%x, want 0x%x", got, second)
	}
	win32.Global.SetLong(second, win32.GWL_STYLE, uint64(win32.WS_VISIBLE|win32.WS_DISABLED))
	if got := windowFromPoint(nil, []uint64{second, first}, 0, win32.Rect{}, 30, 40); got != first {
		t.Fatalf("disabled top-level hit = 0x%x, want 0x%x", got, first)
	}
}

func TestWindowClientGeometryUsesClientRect(t *testing.T) {
	const hwnd = uint64(0x7f000003)
	win32.Global.Create(hwnd, "bordered", 100, 200, 120, 80,
		win32.WS_CHILD|win32.WS_VISIBLE|win32.WS_BORDER, 0, 1)
	defer win32.Global.Destroy(hwnd)

	x, y, width, height := windowClientGeometry(nil, hwnd)
	if x <= 100 || y <= 200 || width >= 120 || height >= 80 {
		t.Fatalf("client geometry = (%d,%d %dx%d)", x, y, width, height)
	}
}

func TestWriteComboBoxInfoGuestLayouts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		is32       bool
		structSize uint32
	}{
		{name: "PE32", is32: true, structSize: 52},
		{name: "PE64", is32: false, structSize: 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem := mmu.New()
			const (
				addr     = uint64(0x4000)
				hwnd     = uint64(0x12345678)
				sentinel = uint32(0xa5a5a5a5)
			)
			mem.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			if err := mem.Write32(addr, tc.structSize); err != nil {
				t.Fatal(err)
			}
			if err := mem.Write32(addr+uint64(tc.structSize), sentinel); err != nil {
				t.Fatal(err)
			}

			ctx := &ntapi.TrapContext{Mem: mem, State: &ntapi.ProcessState{Is32: tc.is32}}
			if !writeComboBoxInfoForTrap(ctx, addr, hwnd, 120, 200, 3, true) {
				t.Fatal("writeComboBoxInfo returned false")
			}
			for offset, want := range map[uint64]uint32{
				12: 103,
				16: 24,
				20: 103,
				28: 120,
				32: 24,
				36: 8,
			} {
				got, err := mem.Read32(addr + offset)
				if err != nil || got != want {
					t.Fatalf("field at %d = %d, want %d, err = %v", offset, got, want, err)
				}
			}
			if tc.is32 {
				got, err := mem.Read32(addr + 40)
				if err != nil || got != uint32(hwnd) {
					t.Fatalf("hwndCombo = %#x, err = %v", got, err)
				}
				for _, offset := range []uint64{44, 48} {
					got, err = mem.Read32(addr + offset)
					if err != nil || got != uint32(hwnd) {
						t.Fatalf("child handle at %d = %#x, err = %v", offset, got, err)
					}
				}
			} else {
				got, err := mem.Read64(addr + 40)
				if err != nil || got != hwnd {
					t.Fatalf("hwndCombo = %#x, err = %v", got, err)
				}
				for _, offset := range []uint64{48, 56} {
					got, err = mem.Read64(addr + offset)
					if err != nil || got != hwnd {
						t.Fatalf("child handle at %d = %#x, err = %v", offset, got, err)
					}
				}
			}
			gotSentinel, err := mem.Read32(addr + uint64(tc.structSize))
			if err != nil || gotSentinel != sentinel {
				t.Fatalf("adjacent memory = %#x, err = %v", gotSentinel, err)
			}
		})
	}
}

func TestWriteComboBoxInfoRejectsShortBuffer(t *testing.T) {
	mem := mmu.New()
	const addr = uint64(0x4000)
	mem.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if err := mem.Write32(addr, 48); err != nil {
		t.Fatal(err)
	}
	if writeComboBoxInfo(mem, addr, 1, true, 100, 20, 3, false) {
		t.Fatal("writeComboBoxInfo accepted a short PE32 structure")
	}
}

func TestWriteComboBoxInfoSimpleHidesButton(t *testing.T) {
	mem := mmu.New()
	const addr = uint64(0x4000)
	mem.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if err := mem.Write32(addr, 52); err != nil {
		t.Fatal(err)
	}
	if !writeComboBoxInfo(mem, addr, 1, true, 100, 200, 1, true) {
		t.Fatal("writeComboBoxInfo returned false")
	}
	buttonLeft, err := mem.Read32(addr + 20)
	if err != nil || buttonLeft != 100 {
		t.Fatalf("button left = %d, err = %v", buttonLeft, err)
	}
	buttonState, err := mem.Read32(addr + 36)
	if err != nil || buttonState != 0x8000 {
		t.Fatalf("button state = %#x, err = %v", buttonState, err)
	}
}
