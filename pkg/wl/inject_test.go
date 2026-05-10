package wl

import (
	"testing"
	"time"
)

func TestInjectKeyChord(t *testing.T) {
	d := &Display{}
	d.InjectKeyChord(29, 31) // Ctrl+S

	if len(d.keyEvents) != 4 {
		t.Fatalf("events = %d, want 4", len(d.keyEvents))
	}
	wantVK := []uint32{0x11, 'S', 'S', 0x11}
	wantPressed := []bool{true, true, false, false}
	for i, event := range d.keyEvents {
		if event.VK != wantVK[i] || event.Pressed != wantPressed[i] {
			t.Fatalf("event %d = {VK:0x%x Pressed:%v}, want {VK:0x%x Pressed:%v}", i, event.VK, event.Pressed, wantVK[i], wantPressed[i])
		}
		if event.Char != 0 {
			t.Fatalf("event %d Char = %q, want no text input for chord", i, event.Char)
		}
	}
}

func TestInjectKeyWindowTargetsRequestedWindow(t *testing.T) {
	d := &Display{}
	win := &Window{Title: "Find"}

	d.InjectKeyWindow(win, 35)

	if len(d.keyEvents) != 2 {
		t.Fatalf("key events = %d, want 2", len(d.keyEvents))
	}
	for _, event := range d.keyEvents {
		if event.Window != win {
			t.Fatal("key event targeted the wrong window")
		}
	}
}

func TestInjectTextWindowPreservesCharactersAndTarget(t *testing.T) {
	d := &Display{}
	win := &Window{Title: "Run..."}
	d.InjectTextWindow(win, "notepad++.exe")

	if got, want := len(d.keyEvents), len([]rune("notepad++.exe"))*2; got != want {
		t.Fatalf("events = %d, want %d", got, want)
	}
	for i, ch := range []rune("notepad++.exe") {
		event := d.keyEvents[i*2]
		if event.Window != win || event.Char != ch || !event.Pressed {
			t.Fatalf("event %d = %+v", i*2, event)
		}
	}
}

func TestPollKeyTracksSyntheticModifiers(t *testing.T) {
	d := &Display{}
	d.InjectKeyChord(29, 31)

	event, ok := d.PollKey()
	if !ok || event.VK != 0x11 || !event.Pressed {
		t.Fatalf("first event = %#v, %v, want control press", event, ok)
	}
	if !d.CtrlDown() {
		t.Fatal("control state is not set after synthetic key press")
	}

	for i := 0; i < 3; i++ {
		if _, ok := d.PollKey(); !ok {
			t.Fatalf("missing event %d", i+2)
		}
	}
	if d.CtrlDown() {
		t.Fatal("control state remains set after synthetic key release")
	}
}

func TestSyntheticInputTargetsPrimaryWindow(t *testing.T) {
	win := NewHeadlessWindow("primary", 320, 200, 0)
	d := &Display{win: win}

	d.InjectClick(12, 34)
	for i := 0; i < 3; i++ {
		event, ok := d.PollMouse()
		if !ok {
			t.Fatalf("missing mouse event %d", i)
		}
		if event.Window != win {
			t.Fatalf("mouse event %d targets %p, want %p", i, event.Window, win)
		}
	}

	d.InjectKey(30)
	for i := 0; i < 2; i++ {
		event, ok := d.PollKey()
		if !ok {
			t.Fatalf("missing key event %d", i)
		}
		if event.Window != win {
			t.Fatalf("key event %d targets %p, want %p", i, event.Window, win)
		}
	}
}

func TestInjectClickTargetsRequestedWindow(t *testing.T) {
	primary := NewHeadlessWindow("primary", 320, 200, 0)
	dialog := NewHeadlessWindow("Find", 200, 100, 0)
	d := &Display{win: primary}

	d.InjectClickWindow(dialog, 40, 20)
	for i := 0; i < 3; i++ {
		event, ok := d.PollMouse()
		if !ok {
			t.Fatalf("missing mouse event %d", i)
		}
		if event.Window != dialog {
			t.Fatalf("mouse event %d targets %p, want %p", i, event.Window, dialog)
		}
		if event.Kind == 1 && event.When.IsZero() {
			t.Fatalf("mouse button event %d has no source timestamp", i)
		}
	}
}

func TestInjectDoubleClickUsesSourceTimestamps(t *testing.T) {
	win := NewHeadlessWindow("primary", 320, 200, 0)
	d := &Display{win: win}

	d.InjectDoubleClick(12, 34)
	var presses []MouseEvent
	for i := 0; i < 5; i++ {
		event, ok := d.PollMouse()
		if !ok {
			t.Fatalf("missing mouse event %d", i)
		}
		if event.Kind == 1 && event.Pressed {
			presses = append(presses, event)
		}
	}
	if len(presses) != 2 {
		t.Fatalf("press count = %d, want 2", len(presses))
	}
	if got := presses[1].When.Sub(presses[0].When); got != 100*time.Millisecond {
		t.Fatalf("press interval = %s, want 100ms", got)
	}
}

func TestClearWindowInputDropsDestroyedTargets(t *testing.T) {
	d := &Display{}
	dialog := NewHeadlessWindow("Print", 200, 100, 0)
	other := NewHeadlessWindow("main", 320, 200, 0)
	d.pointerWindow = dialog
	d.keyboardWindow = dialog
	d.lastEventWindow = dialog
	d.shiftDown = true
	d.ctrlDown = true
	d.altDown = true
	d.keyEvents = []KeyEvent{{Window: dialog}, {Window: other}}
	d.mouseEvents = []MouseEvent{{Window: dialog}, {Window: other}}

	d.clearWindowInput(dialog)

	if d.pointerWindow != nil || d.keyboardWindow != nil || d.lastEventWindow != nil {
		t.Fatal("destroyed window remained an input target")
	}
	if d.shiftDown || d.ctrlDown || d.altDown {
		t.Fatal("destroyed keyboard target left modifiers pressed")
	}
	if len(d.keyEvents) != 1 || d.keyEvents[0].Window != other {
		t.Fatalf("key events = %+v", d.keyEvents)
	}
	if len(d.mouseEvents) != 1 || d.mouseEvents[0].Window != other {
		t.Fatalf("mouse events = %+v", d.mouseEvents)
	}
}

func TestPollInputForWindowsPreservesOtherTargets(t *testing.T) {
	d := &Display{}
	dialog := NewHeadlessWindow("dialog", 200, 100, 0)
	owner := NewHeadlessWindow("owner", 320, 200, 0)
	other := NewHeadlessWindow("other", 320, 200, 0)
	d.keyEvents = []KeyEvent{
		{Window: other, VK: 0x41, Pressed: true},
		{Window: dialog, VK: 0x0d, Pressed: true},
		{Window: owner, VK: 0x1b, Pressed: true},
	}
	d.mouseEvents = []MouseEvent{
		{Window: other, Button: 272, Pressed: true},
		{Window: dialog, Button: 272, Pressed: true},
	}

	if !d.HasPendingInputForWindows(dialog, owner) {
		t.Fatal("modal input was not reported as pending")
	}
	key, ok := d.PollKeyForWindows(dialog, owner)
	if !ok || key.Window != dialog || key.VK != 0x0d {
		t.Fatalf("key = %+v, ok = %v", key, ok)
	}
	mouse, ok := d.PollMouseForWindows(dialog, owner)
	if !ok || mouse.Window != dialog {
		t.Fatalf("mouse = %+v, ok = %v", mouse, ok)
	}
	if len(d.keyEvents) != 2 || d.keyEvents[0].Window != other || d.keyEvents[1].Window != owner {
		t.Fatalf("key events = %+v", d.keyEvents)
	}
	if len(d.mouseEvents) != 1 || d.mouseEvents[0].Window != other {
		t.Fatalf("mouse events = %+v", d.mouseEvents)
	}
}

func TestTakeAndPrependInputForWindows(t *testing.T) {
	d := &Display{}
	dialog := NewHeadlessWindow("dialog", 200, 100, 0)
	other := NewHeadlessWindow("other", 320, 200, 0)
	dialogKey := KeyEvent{Window: dialog, VK: 0x0d, Pressed: true}
	otherKey := KeyEvent{Window: other, VK: 0x41, Pressed: true}
	dialogMouse := MouseEvent{Window: dialog, Button: 272, Pressed: true}
	otherMouse := MouseEvent{Window: other, Button: 272, Pressed: true}
	d.keyEvents = []KeyEvent{dialogKey, otherKey}
	d.mouseEvents = []MouseEvent{dialogMouse, otherMouse}

	keys, mouse := d.TakeInputForWindows(dialog)
	if len(keys) != 1 || keys[0].Window != dialog || len(mouse) != 1 || mouse[0].Window != dialog {
		t.Fatalf("taken keys=%+v mouse=%+v", keys, mouse)
	}
	if len(d.keyEvents) != 1 || d.keyEvents[0].Window != other ||
		len(d.mouseEvents) != 1 || d.mouseEvents[0].Window != other {
		t.Fatalf("remaining keys=%+v mouse=%+v", d.keyEvents, d.mouseEvents)
	}

	d.PrependInput(keys, mouse)
	if len(d.keyEvents) != 2 || d.keyEvents[0].Window != dialog ||
		len(d.mouseEvents) != 2 || d.mouseEvents[0].Window != dialog {
		t.Fatalf("restored keys=%+v mouse=%+v", d.keyEvents, d.mouseEvents)
	}
}

func TestSuspendedInputBlocksConcurrentInjection(t *testing.T) {
	d := &Display{}
	dialog := NewHeadlessWindow("dialog", 200, 100, 0)
	started := make(chan struct{})
	done := make(chan struct{})

	d.WithInputForWindowsSuspended([]*Window{dialog}, func() {
		go func() {
			close(started)
			d.InjectKeyWindow(dialog, 28)
			close(done)
		}()
		<-started
		select {
		case <-done:
			t.Fatal("input injection completed while modal input was suspended")
		default:
		}
	})
	<-done
	key, ok := d.PollKeyForWindows(dialog)
	if !ok || key.Window != dialog || key.VK != 0x0d {
		t.Fatalf("key = %+v, ok = %v", key, ok)
	}
}

func TestWindowForSurfaceResolvesOwnedWindow(t *testing.T) {
	mainWindow := NewHeadlessWindow("main", 320, 200, 0)
	dialogWindow := NewHeadlessWindow("Replace", 200, 100, 0)
	d := &Display{windowsBySurface: map[uint32]*Window{
		11: mainWindow,
		17: dialogWindow,
	}}

	if got := d.windowForSurface(17); got != dialogWindow {
		t.Fatalf("surface 17 resolved to %p, want %p", got, dialogWindow)
	}
	if got := d.windowForSurface(99); got != nil {
		t.Fatalf("unknown surface resolved to %p", got)
	}
}

func TestPollReturnsRetainedCloseWithOriginalWindow(t *testing.T) {
	mainWindow := NewHeadlessWindow("main", 320, 200, 0)
	dialogWindow := NewHeadlessWindow("Find", 200, 100, 0)
	d := &Display{fd: -1, lastEventWindow: dialogWindow}
	d.retainEvent(EventClose)
	d.lastEventWindow = mainWindow

	evt, err := d.Poll()
	if err != nil {
		t.Fatal(err)
	}
	if evt != EventClose {
		t.Fatalf("event = %v, want EventClose", evt)
	}
	if d.LastEventWindow() != dialogWindow {
		t.Fatal("retained close lost its source window")
	}
}

func TestInjectCloseWindowQueuesTargetedClose(t *testing.T) {
	display := &Display{}
	mainWindow := NewHeadlessWindow("main", 320, 200, 0)
	dialogWindow := NewHeadlessWindow("Find", 200, 100, 0)

	display.InjectCloseWindow(dialogWindow)

	event, err := display.Poll()
	if err != nil {
		t.Fatal(err)
	}
	if event != EventClose {
		t.Fatalf("event = %v, want EventClose", event)
	}
	if display.LastEventWindow() != dialogWindow {
		t.Fatal("close target was not preserved")
	}
	if display.LastEventWindow() == mainWindow {
		t.Fatal("close targeted the main window")
	}
}

func TestDispatchOneMapsXdgToplevelCloseToItsWindow(t *testing.T) {
	dialogWindow := NewHeadlessWindow("Find", 200, 100, 0)
	const toplevelID = uint32(23)
	display := &Display{
		objects:             map[uint32]objKind{toplevelID: kindXdgToplevel},
		windowsByToplevel:   map[uint32]*Window{toplevelID: dialogWindow},
		windowsBySurface:    map[uint32]*Window{},
		windowsByXdgSurface: map[uint32]*Window{},
		fd:                  -1,
	}
	display.readBuf = append(pu32(toplevelID), pu32(uint32(8)<<16|1)...)

	event, err := display.dispatchOne()
	if err != nil {
		t.Fatal(err)
	}
	if event != EventClose {
		t.Fatalf("event = %v, want EventClose", event)
	}
	if display.LastEventWindow() != dialogWindow {
		t.Fatal("xdg_toplevel close lost its target window")
	}
	if !dialogWindow.Closed {
		t.Fatal("xdg_toplevel close did not mark the target closed")
	}
}
