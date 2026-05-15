//go:build guest_windows

package main

import (
	"errors"
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/ntobj"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestReadWin32HandleArrayLayouts(t *testing.T) {
	mem := mmu.New()
	const address = uint64(0x4000)
	mem.MapRange(address, mmu.PageSize, mmu.PermRead|mmu.PermWrite)

	if err := mem.Write32(address, 0x200); err != nil {
		t.Fatal(err)
	}
	if err := mem.Write32(address+4, 0x204); err != nil {
		t.Fatal(err)
	}
	values := readWin32HandleArray(mem, address, 2, true)
	if len(values) != 2 || values[0] != 0x200 || values[1] != 0x204 {
		t.Fatalf("PE32 handles = %#v", values)
	}

	if err := mem.Write64(address, 0x100000200); err != nil {
		t.Fatal(err)
	}
	if err := mem.Write64(address+8, 0x100000204); err != nil {
		t.Fatal(err)
	}
	values = readWin32HandleArray(mem, address, 2, false)
	if len(values) != 2 || values[0] != 0x100000200 || values[1] != 0x100000204 {
		t.Fatalf("PE64 handles = %#v", values)
	}
}

func TestWaitMultipleFallbackObservesLaterSignaledHandle(t *testing.T) {
	handles := ntapi.NewHandleTable()
	pending := make(chan struct{})
	first := handles.Alloc(&ntapi.ThreadHandle{Done: pending})
	second := handles.Alloc(ntapi.NewEvent(true, true))

	start := time.Now()
	result := waitMultipleFallbackWin32(handles, []ntapi.Handle{first, second}, 1, false, time.Second)
	if result != 1 {
		t.Fatalf("wait result = %#x, want 1", result)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("wait took %s", elapsed)
	}
}

func TestWaitMultipleFallbackTimesOut(t *testing.T) {
	handles := ntapi.NewHandleTable()
	first := handles.Alloc(ntapi.NewEvent(true, false))
	second := handles.Alloc(ntapi.NewEvent(true, false))

	result := waitMultipleFallbackWin32(handles, []ntapi.Handle{first, second}, 1, false, 5*time.Millisecond)
	if result != 0x102 {
		t.Fatalf("wait result = %#x, want WAIT_TIMEOUT", result)
	}
}

func TestWaitExRejectsInvalidHandles(t *testing.T) {
	handles := ntapi.NewHandleTable()
	invalid := ntapi.Handle(0x7FFFFFF0)

	if result, apcs := waitOneExWin32(handles, invalid, 1, 0, true); result != uint64(ntobj.WaitFailed) || len(apcs) != 0 {
		t.Fatalf("single invalid wait = %#x/%d", result, len(apcs))
	}
	if result, apcs := waitMultipleExWin32(handles, []ntapi.Handle{invalid}, 1, false, 0, true); result != uint64(ntobj.WaitFailed) || len(apcs) != 0 {
		t.Fatalf("multiple invalid wait = %#x/%d", result, len(apcs))
	}
}

func TestWaitMultipleFallbackDoesNotConsumeUnifiedObjectBeforeWaitAll(t *testing.T) {
	handles := ntapi.NewHandleTable()
	event := ntapi.NewEvent(false, true)
	eventHandle := handles.Alloc(event)
	threadHandle := handles.Alloc(&ntapi.ThreadHandle{Done: make(chan struct{})})

	result := waitMultipleFallbackWin32(
		handles,
		[]ntapi.Handle{eventHandle, threadHandle},
		1,
		true,
		5*time.Millisecond,
	)
	if result != 0x102 {
		t.Fatalf("wait result = %#x, want WAIT_TIMEOUT", result)
	}
	if !event.WaitTimeout(0) {
		t.Fatal("wait-all timeout consumed the auto-reset event")
	}
}

func TestWaitAllTimerAndEventIsAtomic(t *testing.T) {
	handles := ntapi.NewHandleTable()
	event := ntapi.NewEvent(false, true)
	timer := ntapi.NewWaitableTimer(false)
	eventHandle := handles.Alloc(event)
	timerHandle := handles.Alloc(timer)

	result := waitMultipleFallbackWin32(handles, []ntapi.Handle{eventHandle, timerHandle}, 1, true, 2*time.Millisecond)
	if result != uint64(ntobj.WaitTimeout) {
		t.Fatalf("initial wait = %#x, want WAIT_TIMEOUT", result)
	}
	if !event.PeekSignaled() {
		t.Fatal("timed-out WaitAll consumed the auto-reset event")
	}

	timer.Set(0, 0)
	result = waitMultipleFallbackWin32(handles, []ntapi.Handle{eventHandle, timerHandle}, 1, true, 200*time.Millisecond)
	if result != uint64(ntobj.WaitObject0) {
		t.Fatalf("signaled wait = %#x, want WAIT_OBJECT_0", result)
	}
	if event.PeekSignaled() || timer.IsSignaled() {
		t.Fatal("successful WaitAll did not consume synchronization objects")
	}
}

func TestWaitOneExAlertableReturnsQueuedAPC(t *testing.T) {
	handles := ntapi.NewHandleTable()
	event := handles.Alloc(ntapi.NewEvent(true, false))
	const tid = uint32(0x7101)
	ran := false
	ntapi.ObjMgr.QueueAPC(uint64(tid), func() { ran = true })

	result, apcs := waitOneExWin32(handles, event, tid, time.Second, true)
	if result != 0xC0 {
		t.Fatalf("wait result = %#x, want WAIT_IO_COMPLETION", result)
	}
	if len(apcs) != 1 {
		t.Fatalf("APC count = %d, want 1", len(apcs))
	}
	if ran {
		t.Fatal("APC ran while the object manager lock was held")
	}
	for _, apc := range apcs {
		apc()
	}
	if !ran {
		t.Fatal("queued APC did not run")
	}
}

func TestWaitOneExNonAlertableLeavesAPCQueued(t *testing.T) {
	handles := ntapi.NewHandleTable()
	event := handles.Alloc(ntapi.NewEvent(true, true))
	const tid = uint32(0x7102)
	ntapi.ObjMgr.QueueAPC(uint64(tid), func() {})

	result, apcs := waitOneExWin32(handles, event, tid, 0, false)
	if result != 0 || len(apcs) != 0 {
		t.Fatalf("non-alertable wait = %#x with %d APCs, want object 0", result, len(apcs))
	}
	result32, queued := ntapi.ObjMgr.WaitEx(nil, false, uint64(tid), 0, true)
	if result32 != 0xC0 || len(queued) != 1 {
		t.Fatalf("queued APC after non-alertable wait = %#x/%d", result32, len(queued))
	}
}

func TestWaitMultipleExAlertableReturnsQueuedAPC(t *testing.T) {
	handles := ntapi.NewHandleTable()
	first := handles.Alloc(ntapi.NewEvent(true, false))
	second := handles.Alloc(ntapi.NewEvent(true, false))
	const tid = uint32(0x7103)
	ntapi.ObjMgr.QueueAPC(uint64(tid), func() {})

	result, apcs := waitMultipleExWin32(
		handles,
		[]ntapi.Handle{first, second},
		tid,
		false,
		time.Second,
		true,
	)
	if result != 0xC0 || len(apcs) != 1 {
		t.Fatalf("alertable multiple wait = %#x/%d, want WAIT_IO_COMPLETION/1", result, len(apcs))
	}
}

func TestDispatchAlertableAPCsDrainsInFIFOOrder(t *testing.T) {
	const tid = uint32(0x7105)
	order := make([]int, 0, 2)
	ntapi.ObjMgr.QueueAPC(uint64(tid), func() { order = append(order, 1) })
	ntapi.ObjMgr.QueueAPC(uint64(tid), func() { order = append(order, 2) })

	result, queued := ntapi.ObjMgr.WaitEx(nil, false, uint64(tid), 0, true)
	if result != ntobj.WaitIOCompletion {
		t.Fatalf("initial APC wait = %#x", result)
	}
	dispatchAlertableAPCs(tid, queued)
	if len(order) != 2 || order[0] != 1 || order[1] != 2 {
		t.Fatalf("APC order = %v", order)
	}
}

func TestAbortGuestCPUStoresCallbackFailure(t *testing.T) {
	cpu := x64.New(mmu.New())
	want := errors.New("callback fault")
	abortGuestCPU(cpu, want)
	if !errors.Is(cpu.AbortError(), want) {
		t.Fatalf("abort error = %v", cpu.AbortError())
	}
}

func TestWaitOneExAlertableTimesOut(t *testing.T) {
	handles := ntapi.NewHandleTable()
	event := handles.Alloc(ntapi.NewEvent(true, false))
	const tid = uint32(0x7104)

	result, apcs := waitOneExWin32(handles, event, tid, 2*time.Millisecond, true)
	if result != 0x102 || len(apcs) != 0 {
		t.Fatalf("alertable timeout = %#x/%d, want WAIT_TIMEOUT/0", result, len(apcs))
	}
}

func TestWindowsFileMatch(t *testing.T) {
	for _, test := range []struct {
		pattern string
		name    string
		want    bool
	}{
		{pattern: "*.TXT", name: "readme.txt", want: true},
		{pattern: "*.*", name: "LICENSE", want: true},
		{pattern: "file?.log", name: "FILE1.LOG", want: true},
		{pattern: "*.txt", name: "image.png", want: false},
	} {
		if got := windowsFileMatch(test.pattern, test.name); got != test.want {
			t.Errorf("windowsFileMatch(%q, %q) = %t, want %t", test.pattern, test.name, got, test.want)
		}
	}
}
