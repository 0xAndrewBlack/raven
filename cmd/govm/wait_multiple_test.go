//go:build guest_windows

package main

import (
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
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
