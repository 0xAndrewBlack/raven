//go:build guest_windows

package ntapi

import "testing"

func TestThreadExitCodeLifecycle(t *testing.T) {
	handles := NewHandleTable()
	done := make(chan struct{})
	handle := handles.Alloc(&ThreadHandle{TID: 42, Done: done})

	if code, active, ok := handles.ThreadExitCode(handle); !ok || !active || code != 0 {
		t.Fatalf("active thread = (%d, %v, %v)", code, active, ok)
	}
	if !handles.SetThreadExitCodeByTID(42, 17) {
		t.Fatal("thread exit code was not stored")
	}
	close(done)
	if code, active, ok := handles.ThreadExitCode(handle); !ok || active || code != 17 {
		t.Fatalf("exited thread = (%d, %v, %v)", code, active, ok)
	}
	if _, _, ok := handles.ThreadExitCode(Handle(0xdead)); ok {
		t.Fatal("invalid handle was accepted")
	}
}

func TestThreadByTIDFindsExistingHandle(t *testing.T) {
	handles := NewHandleTable()
	thread := &ThreadHandle{TID: 42, Done: make(chan struct{})}
	handles.Alloc(thread)

	if got := handles.ThreadByTID(42); got != thread {
		t.Fatalf("ThreadByTID(42) = %p, want %p", got, thread)
	}
	if got := handles.ThreadByTID(43); got != nil {
		t.Fatalf("ThreadByTID(43) = %p, want nil", got)
	}
}
