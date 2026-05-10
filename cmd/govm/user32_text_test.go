//go:build guest_windows

package main

import "testing"

func TestResolveWindowTextPrefersControlText(t *testing.T) {
	children := map[uint64]*controlState{
		0x10: {text: "testdata/notepad.exe"},
	}
	titles := map[uint64]string{
		0x10: "stale title",
		0x20: "window title",
	}

	if got := resolveWindowText(0x10, children, titles); got != "testdata/notepad.exe" {
		t.Fatalf("control text = %q", got)
	}
	if got := resolveWindowText(0x20, children, titles); got != "window title" {
		t.Fatalf("window title = %q", got)
	}
}
