//go:build guest_windows

package main

import "testing"

func TestPopupMenuNextSelectableWrapsAndSkipsUnavailableItems(t *testing.T) {
	items := []menuItem{
		{text: "separator", flags: 0x0800},
		{text: "disabled", flags: 0x0003},
		{text: "Open"},
		{text: "Save"},
	}
	if got := popupMenuNextSelectable(items, -1, 1); got != 2 {
		t.Fatalf("first selection = %d, want 2", got)
	}
	if got := popupMenuNextSelectable(items, 2, -1); got != 3 {
		t.Fatalf("wrapped selection = %d, want 3", got)
	}
}
