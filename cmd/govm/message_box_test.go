//go:build guest_windows

package main

import (
	"reflect"
	"testing"
)

func TestResolveMessageBoxSpec(t *testing.T) {
	tests := []struct {
		name      string
		uType     uint32
		ids       []uint64
		defaultID uint64
		escapeID  uint64
	}{
		{name: "ok", ids: []uint64{1}, defaultID: 1, escapeID: 1},
		{name: "ok cancel", uType: 1, ids: []uint64{1, 2}, defaultID: 1, escapeID: 2},
		{name: "abort retry ignore", uType: 2, ids: []uint64{3, 4, 5}, defaultID: 3},
		{name: "yes no cancel", uType: 3, ids: []uint64{6, 7, 2}, defaultID: 6, escapeID: 2},
		{name: "yes no", uType: 4, ids: []uint64{6, 7}, defaultID: 6},
		{name: "retry cancel", uType: 5, ids: []uint64{4, 2}, defaultID: 4, escapeID: 2},
		{name: "cancel try continue", uType: 6, ids: []uint64{2, 10, 11}, defaultID: 2, escapeID: 2},
		{name: "second default", uType: 3 | 0x100, ids: []uint64{6, 7, 2}, defaultID: 7, escapeID: 2},
		{name: "invalid default", uType: 4 | 0x300, ids: []uint64{6, 7}, defaultID: 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := resolveMessageBoxSpec(tt.uType)
			ids := make([]uint64, len(spec.buttons))
			for i, button := range spec.buttons {
				ids[i] = button.id
			}
			if !reflect.DeepEqual(ids, tt.ids) {
				t.Fatalf("buttons = %v, want %v", ids, tt.ids)
			}
			if spec.defaultID != tt.defaultID || spec.escapeID != tt.escapeID {
				t.Fatalf("default/escape = %d/%d, want %d/%d", spec.defaultID, spec.escapeID, tt.defaultID, tt.escapeID)
			}
		})
	}
}

func TestWrapMessageBoxTextPreservesParagraphs(t *testing.T) {
	got := wrapMessageBoxText("one two three four\n\nfive", 9)
	want := []string{"one two", "three", "four", "", "five"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %#v, want %#v", got, want)
	}
}

func TestMessageBoxButtonAtUsesDialogLocalCoordinates(t *testing.T) {
	const dialog = uint64(0x50010)
	children := map[uint64]*controlState{
		dialog: {className: "dialog", x: 300, y: 200, w: 420, h: 160, visible: true},
		0x50011: {
			className: "button", parentHWND: dialog, ctrlID: 6,
			x: 410, y: 300, w: 88, h: 28, visible: true,
		},
		0x50012: {
			className: "button", parentHWND: dialog, ctrlID: 7,
			x: 510, y: 300, w: 88, h: 28, visible: true,
		},
	}
	if got := messageBoxButtonAt(children, dialog, 120, 110); got != 6 {
		t.Fatalf("button = %d, want 6", got)
	}
	if got := messageBoxButtonAt(children, dialog, 220, 110); got != 7 {
		t.Fatalf("button = %d, want 7", got)
	}
	if got := messageBoxButtonAt(children, dialog, 20, 20); got != 0 {
		t.Fatalf("outside button = %d, want 0", got)
	}
}
