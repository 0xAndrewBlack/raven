//go:build guest_windows

package main

import "testing"

func TestIsChildWindow(t *testing.T) {
	windows := map[uint64]*controlState{
		2: {parentHWND: 1, style: wsChildStyle},
		3: {parentHWND: 2, style: wsChildStyle},
		4: {parentHWND: 3, style: wsChildStyle},
		5: {parentHWND: 1},
		6: {parentHWND: 5, style: wsChildStyle},
	}

	for _, test := range []struct {
		name          string
		parent, child uint64
		want          bool
	}{
		{name: "direct child", parent: 1, child: 2, want: true},
		{name: "grandchild", parent: 1, child: 3, want: true},
		{name: "deep descendant", parent: 1, child: 4, want: true},
		{name: "reverse relationship", parent: 4, child: 1},
		{name: "same window", parent: 2, child: 2},
		{name: "unknown parent", parent: 9, child: 4},
		{name: "unknown child", parent: 1, child: 9},
		{name: "owned top level", parent: 1, child: 5},
		{name: "child of owned top level", parent: 1, child: 6},
		{name: "null parent", child: 2},
		{name: "null child", parent: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isChildWindow(windows, test.parent, test.child); got != test.want {
				t.Fatalf("isChildWindow(%d, %d) = %v, want %v", test.parent, test.child, got, test.want)
			}
		})
	}
}

func TestIsChildWindowRejectsParentCycles(t *testing.T) {
	windows := map[uint64]*controlState{
		2: {parentHWND: 3, style: wsChildStyle},
		3: {parentHWND: 2, style: wsChildStyle},
	}
	if isChildWindow(windows, 1, 2) {
		t.Fatal("cyclic hierarchy reported a child relationship")
	}
}

func TestReparentControlPreservesCoordinatesAndRejectsCycles(t *testing.T) {
	windows := map[uint64]*controlState{
		1: {x: 10, y: 20},
		2: {parentHWND: 1, x: 40, y: 50},
		3: {parentHWND: 2, x: 60, y: 70},
		4: {x: 100, y: 120},
	}
	oldParent, ok := reparentControl(windows, 2, 4)
	if !ok || oldParent != 1 {
		t.Fatalf("reparent = (%d, %v), want (1, true)", oldParent, ok)
	}
	if windows[2].parentHWND != 4 || windows[2].x != 40 || windows[2].y != 50 {
		t.Fatalf("reparent changed window geometry: %+v", windows[2])
	}
	if _, ok := reparentControl(windows, 4, 3); ok {
		t.Fatal("cyclic reparent was accepted")
	}
}
