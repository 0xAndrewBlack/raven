//go:build guest_windows

package main

const wsChildStyle = uint32(0x40000000)

func isChildWindow(windows map[uint64]*controlState, parent, child uint64) bool {
	if parent == 0 || child == 0 || parent == child {
		return false
	}

	for steps := 0; child != 0 && steps <= len(windows); steps++ {
		state, ok := windows[child]
		if !ok {
			return false
		}
		if state.style&wsChildStyle == 0 {
			return false
		}
		child = state.parentHWND
		if child == parent {
			return true
		}
	}
	return false
}

func reparentControl(windows map[uint64]*controlState, hwnd, newParent uint64) (uint64, bool) {
	state := windows[hwnd]
	if state == nil || hwnd == newParent {
		return 0, false
	}
	for ancestor, steps := newParent, 0; ancestor != 0 && steps <= len(windows); steps++ {
		if ancestor == hwnd {
			return 0, false
		}
		parent := windows[ancestor]
		if parent == nil {
			break
		}
		ancestor = parent.parentHWND
	}
	oldParent := state.parentHWND
	state.parentHWND = newParent
	return oldParent, true
}
