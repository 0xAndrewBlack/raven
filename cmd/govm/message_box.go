//go:build guest_windows

package main

import "strings"

const (
	messageBoxIDOK       = uint64(1)
	messageBoxIDCancel   = uint64(2)
	messageBoxIDAbort    = uint64(3)
	messageBoxIDRetry    = uint64(4)
	messageBoxIDIgnore   = uint64(5)
	messageBoxIDYes      = uint64(6)
	messageBoxIDNo       = uint64(7)
	messageBoxIDTryAgain = uint64(10)
	messageBoxIDContinue = uint64(11)
)

type messageBoxButton struct {
	id    uint64
	label string
}

type messageBoxSpec struct {
	buttons   []messageBoxButton
	defaultID uint64
	escapeID  uint64
}

type messageBoxRuntime struct {
	hwnd          uint64
	owner         uint64
	defaultID     uint64
	escapeID      uint64
	result        uint64
	previousFocus uint64
	retAddr       uint64
	retRSP        uint64
	pumpSP        uint64
	callee        guestNonvolatileRegisters
	syncDepth     int
}

func resolveMessageBoxSpec(uType uint32) messageBoxSpec {
	var buttons []messageBoxButton
	switch uType & 0x0f {
	case 1:
		buttons = []messageBoxButton{
			{id: messageBoxIDOK, label: "OK"},
			{id: messageBoxIDCancel, label: "Cancel"},
		}
	case 2:
		buttons = []messageBoxButton{
			{id: messageBoxIDAbort, label: "Abort"},
			{id: messageBoxIDRetry, label: "Retry"},
			{id: messageBoxIDIgnore, label: "Ignore"},
		}
	case 3:
		buttons = []messageBoxButton{
			{id: messageBoxIDYes, label: "Yes"},
			{id: messageBoxIDNo, label: "No"},
			{id: messageBoxIDCancel, label: "Cancel"},
		}
	case 4:
		buttons = []messageBoxButton{
			{id: messageBoxIDYes, label: "Yes"},
			{id: messageBoxIDNo, label: "No"},
		}
	case 5:
		buttons = []messageBoxButton{
			{id: messageBoxIDRetry, label: "Retry"},
			{id: messageBoxIDCancel, label: "Cancel"},
		}
	case 6:
		buttons = []messageBoxButton{
			{id: messageBoxIDCancel, label: "Cancel"},
			{id: messageBoxIDTryAgain, label: "Try Again"},
			{id: messageBoxIDContinue, label: "Continue"},
		}
	default:
		buttons = []messageBoxButton{{id: messageBoxIDOK, label: "OK"}}
	}

	defaultIndex := int((uType >> 8) & 3)
	if defaultIndex >= len(buttons) {
		defaultIndex = 0
	}
	spec := messageBoxSpec{
		buttons:   buttons,
		defaultID: buttons[defaultIndex].id,
	}
	for _, button := range buttons {
		if button.id == messageBoxIDCancel {
			spec.escapeID = messageBoxIDCancel
			break
		}
	}
	if len(buttons) == 1 && buttons[0].id == messageBoxIDOK {
		spec.escapeID = messageBoxIDOK
	}
	return spec
}

func wrapMessageBoxText(text string, width int) []string {
	if width < 1 {
		width = 1
	}
	var lines []string
	for _, paragraph := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}
		line := words[0]
		for _, word := range words[1:] {
			if len([]rune(line))+1+len([]rune(word)) <= width {
				line += " " + word
				continue
			}
			lines = append(lines, line)
			line = word
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func messageBoxButtonAt(children map[uint64]*controlState, dialog uint64, x, y int32) uint64 {
	root := children[dialog]
	if root == nil {
		return 0
	}
	for _, state := range children {
		if state == nil || state.parentHWND != dialog || !state.visible || !strings.EqualFold(state.className, "button") {
			continue
		}
		left := state.x - root.x
		top := state.y - root.y
		if x >= left && x < left+state.w && y >= top && y < top+state.h {
			return state.ctrlID
		}
	}
	return 0
}
