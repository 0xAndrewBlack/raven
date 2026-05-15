//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestMessageQueueInsertsEraseBeforePendingPaint(t *testing.T) {
	cpu := x64.New(mmu.New())
	queue := &messageQueue{}
	queue.enqueue(cpu, queuedMsg{hwnd: 10, message: 0x000F})
	queue.enqueueBefore(cpu, queuedMsg{hwnd: 10, message: 0x0014}, func(message queuedMsg) bool {
		return message.hwnd == 10 && message.message == 0x000F
	})

	erase, ok := queue.take(cpu, nil)
	if !ok || erase.message != 0x0014 {
		t.Fatalf("first message = %#x, want WM_ERASEBKGND", erase.message)
	}
	paint, ok := queue.take(cpu, nil)
	if !ok || paint.message != 0x000F {
		t.Fatalf("second message = %#x, want WM_PAINT", paint.message)
	}
}
