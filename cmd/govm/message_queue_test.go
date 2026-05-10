//go:build guest_windows

package main

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestMessageQueueIsolatesGuestCPUs(t *testing.T) {
	first := x64.New(mmu.New())
	second := x64.New(mmu.New())
	var queue messageQueue

	queue.enqueue(first, queuedMsg{message: 1}, queuedMsg{message: 2})
	queue.enqueue(second, queuedMsg{message: 3})

	if got := queue.count(first); got != 2 {
		t.Fatalf("first CPU count = %d, want 2", got)
	}
	if got := queue.count(second); got != 1 {
		t.Fatalf("second CPU count = %d, want 1", got)
	}
	message, ok := queue.take(second, nil)
	if !ok || message.message != 3 {
		t.Fatalf("second CPU message = %+v, %v", message, ok)
	}
	message, ok = queue.take(first, nil)
	if !ok || message.message != 1 {
		t.Fatalf("first CPU first message = %+v, %v", message, ok)
	}
	message, ok = queue.take(first, nil)
	if !ok || message.message != 2 {
		t.Fatalf("first CPU second message = %+v, %v", message, ok)
	}
}

func TestMessageQueueRejectsOwnerlessMessages(t *testing.T) {
	var queue messageQueue
	queue.enqueue(nil, queuedMsg{message: 1})
	if queue.contains(nil) {
		t.Fatal("ownerless message entered the queue")
	}
}

func TestHandlerCtxRoutesWindowAndThreadMessages(t *testing.T) {
	first := x64.New(mmu.New())
	second := x64.New(mmu.New())
	hctx := &HandlerCtx{MainHWND: 0x50000}
	hctx.setWindowCPU(hctx.MainHWND, first)
	hctx.setWindowCPU(0x50001, second)

	hctx.enqueueMessage(first, queuedMsg{hwnd: 0x50001, message: 1})
	hctx.enqueueMessage(first, queuedMsg{message: 2})

	windowMessage, ok := hctx.MsgQueue.take(second, nil)
	if !ok || windowMessage.hwnd != 0x50001 {
		t.Fatalf("window message = %+v, %v", windowMessage, ok)
	}
	threadMessage, ok := hctx.MsgQueue.take(first, nil)
	if !ok || threadMessage.hwnd != 0 || threadMessage.message != 2 {
		t.Fatalf("thread message = %+v, %v", threadMessage, ok)
	}
}

func TestMessageQueueConcurrentProducersAndConsumer(t *testing.T) {
	cpu := x64.New(mmu.New())
	var queue messageQueue
	const producers = 8
	const perProducer = 250
	const total = producers * perProducer

	var producersDone sync.WaitGroup
	producersDone.Add(producers)
	for producer := 0; producer < producers; producer++ {
		go func(producer int) {
			defer producersDone.Done()
			for sequence := 0; sequence < perProducer; sequence++ {
				value := uint64(producer*perProducer + sequence)
				queue.enqueue(cpu, queuedMsg{message: 1, wParam: value})
			}
		}(producer)
	}

	seen := make(map[uint64]bool, total)
	deadline := time.After(5 * time.Second)
	for len(seen) < total {
		select {
		case <-deadline:
			t.Fatalf("timed out after receiving %d of %d messages", len(seen), total)
		default:
			if message, ok := queue.take(cpu, nil); ok {
				if seen[message.wParam] {
					t.Fatalf("duplicate message %d", message.wParam)
				}
				seen[message.wParam] = true
				continue
			}
			runtime.Gosched()
		}
	}
	producersDone.Wait()
	if got := queue.count(cpu); got != 0 {
		t.Fatalf("remaining messages = %d", got)
	}
}

func TestMessageQueueWakeIsScopedToGuestCPU(t *testing.T) {
	first := x64.New(mmu.New())
	second := x64.New(mmu.New())
	var queue messageQueue
	woke := make(chan bool, 1)
	go func() {
		woke <- queue.wait(second, time.Second)
	}()

	time.Sleep(10 * time.Millisecond)
	queue.enqueue(first, queuedMsg{message: 1})
	select {
	case <-woke:
		t.Fatal("first CPU message woke the second CPU")
	case <-time.After(20 * time.Millisecond):
	}
	queue.enqueue(second, queuedMsg{message: 2})
	select {
	case ready := <-woke:
		if !ready {
			t.Fatal("second CPU wake timed out")
		}
	case <-time.After(time.Second):
		t.Fatal("second CPU message did not wake its waiter")
	}
}

func TestTimerStoreSeparatesGuestCPUs(t *testing.T) {
	first := x64.New(mmu.New())
	second := x64.New(mmu.New())
	now := time.Now()
	var timers timerStore
	timers.set(&win32Timer{id: 7, hwnd: 0x50001, cpu: first, intervalMs: 10, deadline: now.Add(-time.Millisecond)})
	timers.set(&win32Timer{id: 7, hwnd: 0x50001, cpu: second, intervalMs: 10, deadline: now.Add(-time.Millisecond)})

	expired := timers.expire(first, now)
	if len(expired) != 1 || expired[0].cpu != first {
		t.Fatalf("first CPU expired timers = %+v", expired)
	}
	if !timers.kill(second, 0x50001, 7) {
		t.Fatal("second CPU timer was not found")
	}
	if !timers.has(first, 0x50001, 7) {
		t.Fatal("killing the second CPU timer removed the first CPU timer")
	}
}

func TestMessageQueueZeroTimeoutDoesNotBlock(t *testing.T) {
	cpu := x64.New(mmu.New())
	var queue messageQueue
	done := make(chan bool, 1)
	go func() {
		done <- queue.wait(cpu, 0)
	}()

	select {
	case ready := <-done:
		if ready {
			t.Fatal("empty queue reported a message")
		}
	case <-time.After(time.Second):
		t.Fatal("zero timeout blocked")
	}
}

func TestHandlerCtxCleansExitedGuestCPUState(t *testing.T) {
	first := x64.New(mmu.New())
	second := x64.New(mmu.New())
	hctx := &HandlerCtx{}
	hctx.MsgQueue.enqueue(first, queuedMsg{message: 1})
	hctx.MsgQueue.enqueue(second, queuedMsg{message: 2})
	hctx.Timers.set(&win32Timer{id: 1, cpu: first})
	hctx.Timers.set(&win32Timer{id: 2, cpu: second})
	hctx.MessageMetadata.delivered(first, queuedMsg{time: 1})
	hctx.MessageMetadata.delivered(second, queuedMsg{time: 2})
	hctx.setWindowCPU(0x50001, first)
	hctx.setWindowCPU(0x50002, second)

	hctx.cleanupMessageCPU(first)

	if hctx.MsgQueue.count(first) != 0 || hctx.Timers.has(first, 0, 1) || hctx.MessageMetadata.get(first).messageTime != 0 {
		t.Fatal("exited CPU state was not removed")
	}
	if hctx.MsgQueue.count(second) != 1 || !hctx.Timers.has(second, 0, 2) || hctx.MessageMetadata.get(second).messageTime != 2 {
		t.Fatal("live CPU state was modified")
	}
	if hctx.windowCPU(0x50001) != nil {
		t.Fatal("exited CPU window ownership was not removed")
	}
	if hctx.windowCPU(0x50002) != second {
		t.Fatal("live CPU window ownership was modified")
	}
}
