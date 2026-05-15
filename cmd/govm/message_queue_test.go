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

func TestSynchronousSendWaitsForOwnerCompletion(t *testing.T) {
	owner := x64.New(mmu.New())
	var queue messageQueue
	request := newSynchronousSendRequest(0x50001, 0x8123, 0x4567, 0x89ab)
	if !queue.enqueueSynchronous(owner, request) {
		t.Fatal("synchronous send was not queued")
	}

	result := make(chan uint64, 1)
	go func() {
		result <- request.wait()
	}()
	select {
	case value := <-result:
		t.Fatalf("sender returned before owner dispatch with %#x", value)
	case <-time.After(20 * time.Millisecond):
	}

	delivered, ok := queue.takeSynchronous(owner)
	if !ok || delivered != request {
		t.Fatalf("owner received request %p, %v; want %p", delivered, ok, request)
	}
	if delivered.hwnd != 0x50001 || delivered.message != 0x8123 ||
		delivered.wParam != 0x4567 || delivered.lParam != 0x89ab {
		t.Fatalf("owner received corrupted request: %+v", delivered)
	}
	delivered.complete(0x13579bdf)

	select {
	case value := <-result:
		if value != 0x13579bdf {
			t.Fatalf("sender result = %#x, want 0x13579bdf", value)
		}
	case <-time.After(time.Second):
		t.Fatal("sender did not resume after owner completion")
	}
}

func TestSynchronousSendIsInternalAndOwnerScoped(t *testing.T) {
	owner := x64.New(mmu.New())
	other := x64.New(mmu.New())
	var queue messageQueue
	request := newSynchronousSendRequest(0x50001, 0x8123, 1, 2)
	queue.enqueueSynchronous(owner, request)

	if queue.count(owner) != 0 || queue.contains(nil) {
		t.Fatal("synchronous request was exposed as a posted message")
	}
	if _, ok := queue.takeSynchronous(other); ok {
		t.Fatal("non-owner CPU received synchronous request")
	}
	if delivered, ok := queue.takeSynchronous(owner); !ok || delivered != request {
		t.Fatalf("owner received request %p, %v; want %p", delivered, ok, request)
	}
}

func TestMessageQueueWakeMasksAndInputAvailable(t *testing.T) {
	cpu := x64.New(mmu.New())
	var queue messageQueue
	queue.enqueue(cpu, queuedMsg{message: 0x0100})

	if !queue.hasWakeMask(cpu, qsKey, false) {
		t.Fatal("new key input did not set QS_KEY")
	}
	if queue.hasWakeMask(cpu, qsTimer, true) {
		t.Fatal("key input matched QS_TIMER")
	}
	queue.markWakeMaskSeen(cpu, qsKey)
	if queue.hasWakeMask(cpu, qsKey, false) {
		t.Fatal("seen key input remained new")
	}
	if !queue.hasWakeMask(cpu, qsKey, true) {
		t.Fatal("MWMO_INPUTAVAILABLE did not expose queued key input")
	}
	if _, ok := queue.take(cpu, nil); !ok {
		t.Fatal("queued key input was not delivered")
	}
	if queue.hasWakeMask(cpu, qsKey, true) {
		t.Fatal("removed key input remained available")
	}
}

func TestMessageQueueFilteredWaitIgnoresExistingOtherCategory(t *testing.T) {
	cpu := x64.New(mmu.New())
	var queue messageQueue
	queue.enqueue(cpu, queuedMsg{message: 0x0100})

	started := time.Now()
	if queue.waitWakeMask(cpu, qsTimer, false, 20*time.Millisecond) {
		t.Fatal("QS_TIMER wait woke for queued key input")
	}
	if elapsed := time.Since(started); elapsed < 10*time.Millisecond {
		t.Fatalf("filtered wait returned too early after %s", elapsed)
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		queue.enqueue(cpu, queuedMsg{message: 0x0113})
	}()
	if !queue.waitWakeMask(cpu, qsTimer, false, time.Second) {
		t.Fatal("QS_TIMER wait did not wake for timer input")
	}
}

func TestMessageQueueSynchronousWakeMaskClearsOnTake(t *testing.T) {
	cpu := x64.New(mmu.New())
	var queue messageQueue
	request := newSynchronousSendRequest(0x50001, 0x8123, 0, 0)
	queue.enqueueSynchronous(cpu, request)

	if !queue.hasWakeMask(cpu, qsSendMessage, false) {
		t.Fatal("synchronous request did not set QS_SENDMESSAGE")
	}
	if delivered, ok := queue.takeSynchronous(cpu); !ok || delivered != request {
		t.Fatalf("synchronous request = %p, %v; want %p", delivered, ok, request)
	}
	if queue.hasWakeMask(cpu, qsSendMessage, true) {
		t.Fatal("delivered synchronous request remained available")
	}
}

func TestSynchronousSendUnblocksWhenOwnerExits(t *testing.T) {
	owner := x64.New(mmu.New())
	var queue messageQueue
	request := newSynchronousSendRequest(0x50001, 0x8123, 0, 0)
	queue.enqueueSynchronous(owner, request)

	result := make(chan uint64, 1)
	go func() {
		result <- request.wait()
	}()
	queue.removeCPU(owner)

	select {
	case value := <-result:
		if value != 0 {
			t.Fatalf("cancelled send result = %#x, want 0", value)
		}
	case <-time.After(time.Second):
		t.Fatal("owner exit left sender blocked")
	}
}

func TestSynchronousSendIsRemovedWhenSenderExits(t *testing.T) {
	owner := x64.New(mmu.New())
	sender := x64.New(mmu.New())
	var queue messageQueue
	request := newSynchronousSendRequest(0x50001, 0x8123, 0, 0)
	request.sender = sender
	queue.enqueueSynchronous(owner, request)

	queue.cancelSynchronousSender(sender)

	if delivered, ok := queue.takeSynchronous(owner); ok || delivered != nil {
		t.Fatalf("owner received cancelled request %p, %v", delivered, ok)
	}
	if result := request.wait(); result != 0 {
		t.Fatalf("cancelled send result = %#x, want 0", result)
	}
}

func TestSynchronousSendReplyCompletesOnlyOnce(t *testing.T) {
	request := newSynchronousSendRequest(0x50001, 0x8123, 0, 0)
	request.reply(0x1357)
	request.complete(0x2468)
	if !request.replied.Load() {
		t.Fatal("ReplyMessage state was not recorded")
	}
	if result := request.wait(); result != 0x1357 {
		t.Fatalf("reply result = %#x, want 0x1357", result)
	}
}

func TestSynchronousSendTimedWait(t *testing.T) {
	request := newSynchronousSendRequest(0x50001, 0x8123, 0, 0)
	if result, ready := request.waitTimeout(0); ready || result != 0 {
		t.Fatalf("pending wait = %#x, %v; want zero, false", result, ready)
	}
	request.complete(0x2468)
	if result, ready := request.waitTimeout(time.Second); !ready || result != 0x2468 {
		t.Fatalf("completed wait = %#x, %v; want 0x2468, true", result, ready)
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
