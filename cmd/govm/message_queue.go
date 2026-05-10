//go:build guest_windows

package main

import (
	"sync"
	"time"

	"github.com/mirkobrombin/Raven/pkg/arch"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
)

type messageQueue struct {
	mu     sync.Mutex
	items  []queuedMsg
	wakeup map[arch.CPU]chan struct{}
}

type messageThreadMetadata struct {
	messageTime uint32
	x           int32
	y           int32
	extraInfo   uint64
}

type messageMetadataStore struct {
	mu      sync.Mutex
	threads map[arch.CPU]messageThreadMetadata
}

func (s *messageMetadataStore) delivered(cpu arch.CPU, msg queuedMsg) {
	if cpu == nil {
		return
	}
	s.mu.Lock()
	if s.threads == nil {
		s.threads = make(map[arch.CPU]messageThreadMetadata)
	}
	s.threads[cpu] = messageThreadMetadata{
		messageTime: msg.time,
		x:           msg.x,
		y:           msg.y,
		extraInfo:   msg.extraInfo,
	}
	s.mu.Unlock()
}

func (s *messageMetadataStore) get(cpu arch.CPU) messageThreadMetadata {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.threads[cpu]
}

func (s *messageMetadataStore) setExtraInfo(cpu arch.CPU, extraInfo uint64) uint64 {
	if cpu == nil {
		return 0
	}
	s.mu.Lock()
	if s.threads == nil {
		s.threads = make(map[arch.CPU]messageThreadMetadata)
	}
	state := s.threads[cpu]
	previous := state.extraInfo
	state.extraInfo = extraInfo
	s.threads[cpu] = state
	s.mu.Unlock()
	return previous
}

func messageOwnedBy(msg queuedMsg, cpu arch.CPU) bool {
	return msg.cpu != nil && msg.cpu == cpu
}

func (q *messageQueue) enqueue(cpu arch.CPU, messages ...queuedMsg) {
	if cpu == nil || len(messages) == 0 {
		return
	}
	q.mu.Lock()
	if q.wakeup == nil {
		q.wakeup = make(map[arch.CPU]chan struct{})
	}
	wakeup := q.wakeup[cpu]
	if wakeup == nil {
		wakeup = make(chan struct{}, 1)
		q.wakeup[cpu] = wakeup
	}
	for i := range messages {
		messages[i].cpu = cpu
		q.items = append(q.items, messages[i])
	}
	select {
	case wakeup <- struct{}{}:
	default:
	}
	q.mu.Unlock()
}

func (q *messageQueue) count(cpu arch.CPU) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	count := 0
	for _, msg := range q.items {
		if messageOwnedBy(msg, cpu) {
			count++
		}
	}
	return count
}

func (q *messageQueue) wait(cpu arch.CPU, timeout time.Duration) bool {
	q.mu.Lock()
	for _, msg := range q.items {
		if messageOwnedBy(msg, cpu) {
			q.mu.Unlock()
			return true
		}
	}
	if q.wakeup == nil {
		q.wakeup = make(map[arch.CPU]chan struct{})
	}
	wakeup := q.wakeup[cpu]
	if wakeup == nil {
		wakeup = make(chan struct{}, 1)
		q.wakeup[cpu] = wakeup
	}
	select {
	case <-wakeup:
	default:
	}
	q.mu.Unlock()

	if timeout < 0 {
		<-wakeup
		return true
	}
	if timeout == 0 {
		return false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-wakeup:
		return true
	case <-timer.C:
		return false
	}
}

func (q *messageQueue) contains(match func(queuedMsg) bool) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, msg := range q.items {
		if match == nil || match(msg) {
			return true
		}
	}
	return false
}

func (q *messageQueue) prune(cpu arch.CPU, keep func(queuedMsg) bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	kept := q.items[:0]
	for _, msg := range q.items {
		if !messageOwnedBy(msg, cpu) || keep == nil || keep(msg) {
			kept = append(kept, msg)
		}
	}
	q.items = kept
}

func (q *messageQueue) removeCPU(cpu arch.CPU) {
	if cpu == nil {
		return
	}
	q.mu.Lock()
	kept := q.items[:0]
	for _, msg := range q.items {
		if !messageOwnedBy(msg, cpu) {
			kept = append(kept, msg)
		}
	}
	q.items = kept
	delete(q.wakeup, cpu)
	q.mu.Unlock()
}

func (q *messageQueue) deliver(
	cpu arch.CPU,
	match func(queuedMsg) bool,
	remove func(queuedMsg) bool,
	write func(queuedMsg) bool,
) (queuedMsg, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for index, msg := range q.items {
		if !messageOwnedBy(msg, cpu) || match != nil && !match(msg) {
			continue
		}
		if write == nil || !write(msg) {
			return queuedMsg{}, false
		}
		shouldRemove := remove != nil && remove(msg)
		if traceEnqueue {
			ravelog.Logf("[msg-trace] deliver hwnd=0x%x msg=0x%x owner=%p consumer=%p remove=%t\n",
				msg.hwnd, msg.message, msg.cpu, cpu, shouldRemove)
		}
		if shouldRemove {
			q.items = append(q.items[:index], q.items[index+1:]...)
		}
		return msg, true
	}
	return queuedMsg{}, false
}

func (q *messageQueue) take(cpu arch.CPU, match func(queuedMsg) bool) (queuedMsg, bool) {
	return q.deliver(cpu, match, func(queuedMsg) bool { return true }, func(queuedMsg) bool { return true })
}

type timerKey struct {
	cpu  arch.CPU
	hwnd uint64
	id   uint64
}

type timerStore struct {
	mu     sync.Mutex
	timers map[timerKey]*win32Timer
	nextID uint64
}

func (s *timerStore) allocateID() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextID < 1000 {
		s.nextID = 1000
	}
	s.nextID++
	return s.nextID
}

func (s *timerStore) set(timer *win32Timer) {
	if timer == nil {
		return
	}
	s.mu.Lock()
	if s.timers == nil {
		s.timers = make(map[timerKey]*win32Timer)
	}
	s.timers[timerKey{cpu: timer.cpu, hwnd: timer.hwnd, id: timer.id}] = timer
	s.mu.Unlock()
}

func (s *timerStore) has(cpu arch.CPU, hwnd, id uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.timers[timerKey{cpu: cpu, hwnd: hwnd, id: id}]
	return ok
}

func (s *timerStore) kill(cpu arch.CPU, hwnd, id uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := timerKey{cpu: cpu, hwnd: hwnd, id: id}
	if _, ok := s.timers[key]; !ok {
		return false
	}
	delete(s.timers, key)
	return true
}

func (s *timerStore) expire(cpu arch.CPU, now time.Time) []win32Timer {
	s.mu.Lock()
	defer s.mu.Unlock()
	var expired []win32Timer
	for key, timer := range s.timers {
		if key.cpu != cpu || now.Before(timer.deadline) {
			continue
		}
		timer.deadline = now.Add(time.Duration(timer.intervalMs) * time.Millisecond)
		expired = append(expired, *timer)
	}
	return expired
}

func (s *timerStore) nextDelay(cpu arch.CPU, now time.Time, maximum time.Duration) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	delay := maximum
	for key, timer := range s.timers {
		if key.cpu != cpu {
			continue
		}
		until := timer.deadline.Sub(now)
		if until < 0 {
			until = 0
		}
		if until < delay {
			delay = until
		}
	}
	return delay
}

func (s *timerStore) removeCPU(cpu arch.CPU) {
	if cpu == nil {
		return
	}
	s.mu.Lock()
	for key := range s.timers {
		if key.cpu == cpu {
			delete(s.timers, key)
		}
	}
	s.mu.Unlock()
}

func (s *messageMetadataStore) removeCPU(cpu arch.CPU) {
	if cpu == nil {
		return
	}
	s.mu.Lock()
	delete(s.threads, cpu)
	s.mu.Unlock()
}

func (h *HandlerCtx) cleanupMessageCPU(cpu arch.CPU) {
	h.MsgQueue.removeCPU(cpu)
	h.Timers.removeCPU(cpu)
	h.MessageMetadata.removeCPU(cpu)
	h.clearWindowsForCPU(cpu)
}

func (h *HandlerCtx) defaultMessageCPU() arch.CPU {
	if cpu := h.windowCPU(h.MainHWND); cpu != nil {
		return cpu
	}
	if h.TMPtr != nil && *h.TMPtr != nil {
		if cpu, ok := (*h.TMPtr).GetCPU(1); ok {
			return cpu
		}
	}
	return nil
}

func (h *HandlerCtx) enqueueMessage(cpu arch.CPU, messages ...queuedMsg) {
	for i := range messages {
		owner := h.windowCPU(messages[i].hwnd)
		if owner == nil {
			owner = cpu
		}
		if owner == nil {
			owner = h.defaultMessageCPU()
		}
		if owner == nil {
			continue
		}
		if traceEnqueue {
			ravelog.Logf("[msg-trace] route hwnd=0x%x msg=0x%x source=%p owner=%p\n",
				messages[i].hwnd, messages[i].message, cpu, owner)
		}
		h.MsgQueue.enqueue(owner, messages[i])
	}
}

func (h *HandlerCtx) queueCount(cpu arch.CPU) int {
	return h.MsgQueue.count(cpu)
}
