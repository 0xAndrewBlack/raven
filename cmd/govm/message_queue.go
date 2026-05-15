//go:build guest_windows

package main

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/mirkobrombin/Raven/pkg/arch"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

type messageQueue struct {
	mu      sync.Mutex
	items   []queuedMsg
	wakeup  map[arch.CPU]chan struct{}
	changes map[arch.CPU]uint32
}

const (
	qsKey            = uint32(0x0001)
	qsMouseMove      = uint32(0x0002)
	qsMouseButton    = uint32(0x0004)
	qsPostMessage    = uint32(0x0008)
	qsTimer          = uint32(0x0010)
	qsPaint          = uint32(0x0020)
	qsSendMessage    = uint32(0x0040)
	qsHotkey         = uint32(0x0080)
	qsAllPostMessage = uint32(0x0100)
	qsRawInput       = uint32(0x0400)
	qsTouch          = uint32(0x0800)
	qsPointer        = uint32(0x1000)
)

func queuedMessageWakeMask(msg queuedMsg) uint32 {
	if msg.sent != nil {
		return qsSendMessage
	}
	switch {
	case msg.message == 0x000F:
		return qsPaint
	case msg.message == 0x00FF:
		return qsRawInput
	case msg.message >= 0x0100 && msg.message <= 0x0109:
		return qsKey
	case msg.message == 0x0113:
		return qsTimer
	case msg.message == 0x0200:
		return qsMouseMove
	case msg.message >= 0x0201 && msg.message <= 0x020D:
		return qsMouseButton
	case msg.message == 0x0312:
		return qsHotkey
	case msg.message >= 0x0240 && msg.message <= 0x024F:
		return qsTouch | qsPointer
	default:
		return qsPostMessage | qsAllPostMessage
	}
}

type synchronousSendResult struct {
	lResult uint64
}

type synchronousSendRequest struct {
	hwnd    uint64
	message uint32
	wParam  uint64
	lParam  uint64
	sender  arch.CPU
	done    chan synchronousSendResult
	once    sync.Once
	replied atomic.Bool
}

func newSynchronousSendRequest(hwnd uint64, message uint32, wParam, lParam uint64) *synchronousSendRequest {
	return &synchronousSendRequest{
		hwnd:    hwnd,
		message: message,
		wParam:  wParam,
		lParam:  lParam,
		done:    make(chan synchronousSendResult, 1),
	}
}

func (request *synchronousSendRequest) complete(lResult uint64) {
	if request == nil {
		return
	}
	request.once.Do(func() {
		request.done <- synchronousSendResult{lResult: lResult}
		close(request.done)
	})
}

func (request *synchronousSendRequest) reply(lResult uint64) {
	if request == nil {
		return
	}
	request.replied.Store(true)
	request.complete(lResult)
}

func (request *synchronousSendRequest) wait() uint64 {
	if request == nil {
		return 0
	}
	result, ok := <-request.done
	if !ok {
		return 0
	}
	return result.lResult
}

func (request *synchronousSendRequest) waitTimeout(timeout time.Duration) (uint64, bool) {
	if request == nil {
		return 0, true
	}
	if timeout <= 0 {
		select {
		case result, ok := <-request.done:
			if !ok {
				return 0, true
			}
			return result.lResult, true
		default:
			return 0, false
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result, ok := <-request.done:
		if !ok {
			return 0, true
		}
		return result.lResult, true
	case <-timer.C:
		return 0, false
	}
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
	if q.changes == nil {
		q.changes = make(map[arch.CPU]uint32)
	}
	wakeup := q.wakeup[cpu]
	if wakeup == nil {
		wakeup = make(chan struct{}, 1)
		q.wakeup[cpu] = wakeup
	}
	for i := range messages {
		messages[i].cpu = cpu
		q.items = append(q.items, messages[i])
		q.changes[cpu] |= queuedMessageWakeMask(messages[i])
	}
	select {
	case wakeup <- struct{}{}:
	default:
	}
	q.mu.Unlock()
}

func (q *messageQueue) enqueueSynchronous(cpu arch.CPU, request *synchronousSendRequest) bool {
	if cpu == nil || request == nil {
		return false
	}
	q.enqueue(cpu, queuedMsg{
		hwnd:    request.hwnd,
		message: request.message,
		wParam:  request.wParam,
		lParam:  request.lParam,
		sent:    request,
	})
	return true
}

func (q *messageQueue) enqueueBefore(cpu arch.CPU, message queuedMsg, before func(queuedMsg) bool) {
	if cpu == nil {
		return
	}
	q.mu.Lock()
	if q.wakeup == nil {
		q.wakeup = make(map[arch.CPU]chan struct{})
	}
	if q.changes == nil {
		q.changes = make(map[arch.CPU]uint32)
	}
	wakeup := q.wakeup[cpu]
	if wakeup == nil {
		wakeup = make(chan struct{}, 1)
		q.wakeup[cpu] = wakeup
	}
	message.cpu = cpu
	index := len(q.items)
	for i, queued := range q.items {
		if messageOwnedBy(queued, cpu) && before != nil && before(queued) {
			index = i
			break
		}
	}
	q.items = append(q.items, queuedMsg{})
	copy(q.items[index+1:], q.items[index:])
	q.items[index] = message
	q.changes[cpu] |= queuedMessageWakeMask(message)
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
		if messageOwnedBy(msg, cpu) && msg.sent == nil {
			count++
		}
	}
	return count
}

func (q *messageQueue) hasWakeMask(cpu arch.CPU, mask uint32, inputAvailable bool) bool {
	if cpu == nil || mask == 0 {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.hasWakeMaskLocked(cpu, mask, inputAvailable)
}

func (q *messageQueue) hasWakeMaskLocked(cpu arch.CPU, mask uint32, inputAvailable bool) bool {
	available := uint32(0)
	for _, msg := range q.items {
		if messageOwnedBy(msg, cpu) {
			available |= queuedMessageWakeMask(msg)
		}
	}
	available &= mask
	if inputAvailable {
		return available != 0
	}
	return available&q.changes[cpu] != 0
}

func (q *messageQueue) waitWakeMask(
	cpu arch.CPU, mask uint32, inputAvailable bool, timeout time.Duration,
) bool {
	if cpu == nil || mask == 0 {
		if timeout > 0 {
			time.Sleep(timeout)
		}
		return false
	}
	q.mu.Lock()
	if q.hasWakeMaskLocked(cpu, mask, inputAvailable) {
		q.mu.Unlock()
		return true
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

func (q *messageQueue) markWakeMaskSeen(cpu arch.CPU, mask uint32) {
	if cpu == nil || mask == 0 {
		return
	}
	q.mu.Lock()
	q.changes[cpu] &^= mask
	if q.changes[cpu] == 0 {
		delete(q.changes, cpu)
	}
	q.mu.Unlock()
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
		if msg.sent != nil {
			continue
		}
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
		if msg.sent != nil || !messageOwnedBy(msg, cpu) || keep == nil || keep(msg) {
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
	var cancelled []*synchronousSendRequest
	for _, msg := range q.items {
		if !messageOwnedBy(msg, cpu) {
			kept = append(kept, msg)
		} else if msg.sent != nil {
			cancelled = append(cancelled, msg.sent)
		}
	}
	q.items = kept
	delete(q.wakeup, cpu)
	delete(q.changes, cpu)
	q.mu.Unlock()
	for _, request := range cancelled {
		request.complete(0)
	}
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
		if msg.sent != nil || !messageOwnedBy(msg, cpu) || match != nil && !match(msg) {
			continue
		}
		if write == nil || !write(msg) {
			return queuedMsg{}, false
		}
		q.changes[cpu] &^= queuedMessageWakeMask(msg)
		if q.changes[cpu] == 0 {
			delete(q.changes, cpu)
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

func (q *messageQueue) takeSynchronous(cpu arch.CPU) (*synchronousSendRequest, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for index, msg := range q.items {
		if msg.sent == nil || !messageOwnedBy(msg, cpu) {
			continue
		}
		q.items = append(q.items[:index], q.items[index+1:]...)
		q.changes[cpu] &^= qsSendMessage
		for _, remaining := range q.items {
			if messageOwnedBy(remaining, cpu) && remaining.sent != nil {
				q.changes[cpu] |= qsSendMessage
				break
			}
		}
		if q.changes[cpu] == 0 {
			delete(q.changes, cpu)
		}
		return msg.sent, true
	}
	return nil, false
}

func (q *messageQueue) cancelSynchronousSender(cpu arch.CPU) {
	if cpu == nil {
		return
	}
	q.mu.Lock()
	kept := q.items[:0]
	var cancelled []*synchronousSendRequest
	for _, msg := range q.items {
		if msg.sent == nil || msg.sent.sender != cpu {
			kept = append(kept, msg)
			continue
		}
		cancelled = append(cancelled, msg.sent)
	}
	q.items = kept
	q.mu.Unlock()
	for _, request := range cancelled {
		request.complete(0)
	}
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
	if h.CancelSentMessages != nil {
		h.CancelSentMessages(cpu)
	}
	h.Timers.removeCPU(cpu)
	h.MessageMetadata.removeCPU(cpu)
	h.clearWindowsForCPU(cpu)
	if h.TMPtr != nil && *h.TMPtr != nil {
		ntapi.ObjMgr.DiscardAPCs(uint64((*h.TMPtr).GetTID(cpu)))
	}
	if h.ProcState == nil || h.Mem == nil || cpu == nil {
		return
	}
	teb := cpu.GetTLS()
	if !h.ProcState.Is32 {
		if gsCPU, ok := cpu.(interface{ GetGSBase() uint64 }); ok {
			teb = gsCPU.GetGSBase()
		}
	}
	crtReleaseThreadRuntime(h.Mem, h.ProcState, teb)
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

func (h *HandlerCtx) enqueueMessageBeforePaint(cpu arch.CPU, message queuedMsg) {
	owner := h.windowCPU(message.hwnd)
	if owner == nil {
		owner = cpu
	}
	if owner == nil {
		owner = h.defaultMessageCPU()
	}
	if owner == nil {
		return
	}
	h.MsgQueue.enqueueBefore(owner, message, func(queued queuedMsg) bool {
		return queued.hwnd == message.hwnd && queued.message == 0x000F
	})
}

func (h *HandlerCtx) queueCount(cpu arch.CPU) int {
	return h.MsgQueue.count(cpu)
}
