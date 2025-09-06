package vfs

import (
	"encoding/binary"
	"fmt"
	"sync"
)

// eventfd flags
const (
	EFD_CLOEXEC  = 0x80000
	EFD_NONBLOCK = 0x800
	EFD_SEMAPHORE = 0x1
)

// EventFD implements a Linux-compatible eventfd counter.
type EventFD struct {
	mu       sync.Mutex
	counter  uint64
	flags    int
	closed   bool
}

// NewEventFD creates a new eventfd with the given initial value and flags.
func NewEventFD(initval uint64, flags int) *EventFD {
	return &EventFD{
		counter: initval,
		flags:   flags,
	}
}

// Read reads the 8-byte counter value. In non-semaphore mode, reads the
// counter and resets it to 0. In semaphore mode, decrements by 1.
// Returns 0, nil (would-block) if counter is 0 and EFD_NONBLOCK is set.
func (e *EventFD) Read(buf []byte) (int, error) {
	if len(buf) < 8 {
		return -1, fmt.Errorf("EINVAL")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.counter == 0 {
		// Non-blocking: return EAGAIN (0 bytes)
		return 0, nil
	}

	var val uint64
	if e.flags&EFD_SEMAPHORE != 0 {
		val = 1
		e.counter--
	} else {
		val = e.counter
		e.counter = 0
	}
	binary.LittleEndian.PutUint64(buf[:8], val)
	return 8, nil
}

// Write adds a uint64 value to the counter.
func (e *EventFD) Write(data []byte) (int, error) {
	if len(data) < 8 {
		return -1, fmt.Errorf("EINVAL")
	}
	val := binary.LittleEndian.Uint64(data[:8])
	if val == 0xFFFFFFFFFFFFFFFF {
		return -1, fmt.Errorf("EINVAL")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Overflow check
	if e.counter > 0xFFFFFFFFFFFFFFFE-val {
		return 0, nil // would block
	}
	e.counter += val
	return 8, nil
}

// Close marks the eventfd as closed.
func (e *EventFD) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
}

// Ready returns true if the eventfd has a non-zero counter (readable).
func (e *EventFD) Ready() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.counter > 0
}

// AllocEventFD creates an eventfd and returns a guest FD for it.
func (v *VFS) AllocEventFD(initval uint64, flags int) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	efd := NewEventFD(initval, flags)
	node := newVNode("eventfd", false)
	node.FileMode = S_IFREG | 0600
	fd := v.nextFD
	v.nextFD++
	v.fds[fd] = &FD{Node: node, EventFD: efd}
	return fd
}

// GetEventFD returns the EventFD for a guest FD, or nil.
func (v *VFS) GetEventFD(fd int) *EventFD {
	v.mu.Lock()
	defer v.mu.Unlock()
	f, ok := v.fds[fd]
	if !ok {
		return nil
	}
	return f.EventFD
}
