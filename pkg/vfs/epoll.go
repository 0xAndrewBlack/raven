package vfs

import (
	"sync"
	"syscall"
)

// Epoll event flags matching Linux
const (
	EPOLLIN      = 0x001
	EPOLLOUT     = 0x004
	EPOLLERR     = 0x008
	EPOLLHUP     = 0x010
	EPOLLRDHUP   = 0x2000
	EPOLLET      = 1 << 31
	EPOLLONESHOT = 1 << 30
)

// Epoll operations
const (
	EPOLL_CTL_ADD = 1
	EPOLL_CTL_DEL = 2
	EPOLL_CTL_MOD = 3
)

// EpollEntry tracks a monitored FD and its events.
type EpollEntry struct {
	GuestFD int
	Events  uint32
	Data    uint64 // epoll_data (user data, typically the fd)
}

// EpollInstance represents an epoll file descriptor.
type EpollInstance struct {
	mu      sync.Mutex
	entries map[int]*EpollEntry // keyed by guest FD
}

// NewEpollInstance creates a new epoll instance.
func NewEpollInstance() *EpollInstance {
	return &EpollInstance{
		entries: make(map[int]*EpollEntry),
	}
}

// Ctl adds, modifies, or deletes an entry.
func (ep *EpollInstance) Ctl(op int, fd int, events uint32, data uint64) error {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	switch op {
	case EPOLL_CTL_ADD:
		ep.entries[fd] = &EpollEntry{GuestFD: fd, Events: events, Data: data}
	case EPOLL_CTL_MOD:
		e, ok := ep.entries[fd]
		if !ok {
			return syscall.ENOENT
		}
		e.Events = events
		e.Data = data
	case EPOLL_CTL_DEL:
		delete(ep.entries, fd)
	}
	return nil
}

// Entries returns a snapshot of all monitored entries.
func (ep *EpollInstance) Entries() []*EpollEntry {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	result := make([]*EpollEntry, 0, len(ep.entries))
	for _, e := range ep.entries {
		result = append(result, e)
	}
	return result
}

// AllocEpoll creates an epoll instance and returns a guest FD for it.
func (v *VFS) AllocEpoll() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	ep := NewEpollInstance()
	node := newVNode("epoll", false)
	node.FileMode = S_IFREG | 0600
	fd := v.nextFD
	v.nextFD++
	v.fds[fd] = &FD{Node: node, Epoll: ep}
	return fd
}

// GetEpoll returns the EpollInstance for a guest FD, or nil.
func (v *VFS) GetEpoll(fd int) *EpollInstance {
	v.mu.Lock()
	defer v.mu.Unlock()
	f, ok := v.fds[fd]
	if !ok {
		return nil
	}
	return f.Epoll
}
