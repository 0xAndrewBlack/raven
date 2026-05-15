//go:build guest_windows

package ntapi

import (
	"sync"

	"github.com/mirkobrombin/Raven/pkg/vfs"
)

type fileRangeLock struct {
	owner     uint64
	start     uint64
	length    uint64
	key       uint32
	exclusive bool
}

type fileLockState struct {
	mu    sync.Mutex
	cond  *sync.Cond
	locks []fileRangeLock
}

func newFileLockState() *fileLockState {
	state := &fileLockState{}
	state.cond = sync.NewCond(&state.mu)
	return state
}

type FileLockManager struct {
	mu           sync.Mutex
	states       map[vfs.FileIdentity]*fileLockState
	closedOwners map[uint64]bool
}

func NewFileLockManager() *FileLockManager {
	return &FileLockManager{
		states:       make(map[vfs.FileIdentity]*fileLockState),
		closedOwners: make(map[uint64]bool),
	}
}

var fileLockManagers sync.Map

func FileLocksFor(fs *vfs.VFS) *FileLockManager {
	manager := NewFileLockManager()
	actual, _ := fileLockManagers.LoadOrStore(fs, manager)
	return actual.(*FileLockManager)
}

func (m *FileLockManager) stateFor(identity vfs.FileIdentity) *fileLockState {
	m.mu.Lock()
	state := m.states[identity]
	if state == nil {
		state = newFileLockState()
		m.states[identity] = state
	}
	m.mu.Unlock()
	return state
}

func (m *FileLockManager) ownerClosed(owner uint64) bool {
	m.mu.Lock()
	closed := m.closedOwners[owner]
	m.mu.Unlock()
	return closed
}

func fileRangesOverlap(aStart, aLength, bStart, bLength uint64) bool {
	if aLength == 0 || bLength == 0 {
		return false
	}
	if aStart <= bStart {
		return bStart-aStart < aLength
	}
	return aStart-bStart < bLength
}

func fileLockConflicts(
	locks []fileRangeLock,
	owner, start, length uint64,
	exclusive bool,
) bool {
	for _, lock := range locks {
		if !fileRangesOverlap(start, length, lock.start, lock.length) {
			continue
		}
		if exclusive || lock.exclusive && lock.owner != owner {
			return true
		}
	}
	return false
}

func (m *FileLockManager) Lock(
	identity vfs.FileIdentity,
	owner, start, length uint64,
	exclusive, wait bool,
) bool {
	return m.LockKeyCancelable(
		identity,
		owner,
		start,
		length,
		0,
		exclusive,
		wait,
		nil,
	)
}

func (m *FileLockManager) LockKey(
	identity vfs.FileIdentity,
	owner, start, length uint64,
	key uint32,
	exclusive, wait bool,
) bool {
	return m.LockKeyCancelable(
		identity,
		owner,
		start,
		length,
		key,
		exclusive,
		wait,
		nil,
	)
}

func (m *FileLockManager) LockCancelable(
	identity vfs.FileIdentity,
	owner, start, length uint64,
	exclusive, wait bool,
	cancel <-chan struct{},
) bool {
	return m.LockKeyCancelable(
		identity,
		owner,
		start,
		length,
		0,
		exclusive,
		wait,
		cancel,
	)
}

func (m *FileLockManager) LockKeyCancelable(
	identity vfs.FileIdentity,
	owner, start, length uint64,
	key uint32,
	exclusive, wait bool,
	cancel <-chan struct{},
) bool {
	state := m.stateFor(identity)
	state.mu.Lock()
	defer state.mu.Unlock()
	var stopWake chan struct{}
	if cancel != nil {
		stopWake = make(chan struct{})
		defer close(stopWake)
		go func() {
			select {
			case <-cancel:
				state.mu.Lock()
				state.cond.Broadcast()
				state.mu.Unlock()
			case <-stopWake:
			}
		}()
	}
	for fileLockConflicts(state.locks, owner, start, length, exclusive) {
		if m.ownerClosed(owner) {
			return false
		}
		if !wait {
			return false
		}
		if cancel != nil {
			select {
			case <-cancel:
				return false
			default:
			}
		}
		state.cond.Wait()
	}
	if m.ownerClosed(owner) {
		return false
	}
	if cancel != nil {
		select {
		case <-cancel:
			return false
		default:
		}
	}
	state.locks = append(state.locks, fileRangeLock{
		owner:     owner,
		start:     start,
		length:    length,
		key:       key,
		exclusive: exclusive,
	})
	return true
}

func (m *FileLockManager) Unlock(
	identity vfs.FileIdentity,
	owner, start, length uint64,
) bool {
	return m.UnlockKey(identity, owner, start, length, 0)
}

func (m *FileLockManager) UnlockKey(
	identity vfs.FileIdentity,
	owner, start, length uint64,
	key uint32,
) bool {
	state := m.stateFor(identity)
	state.mu.Lock()
	defer state.mu.Unlock()
	match := -1
	for i, lock := range state.locks {
		if lock.owner != owner || lock.start != start ||
			lock.length != length || lock.key != key {
			continue
		}
		if match == -1 || lock.exclusive {
			match = i
		}
		if lock.exclusive {
			break
		}
	}
	if match == -1 {
		return false
	}
	state.locks = append(state.locks[:match], state.locks[match+1:]...)
	state.cond.Broadcast()
	return true
}

func (m *FileLockManager) CanRead(
	identity vfs.FileIdentity,
	owner, start, length uint64,
) bool {
	state := m.stateFor(identity)
	state.mu.Lock()
	defer state.mu.Unlock()
	return fileLocksAllowRead(state.locks, owner, start, length)
}

func fileLocksAllowRead(
	locks []fileRangeLock,
	owner, start, length uint64,
) bool {
	for _, lock := range locks {
		if lock.exclusive && lock.owner != owner &&
			fileRangesOverlap(start, length, lock.start, lock.length) {
			return false
		}
	}
	return true
}

func (m *FileLockManager) CanWrite(
	identity vfs.FileIdentity,
	owner, start, length uint64,
) bool {
	state := m.stateFor(identity)
	state.mu.Lock()
	defer state.mu.Unlock()
	return fileLocksAllowWrite(state.locks, owner, start, length)
}

func fileLocksAllowWrite(
	locks []fileRangeLock,
	owner, start, length uint64,
) bool {
	for _, lock := range locks {
		if fileRangesOverlap(start, length, lock.start, lock.length) &&
			(!lock.exclusive || lock.owner != owner) {
			return false
		}
	}
	return true
}

func (m *FileLockManager) WithReadAccess(
	identity vfs.FileIdentity,
	owner, start, length uint64,
	access func(),
) bool {
	state := m.stateFor(identity)
	state.mu.Lock()
	if !fileLocksAllowRead(state.locks, owner, start, length) {
		state.mu.Unlock()
		return false
	}
	access()
	state.mu.Unlock()
	return true
}

func (m *FileLockManager) WithWriteAccess(
	identity vfs.FileIdentity,
	owner, start, length uint64,
	access func(),
) bool {
	state := m.stateFor(identity)
	state.mu.Lock()
	if !fileLocksAllowWrite(state.locks, owner, start, length) {
		state.mu.Unlock()
		return false
	}
	access()
	state.mu.Unlock()
	return true
}

func (m *FileLockManager) ReleaseOwner(owner uint64) {
	m.mu.Lock()
	m.closedOwners[owner] = true
	states := make([]*fileLockState, 0, len(m.states))
	for _, state := range m.states {
		states = append(states, state)
	}
	m.mu.Unlock()

	for _, state := range states {
		state.mu.Lock()
		kept := state.locks[:0]
		for _, lock := range state.locks {
			if lock.owner != owner {
				kept = append(kept, lock)
			}
		}
		state.locks = kept
		state.cond.Broadcast()
		state.mu.Unlock()
	}
}
