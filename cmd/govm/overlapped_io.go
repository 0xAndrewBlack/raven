//go:build guest_windows

package main

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"golang.org/x/sys/unix"
)

const (
	overlappedStatusSuccess        = uint32(0)
	overlappedStatusPending        = uint32(0x103)
	overlappedStatusCancelled      = uint32(0xC0000120)
	overlappedStatusFailed         = uint32(0xC0000001)
	overlappedStatusNoAccess       = uint32(0xC0000005)
	overlappedStatusInvalidParam   = uint32(0xC000000D)
	overlappedStatusLockConflict   = uint32(0xC0000054)
	overlappedStatusLockNotGranted = uint32(0xC0000055)
	overlappedStatusRangeNotLocked = uint32(0xC000007E)

	fileNotifyChangeFileName   = uint32(0x00000001)
	fileNotifyChangeDirName    = uint32(0x00000002)
	fileNotifyChangeAttributes = uint32(0x00000004)
	fileNotifyChangeSize       = uint32(0x00000008)
	fileNotifyChangeLastWrite  = uint32(0x00000010)
	fileNotifyChangeLastAccess = uint32(0x00000020)
	fileNotifyChangeCreation   = uint32(0x00000040)
	fileNotifyChangeSecurity   = uint32(0x00000100)

	fileActionAdded          = uint32(1)
	fileActionRemoved        = uint32(2)
	fileActionModified       = uint32(3)
	fileActionRenamedOldName = uint32(4)
	fileActionRenamedNewName = uint32(5)
)

type overlappedLayout struct {
	pointerSize  uint64
	internal     uint64
	internalHigh uint64
	offset       uint64
	offsetHigh   uint64
	event        uint64
}

func guestOverlappedLayout(mode32 bool) overlappedLayout {
	if mode32 {
		return overlappedLayout{
			pointerSize:  4,
			internal:     0,
			internalHigh: 4,
			offset:       8,
			offsetHigh:   12,
			event:        16,
		}
	}
	return overlappedLayout{
		pointerSize:  8,
		internal:     0,
		internalHigh: 8,
		offset:       16,
		offsetHigh:   20,
		event:        24,
	}
}

func (l overlappedLayout) readPointer(mem *mmu.MMU, addr uint64) uint64 {
	if l.pointerSize == 4 {
		value, _ := mem.Read32(addr)
		return uint64(value)
	}
	value, _ := mem.Read64(addr)
	return value
}

func (l overlappedLayout) writePointer(mem *mmu.MMU, addr, value uint64) {
	_ = l.writePointerChecked(mem, addr, value)
}

func (l overlappedLayout) writePointerChecked(mem *mmu.MMU, addr, value uint64) error {
	if l.pointerSize == 4 {
		return mem.Write32(addr, uint32(value))
	}
	return mem.Write64(addr, value)
}

func (l overlappedLayout) readOffset(mem *mmu.MMU, overlapped uint64) (uint32, uint32) {
	low, _ := mem.Read32(overlapped + l.offset)
	high, _ := mem.Read32(overlapped + l.offsetHigh)
	return low, high
}

func (l overlappedLayout) readEvent(mem *mmu.MMU, overlapped uint64) uint64 {
	return l.readPointer(mem, overlapped+l.event)
}

func (l overlappedLayout) writeResult(mem *mmu.MMU, overlapped uint64, status uint32, bytes uint32) {
	_ = l.writeResultChecked(mem, overlapped, status, bytes)
}

func (l overlappedLayout) writeResultChecked(
	mem *mmu.MMU,
	overlapped uint64,
	status uint32,
	bytes uint32,
) error {
	if err := l.writePointerChecked(mem, overlapped+l.internal, uint64(status)); err != nil {
		return err
	}
	return l.writePointerChecked(mem, overlapped+l.internalHigh, uint64(bytes))
}

type overlappedKey struct {
	handle     ntapi.Handle
	overlapped uint64
}

type overlappedOperation struct {
	id        uint64
	key       overlappedKey
	ownerTID  uint32
	buffer    uint64
	bufferLen uint32
	event     *ntapi.EventHandle
	postIOCP  func(bytes, status uint32)
	queueAPC  func()
	publish   func(status uint32, data []byte) (uint32, uint32)
	finish    func()

	mu          sync.Mutex
	status      uint32
	data        []byte
	deferStatus bool
	dequeued    bool
	done        chan struct{}
	once        sync.Once
}

func newOverlappedOperation(
	key overlappedKey,
	ownerTID uint32,
	buffer uint64,
	bufferLen uint32,
	event *ntapi.EventHandle,
	postIOCP func(bytes, status uint32),
) *overlappedOperation {
	return &overlappedOperation{
		key:       key,
		ownerTID:  ownerTID,
		buffer:    buffer,
		bufferLen: bufferLen,
		event:     event,
		postIOCP:  postIOCP,
		status:    overlappedStatusPending,
		done:      make(chan struct{}),
	}
}

func (op *overlappedOperation) complete(status uint32, data []byte) bool {
	completed := false
	op.once.Do(func() {
		completed = true
		if op.publish != nil {
			var bytes uint32
			status, bytes = op.publish(status, data)
			if bytes < uint32(len(data)) {
				data = data[:bytes]
			}
		}
		op.mu.Lock()
		op.status = status
		op.data = append([]byte(nil), data...)
		bytes := uint32(len(op.data))
		finish := op.finish
		op.mu.Unlock()
		if finish != nil {
			finish()
		}
		if op.event != nil {
			op.event.Set()
		}
		if op.postIOCP != nil {
			op.postIOCP(bytes, status)
		}
		if op.queueAPC != nil {
			op.queueAPC()
		}
		close(op.done)
	})
	return completed
}

func (op *overlappedOperation) setFinish(finish func()) bool {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.status != overlappedStatusPending {
		return false
	}
	op.finish = finish
	return true
}

func (op *overlappedOperation) result() (uint32, []byte) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.deferStatus && !op.dequeued {
		return overlappedStatusPending, nil
	}
	return op.status, append([]byte(nil), op.data...)
}

func (op *overlappedOperation) markDequeued() {
	op.mu.Lock()
	op.dequeued = true
	op.mu.Unlock()
}

func (op *overlappedOperation) shouldDeferStatus() bool {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.deferStatus
}

func (op *overlappedOperation) pending() bool {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.status == overlappedStatusPending
}

type overlappedRegistry struct {
	mu     sync.Mutex
	nextID uint64
	ops    map[overlappedKey]*overlappedOperation
}

func newOverlappedRegistry() *overlappedRegistry {
	return &overlappedRegistry{ops: make(map[overlappedKey]*overlappedOperation)}
}

func (r *overlappedRegistry) begin(op *overlappedOperation) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current := r.ops[op.key]; current != nil && current.pending() {
		return false
	}
	r.nextID++
	op.id = r.nextID
	r.ops[op.key] = op
	return true
}

func (r *overlappedRegistry) get(handle ntapi.Handle, overlapped uint64) *overlappedOperation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ops[overlappedKey{handle: handle, overlapped: overlapped}]
}

func (r *overlappedRegistry) getCompletion(
	handle ntapi.Handle,
	overlapped uint64,
	operationID uint64,
) *overlappedOperation {
	if operationID == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	op := r.ops[overlappedKey{handle: handle, overlapped: overlapped}]
	if op == nil || op.id != operationID {
		return nil
	}
	return op
}

func (r *overlappedRegistry) forget(op *overlappedOperation) {
	if op == nil {
		return
	}
	r.mu.Lock()
	if r.ops[op.key] == op {
		delete(r.ops, op.key)
	}
	r.mu.Unlock()
}

func (r *overlappedRegistry) cancel(handle ntapi.Handle, overlapped uint64, ownerTID uint32, ownerOnly bool) int {
	r.mu.Lock()
	var matches []*overlappedOperation
	for key, op := range r.ops {
		if key.handle != handle || (overlapped != 0 && key.overlapped != overlapped) {
			continue
		}
		if ownerOnly && op.ownerTID != ownerTID {
			continue
		}
		matches = append(matches, op)
	}
	r.mu.Unlock()

	cancelled := 0
	for _, op := range matches {
		if op.pending() {
			op.complete(overlappedStatusCancelled, nil)
			cancelled++
		}
	}
	return cancelled
}

func (r *overlappedRegistry) cancelHandle(handle ntapi.Handle) {
	r.cancel(handle, 0, 0, false)
	r.mu.Lock()
	for key := range r.ops {
		if key.handle == handle {
			delete(r.ops, key)
		}
	}
	r.mu.Unlock()
}

func materializeOverlapped(mem *mmu.MMU, mode32 bool, op *overlappedOperation) (uint32, uint32) {
	status, data := op.result()
	bytes := uint32(len(data))
	if bytes > op.bufferLen {
		bytes = op.bufferLen
	}
	if err := guestOverlappedLayout(mode32).writeResultChecked(
		mem,
		op.key.overlapped,
		status,
		bytes,
	); err != nil {
		status = overlappedStatusNoAccess
		bytes = 0
	}
	return status, bytes
}

func dequeueOverlapped(mem *mmu.MMU, mode32 bool, op *overlappedOperation) (uint32, uint32) {
	op.markDequeued()
	return materializeOverlapped(mem, mode32, op)
}

type directoryEntryState struct {
	name     string
	isDir    bool
	size     int64
	modTime  int64
	mode     uint32
	identity uint64
}

type directoryChange struct {
	action uint32
	name   string
	filter uint32
}

func directorySnapshot(fs *vfs.VFS, root string, recursive bool) (map[string]directoryEntryState, error) {
	result := make(map[string]directoryEntryState)
	var walk func(string, string) error
	walk = func(path, prefix string) error {
		entries, err := fs.ReadDir(path)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			relative := entry.Name()
			if prefix != "" {
				relative = prefix + `\` + relative
			}
			info, infoErr := entry.Info()
			state := directoryEntryState{name: relative, isDir: entry.IsDir()}
			if infoErr == nil {
				state.size = info.Size()
				state.modTime = info.ModTime().UnixNano()
				state.mode = uint32(info.Mode())
				if stat, ok := info.Sys().(*syscall.Stat_t); ok {
					state.identity = uint64(stat.Dev)<<32 ^ stat.Ino
				}
			}
			key := strings.ToLower(relative)
			result[key] = state
			if recursive && entry.IsDir() {
				if err := walk(filepath.Join(path, entry.Name()), relative); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return result, walk(root, "")
}

func diffDirectorySnapshots(
	before, after map[string]directoryEntryState,
	filter uint32,
) []directoryChange {
	var changes []directoryChange
	removed := make(map[string]directoryEntryState)
	added := make(map[string]directoryEntryState)
	for key, oldEntry := range before {
		newEntry, exists := after[key]
		if !exists {
			removed[key] = oldEntry
			continue
		}
		if oldEntry.name != newEntry.name {
			nameFilter := fileNotifyChangeFileName
			if oldEntry.isDir {
				nameFilter = fileNotifyChangeDirName
			}
			if filter&nameFilter != 0 {
				changes = append(changes,
					directoryChange{
						action: fileActionRenamedOldName,
						name:   oldEntry.name,
						filter: nameFilter,
					},
					directoryChange{
						action: fileActionRenamedNewName,
						name:   newEntry.name,
						filter: nameFilter,
					},
				)
			}
		}
		sizeChanged := oldEntry.size != newEntry.size
		timeChanged := oldEntry.modTime != newEntry.modTime
		modeChanged := oldEntry.mode != newEntry.mode
		var changedFilter uint32
		if sizeChanged {
			changedFilter |= fileNotifyChangeSize
		}
		if timeChanged {
			changedFilter |= fileNotifyChangeLastWrite |
				fileNotifyChangeLastAccess |
				fileNotifyChangeCreation
		}
		if modeChanged {
			changedFilter |= fileNotifyChangeAttributes | fileNotifyChangeSecurity
		}
		if changedFilter&filter != 0 {
			changes = append(changes, directoryChange{
				action: fileActionModified,
				name:   newEntry.name,
				filter: changedFilter,
			})
		}
	}
	for key, newEntry := range after {
		if _, exists := before[key]; exists {
			continue
		}
		added[key] = newEntry
	}
	for oldKey, oldEntry := range removed {
		if oldEntry.identity == 0 {
			continue
		}
		for newKey, newEntry := range added {
			if newEntry.identity != oldEntry.identity || newEntry.isDir != oldEntry.isDir {
				continue
			}
			nameFilter := fileNotifyChangeFileName
			if oldEntry.isDir {
				nameFilter = fileNotifyChangeDirName
			}
			if filter&nameFilter != 0 {
				changes = append(changes,
					directoryChange{
						action: fileActionRenamedOldName,
						name:   oldEntry.name,
						filter: nameFilter,
					},
					directoryChange{
						action: fileActionRenamedNewName,
						name:   newEntry.name,
						filter: nameFilter,
					},
				)
			}
			delete(removed, oldKey)
			delete(added, newKey)
			break
		}
	}
	for _, oldEntry := range removed {
		nameFilter := fileNotifyChangeFileName
		if oldEntry.isDir {
			nameFilter = fileNotifyChangeDirName
		}
		if filter&nameFilter != 0 {
			changes = append(changes, directoryChange{
				action: fileActionRemoved,
				name:   oldEntry.name,
				filter: nameFilter,
			})
		}
	}
	for _, newEntry := range added {
		nameFilter := fileNotifyChangeFileName
		if newEntry.isDir {
			nameFilter = fileNotifyChangeDirName
		}
		if filter&(nameFilter|fileNotifyChangeCreation) != 0 {
			changes = append(changes, directoryChange{
				action: fileActionAdded,
				name:   newEntry.name,
				filter: nameFilter | fileNotifyChangeCreation,
			})
		}
	}
	return changes
}

func encodeDirectoryChanges(changes []directoryChange, limit uint32) ([]byte, bool) {
	var records [][]byte
	total := 0
	for _, change := range changes {
		name := utf16.Encode([]rune(change.name))
		recordLen := 12 + len(name)*2
		alignedLen := (recordLen + 3) &^ 3
		if total+alignedLen > int(limit) {
			return nil, true
		}
		record := make([]byte, alignedLen)
		binary.LittleEndian.PutUint32(record[4:8], change.action)
		binary.LittleEndian.PutUint32(record[8:12], uint32(len(name)*2))
		for i, value := range name {
			binary.LittleEndian.PutUint16(record[12+i*2:], value)
		}
		records = append(records, record)
		total += alignedLen
	}
	output := make([]byte, 0, total)
	for i, record := range records {
		if i+1 < len(records) {
			binary.LittleEndian.PutUint32(record[0:4], uint32(len(record)))
		}
		output = append(output, record...)
	}
	return output, false
}

type directoryJournalRequest struct {
	op        *overlappedOperation
	filter    uint32
	recursive bool
}

type directoryJournal struct {
	fs        *vfs.VFS
	path      string
	recursive bool

	mu        sync.Mutex
	pending   *directoryJournalRequest
	queued    []directoryChange
	overflow  bool
	capacity  uint32
	stopped   bool
	stop      chan struct{}
	stopOnce  sync.Once
	inotifyFD int

	snapshot map[string]directoryEntryState
}

func newDirectoryJournal(fs *vfs.VFS, path string, recursive bool) (*directoryJournal, error) {
	snapshot, err := directorySnapshot(fs, path, recursive)
	if err != nil {
		return nil, err
	}
	journal := &directoryJournal{
		fs:        fs,
		path:      path,
		recursive: recursive,
		stop:      make(chan struct{}),
		snapshot:  snapshot,
		inotifyFD: -1,
	}
	if fd, watches, watchErr := journal.startInotify(); watchErr == nil {
		journal.inotifyFD = fd
		go journal.runInotify(fd, watches)
	} else {
		go journal.runPolling()
	}
	return journal, nil
}

func (j *directoryJournal) arm(op *overlappedOperation, filter uint32, recursive bool) bool {
	j.mu.Lock()
	if j.stopped || j.pending != nil {
		j.mu.Unlock()
		return false
	}
	if j.capacity == 0 {
		j.capacity = op.bufferLen
	}
	if len(j.queued) != 0 {
		if _, overflow := encodeDirectoryChanges(j.queued, j.capacity); overflow {
			j.queued = nil
			j.overflow = true
		}
	}
	if j.overflow {
		j.overflow = false
		j.queued = nil
		j.mu.Unlock()
		op.complete(overlappedStatusSuccess, nil)
		return true
	}
	var matching []directoryChange
	for _, change := range j.queued {
		if (!recursive && strings.Contains(change.name, `\`)) ||
			(change.filter != 0 && change.filter&filter == 0) {
			continue
		}
		if change.filter == 0 || change.filter&filter != 0 {
			matching = append(matching, change)
		}
	}
	j.queued = nil
	limit := j.capacity
	if op.bufferLen < limit {
		limit = op.bufferLen
	}
	if len(matching) == 0 {
		request := &directoryJournalRequest{
			op:        op,
			filter:    filter,
			recursive: recursive,
		}
		if !op.setFinish(func() { j.disarm(op) }) {
			j.mu.Unlock()
			return false
		}
		j.pending = request
		j.mu.Unlock()
		return true
	}
	j.mu.Unlock()
	data, _ := encodeDirectoryChanges(matching, limit)
	op.complete(overlappedStatusSuccess, data)
	return true
}

func (j *directoryJournal) disarm(op *overlappedOperation) {
	j.mu.Lock()
	if j.pending != nil && j.pending.op == op {
		j.pending = nil
	}
	j.mu.Unlock()
}

func (j *directoryJournal) appendChanges(changes []directoryChange) {
	changes = dedupeDirectoryChanges(changes)
	if len(changes) == 0 {
		return
	}
	j.mu.Lock()
	if j.stopped {
		j.mu.Unlock()
		return
	}
	if j.pending == nil {
		j.queued = append(j.queued, changes...)
		if j.capacity != 0 {
			if _, overflow := encodeDirectoryChanges(j.queued, j.capacity); overflow {
				j.queued = nil
				j.overflow = true
			}
		}
		j.mu.Unlock()
		return
	}
	request := j.pending
	var matching []directoryChange
	for _, change := range changes {
		if !request.recursive && strings.Contains(change.name, `\`) {
			continue
		}
		if change.filter == 0 || change.filter&request.filter != 0 {
			matching = append(matching, change)
		}
	}
	if len(matching) == 0 {
		j.mu.Unlock()
		return
	}
	j.pending = nil
	limit := j.capacity
	if request.op.bufferLen < limit {
		limit = request.op.bufferLen
	}
	j.mu.Unlock()
	data, _ := encodeDirectoryChanges(matching, limit)
	request.op.complete(overlappedStatusSuccess, data)
}

func (j *directoryJournal) markOverflow() {
	j.mu.Lock()
	if j.stopped {
		j.mu.Unlock()
		return
	}
	j.queued = nil
	if j.pending == nil {
		j.overflow = true
		j.mu.Unlock()
		return
	}
	request := j.pending
	j.pending = nil
	j.mu.Unlock()
	request.op.complete(overlappedStatusSuccess, nil)
}

type directoryJournalRegistry struct {
	mu       sync.Mutex
	journals map[ntapi.Handle]*directoryJournal
}

func newDirectoryJournalRegistry() *directoryJournalRegistry {
	return &directoryJournalRegistry{
		journals: make(map[ntapi.Handle]*directoryJournal),
	}
}

func (r *directoryJournalRegistry) getOrCreate(
	handle ntapi.Handle,
	fs *vfs.VFS,
	path string,
) (*directoryJournal, error) {
	r.mu.Lock()
	if journal := r.journals[handle]; journal != nil {
		r.mu.Unlock()
		return journal, nil
	}
	journal, err := newDirectoryJournal(fs, path, true)
	if err == nil {
		r.journals[handle] = journal
	}
	r.mu.Unlock()
	return journal, err
}

func (r *directoryJournalRegistry) close(handle ntapi.Handle) {
	r.mu.Lock()
	journal := r.journals[handle]
	delete(r.journals, handle)
	r.mu.Unlock()
	if journal != nil {
		journal.close()
	}
}

func dedupeDirectoryChanges(changes []directoryChange) []directoryChange {
	type changeKey struct {
		action uint32
		name   string
		filter uint32
	}
	seen := make(map[changeKey]struct{}, len(changes))
	result := make([]directoryChange, 0, len(changes))
	for _, change := range changes {
		key := changeKey{
			action: change.action,
			name:   strings.ToLower(change.name),
			filter: change.filter,
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, change)
	}
	return result
}

func (j *directoryJournal) close() {
	j.stopOnce.Do(func() {
		j.mu.Lock()
		j.stopped = true
		pending := j.pending
		j.pending = nil
		inotifyFD := j.inotifyFD
		j.inotifyFD = -1
		j.mu.Unlock()
		close(j.stop)
		if inotifyFD >= 0 {
			_ = unix.Close(inotifyFD)
		}
		if pending != nil {
			pending.op.complete(overlappedStatusCancelled, nil)
		}
	})
}

func (j *directoryJournal) runPolling() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	before := j.snapshot
	for {
		select {
		case <-j.stop:
			return
		case <-ticker.C:
			after, err := directorySnapshot(j.fs, j.path, j.recursive)
			if err != nil {
				j.close()
				return
			}
			changes := diffDirectorySnapshots(before, after, 0x000001FF)
			before = after
			j.appendChanges(changes)
		}
	}
}

type inotifyWatch struct {
	path     string
	relative string
}

func (j *directoryJournal) startInotify() (int, map[int32]inotifyWatch, error) {
	if info, err := os.Stat(j.path); err != nil || !info.IsDir() {
		return -1, nil, errors.New("directory is not host-backed")
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return -1, nil, err
	}
	watches := make(map[int32]inotifyWatch)
	if err := j.addInotifyWatch(fd, watches, j.path, ""); err != nil {
		unix.Close(fd)
		return -1, nil, err
	}
	if j.recursive {
		err = filepath.WalkDir(j.path, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if path == j.path || !entry.IsDir() {
				return nil
			}
			relative, relErr := filepath.Rel(j.path, path)
			if relErr != nil {
				return relErr
			}
			return j.addInotifyWatch(fd, watches, path, filepath.ToSlash(relative))
		})
		if err != nil {
			unix.Close(fd)
			return -1, nil, err
		}
	}
	return fd, watches, nil
}

func (j *directoryJournal) addInotifyWatch(
	fd int,
	watches map[int32]inotifyWatch,
	path, relative string,
) error {
	const mask = unix.IN_CREATE |
		unix.IN_DELETE |
		unix.IN_MODIFY |
		unix.IN_CLOSE_WRITE |
		unix.IN_ATTRIB |
		unix.IN_MOVED_FROM |
		unix.IN_MOVED_TO |
		unix.IN_DELETE_SELF |
		unix.IN_MOVE_SELF
	wd, err := unix.InotifyAddWatch(fd, path, mask)
	if err != nil {
		return err
	}
	watches[int32(wd)] = inotifyWatch{path: path, relative: relative}
	return nil
}

func (j *directoryJournal) addInotifyTree(
	fd int,
	watches map[int32]inotifyWatch,
	path, relative string,
) error {
	return filepath.WalkDir(path, func(childPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		childRelative, err := filepath.Rel(path, childPath)
		if err != nil {
			return err
		}
		watchRelative := relative
		if childRelative != "." {
			watchRelative = filepath.ToSlash(filepath.Join(relative, childRelative))
		}
		return j.addInotifyWatch(fd, watches, childPath, watchRelative)
	})
}

func removeInotifyWatchTree(
	fd int,
	watches map[int32]inotifyWatch,
	relative string,
) {
	relative = filepath.ToSlash(relative)
	for wd, watch := range watches {
		if watch.relative != relative &&
			!strings.HasPrefix(watch.relative, relative+"/") {
			continue
		}
		_, _ = unix.InotifyRmWatch(fd, uint32(wd))
		delete(watches, wd)
	}
}

func rebaseInotifyWatchTree(
	watches map[int32]inotifyWatch,
	oldRelative, newRelative, newPath string,
) {
	oldRelative = filepath.ToSlash(oldRelative)
	newRelative = filepath.ToSlash(newRelative)
	for wd, watch := range watches {
		if watch.relative != oldRelative &&
			!strings.HasPrefix(watch.relative, oldRelative+"/") {
			continue
		}
		suffix := strings.TrimPrefix(watch.relative, oldRelative)
		suffix = strings.TrimPrefix(suffix, "/")
		watch.relative = newRelative
		watch.path = newPath
		if suffix != "" {
			watch.relative = newRelative + "/" + suffix
			watch.path = filepath.Join(newPath, filepath.FromSlash(suffix))
		}
		watches[wd] = watch
	}
}

func (j *directoryJournal) runInotify(fd int, watches map[int32]inotifyWatch) {
	defer j.close()
	buffer := make([]byte, 64*1024)
	type pendingMove struct {
		change   directoryChange
		observed time.Time
		isDir    bool
	}
	pendingMoves := make(map[uint32]pendingMove)
	var batchedChanges []directoryChange
	var lastChange time.Time
	flushMoves := func(force bool) []directoryChange {
		now := time.Now()
		var changes []directoryChange
		for cookie, move := range pendingMoves {
			if !force && now.Sub(move.observed) < 20*time.Millisecond {
				continue
			}
			changes = append(changes, directoryChange{
				action: fileActionRemoved,
				name:   move.change.name,
				filter: move.change.filter,
			})
			if move.isDir {
				removeInotifyWatchTree(
					fd,
					watches,
					strings.ReplaceAll(move.change.name, `\`, "/"),
				)
			}
			delete(pendingMoves, cookie)
		}
		return changes
	}
	for {
		n, err := unix.Read(fd, buffer)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EAGAIN) {
				if staleMoves := flushMoves(false); len(staleMoves) != 0 {
					batchedChanges = append(batchedChanges, staleMoves...)
					lastChange = time.Now()
				}
				if len(batchedChanges) != 0 &&
					time.Since(lastChange) >= 5*time.Millisecond {
					j.appendChanges(batchedChanges)
					batchedChanges = nil
				}
				select {
				case <-j.stop:
					return
				case <-time.After(5 * time.Millisecond):
					continue
				}
			}
			return
		}
		var changes []directoryChange
		for offset := 0; offset+16 <= n; {
			wd := int32(binary.LittleEndian.Uint32(buffer[offset:]))
			mask := binary.LittleEndian.Uint32(buffer[offset+4:])
			cookie := binary.LittleEndian.Uint32(buffer[offset+8:])
			nameLen := int(binary.LittleEndian.Uint32(buffer[offset+12:]))
			if offset+16+nameLen > n {
				break
			}
			nameBytes := buffer[offset+16 : offset+16+nameLen]
			if mask&unix.IN_Q_OVERFLOW != 0 {
				batchedChanges = nil
				j.markOverflow()
				offset += 16 + nameLen
				continue
			}
			if zero := bytesIndexByte(nameBytes, 0); zero >= 0 {
				nameBytes = nameBytes[:zero]
			}
			watch := watches[wd]
			name := string(nameBytes)
			if name == "" {
				offset += 16 + nameLen
				continue
			}
			relative := name
			if watch.relative != "" {
				relative = filepath.ToSlash(filepath.Join(watch.relative, name))
			}
			relative = strings.ReplaceAll(relative, "/", `\`)
			nameFilter := fileNotifyChangeFileName
			if mask&unix.IN_ISDIR != 0 {
				nameFilter = fileNotifyChangeDirName
			}
			switch {
			case mask&unix.IN_MOVED_FROM != 0:
				pendingMoves[cookie] = pendingMove{
					change: directoryChange{
						action: fileActionRenamedOldName,
						name:   relative,
						filter: nameFilter,
					},
					observed: time.Now(),
					isDir:    mask&unix.IN_ISDIR != 0,
				}
			case mask&unix.IN_MOVED_TO != 0:
				if old, ok := pendingMoves[cookie]; ok {
					changes = append(changes, old.change, directoryChange{
						action: fileActionRenamedNewName,
						name:   relative,
						filter: nameFilter,
					})
					if mask&unix.IN_ISDIR != 0 {
						rebaseInotifyWatchTree(
							watches,
							strings.ReplaceAll(old.change.name, `\`, "/"),
							strings.ReplaceAll(relative, `\`, "/"),
							filepath.Join(watch.path, name),
						)
					}
					delete(pendingMoves, cookie)
				} else {
					changes = append(changes, directoryChange{
						action: fileActionAdded,
						name:   relative,
						filter: nameFilter | fileNotifyChangeCreation,
					})
					if j.recursive && mask&unix.IN_ISDIR != 0 {
						_ = j.addInotifyTree(
							fd,
							watches,
							filepath.Join(watch.path, name),
							strings.ReplaceAll(relative, `\`, "/"),
						)
					}
				}
			case mask&unix.IN_CREATE != 0:
				changes = append(changes, directoryChange{
					action: fileActionAdded,
					name:   relative,
					filter: nameFilter | fileNotifyChangeCreation,
				})
				if j.recursive && mask&unix.IN_ISDIR != 0 {
					childPath := filepath.Join(watch.path, name)
					_ = j.addInotifyWatch(fd, watches, childPath, strings.ReplaceAll(relative, `\`, "/"))
				}
			case mask&unix.IN_DELETE != 0:
				changes = append(changes, directoryChange{
					action: fileActionRemoved,
					name:   relative,
					filter: nameFilter,
				})
				if j.recursive && mask&unix.IN_ISDIR != 0 {
					removeInotifyWatchTree(
						fd,
						watches,
						strings.ReplaceAll(relative, `\`, "/"),
					)
				}
			case mask&(unix.IN_MODIFY|unix.IN_CLOSE_WRITE) != 0:
				changes = append(changes, directoryChange{
					action: fileActionModified,
					name:   relative,
					filter: fileNotifyChangeSize | fileNotifyChangeLastWrite,
				})
			case mask&unix.IN_ATTRIB != 0:
				changes = append(changes, directoryChange{
					action: fileActionModified,
					name:   relative,
					filter: fileNotifyChangeAttributes |
						fileNotifyChangeLastAccess |
						fileNotifyChangeSecurity,
				})
			}
			offset += 16 + nameLen
		}
		if len(changes) != 0 {
			batchedChanges = append(batchedChanges, changes...)
			lastChange = time.Now()
		}
		if staleMoves := flushMoves(false); len(staleMoves) != 0 {
			batchedChanges = append(batchedChanges, staleMoves...)
			lastChange = time.Now()
		}
	}
}

func bytesIndexByte(data []byte, target byte) int {
	for i, value := range data {
		if value == target {
			return i
		}
	}
	return -1
}

func waitOverlapped(op *overlappedOperation, timeout time.Duration) bool {
	if timeout < 0 {
		<-op.done
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-op.done:
		return true
	case <-timer.C:
		return false
	}
}
