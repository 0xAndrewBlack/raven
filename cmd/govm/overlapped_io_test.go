//go:build guest_windows

package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
)

func TestGuestOverlappedLayoutWritesPE32AndPE64(t *testing.T) {
	for _, mode32 := range []bool{true, false} {
		t.Run(map[bool]string{true: "PE32", false: "PE64"}[mode32], func(t *testing.T) {
			mem := mmu.New()
			const base = uint64(0x4000)
			mem.MapRangeZero(base, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			layout := guestOverlappedLayout(mode32)

			mem.Write32(base+layout.offset, 0x55667788)
			mem.Write32(base+layout.offsetHigh, 0x11223344)
			layout.writePointer(mem, base+layout.event, 0x12345678)
			layout.writeResult(mem, base, overlappedStatusCancelled, 37)

			low, high := layout.readOffset(mem, base)
			if low != 0x55667788 || high != 0x11223344 {
				t.Fatalf("offset = %#x:%#x", high, low)
			}
			if got := layout.readEvent(mem, base); got != 0x12345678 {
				t.Fatalf("event = %#x", got)
			}
			if got := uint32(layout.readPointer(mem, base+layout.internal)); got != overlappedStatusCancelled {
				t.Fatalf("status = %#x", got)
			}
			if got := layout.readPointer(mem, base+layout.internalHigh); got != 37 {
				t.Fatalf("bytes = %d", got)
			}
		})
	}
}

func TestEncodeDirectoryChangesChainsAlignedRecords(t *testing.T) {
	data, overflow := encodeDirectoryChanges([]directoryChange{
		{action: fileActionAdded, name: "alpha.txt"},
		{action: fileActionModified, name: "beta.txt"},
	}, 1024)
	if overflow {
		t.Fatal("notification buffer unexpectedly overflowed")
	}
	if len(data)%4 != 0 {
		t.Fatalf("buffer length = %d, want DWORD alignment", len(data))
	}
	next := binary.LittleEndian.Uint32(data[0:4])
	if next == 0 || next%4 != 0 {
		t.Fatalf("first NextEntryOffset = %d", next)
	}
	if got := decodeNotifyName(data); got != "alpha.txt" {
		t.Fatalf("first name = %q", got)
	}
	second := data[next:]
	if got := binary.LittleEndian.Uint32(second[0:4]); got != 0 {
		t.Fatalf("last NextEntryOffset = %d", got)
	}
	if got := decodeNotifyName(second); got != "beta.txt" {
		t.Fatalf("second name = %q", got)
	}
}

func TestEncodeDirectoryChangesDropsPartialOverflow(t *testing.T) {
	data, overflow := encodeDirectoryChanges([]directoryChange{
		{action: fileActionAdded, name: "alpha.txt"},
		{action: fileActionAdded, name: "beta.txt"},
	}, 40)
	if !overflow {
		t.Fatal("notification buffer did not report overflow")
	}
	if len(data) != 0 {
		t.Fatalf("overflow returned %d partial bytes", len(data))
	}
}

func TestWatchDirectoryChangesDetectsHostFileCreation(t *testing.T) {
	fs := vfs.New()
	dir := t.TempDir()
	journal, err := newDirectoryJournal(fs, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.close()
	event := ntapi.NewEvent(true, false)
	op := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: 0x5000},
		1,
		0x6000,
		1024,
		event,
		nil,
	)
	if !journal.arm(op, fileNotifyChangeFileName, false) {
		t.Fatal("failed to arm directory journal")
	}
	if err := os.WriteFile(filepath.Join(dir, "created.txt"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !waitOverlapped(op, 2*time.Second) {
		t.Fatal("directory watcher did not complete")
	}
	status, data := op.result()
	if status != overlappedStatusSuccess {
		t.Fatalf("status = %#x", status)
	}
	if got := decodeNotifyName(data); got != "created.txt" {
		t.Fatalf("notification name = %q", got)
	}
	if action := binary.LittleEndian.Uint32(data[4:8]); action != fileActionAdded {
		t.Fatalf("action = %d", action)
	}
	if !event.PeekSignaled() {
		t.Fatal("completion event was not signaled")
	}
}

func TestRecursiveDirectoryJournalWatchesMovedInTree(t *testing.T) {
	fs := vfs.New()
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	source := filepath.Join(parent, "source")
	if err := os.MkdirAll(filepath.Join(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(source, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := newDirectoryJournal(fs, root, true)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.close()

	first := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: 0x5000},
		1,
		0,
		1024,
		nil,
		nil,
	)
	if !journal.arm(first, fileNotifyChangeDirName, true) {
		t.Fatal("failed to arm moved-directory request")
	}
	moved := filepath.Join(root, "moved")
	if err := os.Rename(source, moved); err != nil {
		t.Fatal(err)
	}
	if !waitOverlapped(first, 2*time.Second) {
		t.Fatal("moved directory was not reported")
	}

	second := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: 0x6000},
		1,
		0,
		1024,
		nil,
		nil,
	)
	if !journal.arm(second, fileNotifyChangeFileName, true) {
		t.Fatal("failed to rearm recursive request")
	}
	if err := os.WriteFile(filepath.Join(moved, "nested", "new.txt"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !waitOverlapped(second, 2*time.Second) {
		t.Fatal("moved-in subtree was not watched")
	}
	_, data := second.result()
	if got := decodeNotifyName(data); got != `moved\nested\new.txt` {
		t.Fatalf("notification name = %q", got)
	}
}

func TestDirectoryJournalRearmsQueuedChange(t *testing.T) {
	journal := &directoryJournal{stop: make(chan struct{}), inotifyFD: -1}
	first := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: 0x5000},
		1,
		0,
		1024,
		nil,
		nil,
	)
	if !journal.arm(first, fileNotifyChangeFileName, false) {
		t.Fatal("failed to arm first request")
	}
	journal.appendChanges([]directoryChange{{
		action: fileActionAdded,
		name:   "first.txt",
		filter: fileNotifyChangeFileName,
	}})
	if !waitOverlapped(first, time.Second) {
		t.Fatal("first request did not complete")
	}

	journal.appendChanges([]directoryChange{{
		action: fileActionAdded,
		name:   "between.txt",
		filter: fileNotifyChangeFileName,
	}})
	second := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: 0x6000},
		1,
		0,
		1024,
		nil,
		nil,
	)
	if !journal.arm(second, fileNotifyChangeFileName, false) {
		t.Fatal("failed to rearm directory journal")
	}
	if !waitOverlapped(second, time.Second) {
		t.Fatal("queued change was lost between requests")
	}
	_, data := second.result()
	if got := decodeNotifyName(data); got != "between.txt" {
		t.Fatalf("queued notification name = %q", got)
	}
}

func TestDirectoryJournalQueueOverflowReturnsZeroBytes(t *testing.T) {
	journal := &directoryJournal{
		stop:      make(chan struct{}),
		inotifyFD: -1,
		capacity:  16,
	}
	changes := make([]directoryChange, 4097)
	for i := range changes {
		changes[i] = directoryChange{
			action: fileActionAdded,
			name:   string(rune(i + 1)),
			filter: fileNotifyChangeFileName,
		}
	}
	journal.appendChanges(changes)
	op := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: 0x5000},
		1,
		0,
		1024,
		nil,
		nil,
	)
	if !journal.arm(op, fileNotifyChangeFileName, false) {
		t.Fatal("failed to arm overflow request")
	}
	if !waitOverlapped(op, time.Second) {
		t.Fatal("overflow request did not complete")
	}
	status, data := op.result()
	if status != overlappedStatusSuccess || len(data) != 0 {
		t.Fatalf("overflow result status=%#x bytes=%d", status, len(data))
	}
}

func TestDirectoryJournalKeepsFirstBufferCapacity(t *testing.T) {
	journal := &directoryJournal{stop: make(chan struct{}), inotifyFD: -1}
	first := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: 0x5000},
		1,
		0,
		32,
		nil,
		nil,
	)
	if !journal.arm(first, fileNotifyChangeFileName, false) {
		t.Fatal("failed to arm first request")
	}
	journal.appendChanges([]directoryChange{{
		action: fileActionAdded,
		name:   "a",
		filter: fileNotifyChangeFileName,
	}})
	if !waitOverlapped(first, time.Second) {
		t.Fatal("first request did not complete")
	}

	journal.appendChanges([]directoryChange{
		{action: fileActionAdded, name: "alpha.txt", filter: fileNotifyChangeFileName},
		{action: fileActionAdded, name: "beta.txt", filter: fileNotifyChangeFileName},
	})
	second := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: 0x6000},
		1,
		0,
		1024,
		nil,
		nil,
	)
	if !journal.arm(second, fileNotifyChangeFileName, false) {
		t.Fatal("failed to arm second request")
	}
	if !waitOverlapped(second, time.Second) {
		t.Fatal("overflow request did not complete")
	}
	if status, data := second.result(); status != overlappedStatusSuccess || len(data) != 0 {
		t.Fatalf("second result status=%#x bytes=%d", status, len(data))
	}
	if journal.capacity != 32 {
		t.Fatalf("journal capacity = %d", journal.capacity)
	}
}

func TestDirectoryJournalCloseCancelsPendingRequest(t *testing.T) {
	journal := &directoryJournal{stop: make(chan struct{}), inotifyFD: -1}
	op := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: 0x5000},
		1,
		0,
		1024,
		nil,
		nil,
	)
	if !journal.arm(op, fileNotifyChangeFileName, false) {
		t.Fatal("failed to arm directory journal")
	}
	journal.close()
	if !waitOverlapped(op, time.Second) {
		t.Fatal("close did not complete pending request")
	}
	if status, _ := op.result(); status != overlappedStatusCancelled {
		t.Fatalf("close status = %#x", status)
	}
}

func TestDirectoryJournalRejectsCompletedOperation(t *testing.T) {
	journal := &directoryJournal{stop: make(chan struct{}), inotifyFD: -1}
	op := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: 0x5000},
		1,
		0,
		1024,
		nil,
		nil,
	)
	op.complete(overlappedStatusCancelled, nil)
	if journal.arm(op, fileNotifyChangeFileName, false) {
		t.Fatal("completed operation was armed")
	}
	if journal.pending != nil {
		t.Fatal("completed operation remained pending")
	}
}

func TestOverlappedCompletionPublishesBeforeIOCP(t *testing.T) {
	mem := mmu.New()
	const (
		overlapped = uint64(0x4000)
		buffer     = uint64(0x5000)
	)
	mem.MapRangeZero(overlapped, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	op := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: overlapped},
		1,
		buffer,
		1024,
		nil,
		func(bytes, status uint32) {
			if status != overlappedStatusSuccess || bytes != 7 {
				t.Errorf("completion packet status=%#x bytes=%d", status, bytes)
			}
			layout := guestOverlappedLayout(false)
			if got := layout.readPointer(mem, overlapped+layout.internalHigh); got != 7 {
				t.Errorf("IOCP observed InternalHigh=%d", got)
			}
		},
	)
	op.publish = func(status uint32, data []byte) (uint32, uint32) {
		bytes := uint32(len(data))
		if err := guestOverlappedLayout(false).writeResultChecked(
			mem,
			overlapped,
			status,
			bytes,
		); err != nil {
			t.Fatal(err)
		}
		return status, bytes
	}
	op.complete(overlappedStatusSuccess, []byte("payload"))
}

func TestIOCPDefersStatusUntilDequeued(t *testing.T) {
	mem := mmu.New()
	const overlapped = uint64(0x4000)
	mem.MapRangeZero(overlapped, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	layout := guestOverlappedLayout(false)
	layout.writeResult(mem, overlapped, overlappedStatusPending, 0)

	op := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: overlapped},
		1,
		0x5000,
		1024,
		nil,
		func(uint32, uint32) {},
	)
	op.deferStatus = true
	op.publish = func(status uint32, data []byte) (uint32, uint32) {
		return status, uint32(len(data))
	}
	op.complete(overlappedStatusSuccess, []byte("payload"))

	if got := uint32(layout.readPointer(mem, overlapped+layout.internal)); got != overlappedStatusPending {
		t.Fatalf("status before dequeue = %#x", got)
	}
	if status, _ := op.result(); status != overlappedStatusPending {
		t.Fatalf("operation result before dequeue = %#x", status)
	}
	status, bytes := dequeueOverlapped(mem, false, op)
	if status != overlappedStatusSuccess || bytes != 7 {
		t.Fatalf("dequeued status=%#x bytes=%d", status, bytes)
	}
	if got := uint32(layout.readPointer(mem, overlapped+layout.internal)); got != overlappedStatusSuccess {
		t.Fatalf("status after dequeue = %#x", got)
	}
}

func TestOverlappedRegistryMatchesCompletionGeneration(t *testing.T) {
	registry := newOverlappedRegistry()
	key := overlappedKey{handle: 0x200, overlapped: 0x5000}
	first := newOverlappedOperation(key, 1, 0, 0, nil, nil)
	if !registry.begin(first) {
		t.Fatal("failed to register first operation")
	}
	first.complete(overlappedStatusSuccess, nil)

	second := newOverlappedOperation(key, 1, 0, 0, nil, nil)
	if !registry.begin(second) {
		t.Fatal("failed to register reused operation")
	}
	if got := registry.getCompletion(key.handle, key.overlapped, first.id); got != nil {
		t.Fatal("old completion matched reused OVERLAPPED")
	}
	if got := registry.getCompletion(key.handle, key.overlapped, second.id); got != second {
		t.Fatal("current completion did not match its operation")
	}
}

func TestDirectorySnapshotDiffPairsHostRename(t *testing.T) {
	fs := vfs.New()
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "before.txt")
	if err := os.WriteFile(oldPath, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := directorySnapshot(fs, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(oldPath, filepath.Join(dir, "after.txt")); err != nil {
		t.Fatal(err)
	}
	after, err := directorySnapshot(fs, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	changes := diffDirectorySnapshots(before, after, fileNotifyChangeFileName)
	if len(changes) != 2 {
		t.Fatalf("rename produced %d changes", len(changes))
	}
	if changes[0].action != fileActionRenamedOldName || changes[0].name != "before.txt" {
		t.Fatalf("old rename record = %#v", changes[0])
	}
	if changes[1].action != fileActionRenamedNewName || changes[1].name != "after.txt" {
		t.Fatalf("new rename record = %#v", changes[1])
	}
}

func TestOverlappedRegistryCancellationIsScoped(t *testing.T) {
	registry := newOverlappedRegistry()
	first := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: 0x1000},
		11,
		0,
		0,
		nil,
		nil,
	)
	second := newOverlappedOperation(
		overlappedKey{handle: 0x200, overlapped: 0x2000},
		22,
		0,
		0,
		nil,
		nil,
	)
	if !registry.begin(first) || !registry.begin(second) {
		t.Fatal("failed to register operations")
	}
	if got := registry.cancel(0x200, 0, 11, true); got != 1 {
		t.Fatalf("CancelIo cancelled %d operations", got)
	}
	if first.pending() {
		t.Fatal("owner operation is still pending")
	}
	if !second.pending() {
		t.Fatal("foreign-thread operation was cancelled")
	}
	if got := registry.cancel(0x200, 0x2000, 0, false); got != 1 {
		t.Fatalf("CancelIoEx cancelled %d operations", got)
	}
	if status, _ := second.result(); status != overlappedStatusCancelled {
		t.Fatalf("cancelled status = %#x", status)
	}
}

func decodeNotifyName(data []byte) string {
	if len(data) < 12 {
		return ""
	}
	nameBytes := int(binary.LittleEndian.Uint32(data[8:12]))
	if nameBytes < 0 || 12+nameBytes > len(data) || nameBytes%2 != 0 {
		return ""
	}
	encoded := make([]uint16, nameBytes/2)
	for i := range encoded {
		encoded[i] = binary.LittleEndian.Uint16(data[12+i*2:])
	}
	return string(utf16.Decode(encoded))
}
