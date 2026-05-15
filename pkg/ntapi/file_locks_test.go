//go:build guest_windows

package ntapi

import (
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/vfs"
)

func testFileIdentity(inode uint64) vfs.FileIdentity {
	return vfs.FileIdentity{Inode: inode}
}

func TestFileLockManagerExclusiveRanges(t *testing.T) {
	manager := NewFileLockManager()
	identity := testFileIdentity(1)

	if !manager.Lock(identity, 1, 10, 20, true, false) {
		t.Fatal("initial exclusive lock failed")
	}
	if manager.Lock(identity, 2, 20, 1, false, false) {
		t.Fatal("overlapping shared lock from another owner succeeded")
	}
	if manager.Lock(identity, 1, 20, 1, true, false) {
		t.Fatal("overlapping exclusive lock from the same owner succeeded")
	}
	if !manager.Lock(identity, 2, 30, 5, true, false) {
		t.Fatal("adjacent exclusive lock failed")
	}
	if manager.CanRead(identity, 2, 10, 1) {
		t.Fatal("second owner can read an exclusive range")
	}
	if manager.CanWrite(identity, 2, 10, 1) {
		t.Fatal("second owner can write an exclusive range")
	}
	if !manager.CanRead(identity, 1, 10, 20) {
		t.Fatal("exclusive owner cannot read its range")
	}
	if !manager.CanWrite(identity, 1, 10, 20) {
		t.Fatal("exclusive owner cannot write its range")
	}
	if !manager.CanRead(identity, 2, 0, 10) || !manager.CanWrite(identity, 2, 0, 10) {
		t.Fatal("non-overlapping access was denied")
	}
}

func TestFileLockManagerSharedAndExactUnlock(t *testing.T) {
	manager := NewFileLockManager()
	identity := testFileIdentity(2)

	if !manager.Lock(identity, 1, 40, 8, true, false) {
		t.Fatal("exclusive lock failed")
	}
	if !manager.Lock(identity, 1, 40, 8, false, false) {
		t.Fatal("same-owner shared overlap failed")
	}
	if manager.Lock(identity, 2, 40, 8, false, false) {
		t.Fatal("shared lock overlapped another owner's exclusive lock")
	}
	if manager.CanWrite(identity, 1, 40, 8) {
		t.Fatal("shared lock did not deny its owner write access")
	}
	if manager.CanRead(identity, 2, 40, 8) {
		t.Fatal("second owner read through an exclusive lock")
	}
	if manager.Unlock(identity, 1, 40, 7) {
		t.Fatal("inexact unlock succeeded")
	}
	if !manager.Unlock(identity, 1, 40, 8) {
		t.Fatal("exclusive unlock failed")
	}
	if manager.CanWrite(identity, 1, 40, 8) {
		t.Fatal("shared lock disappeared with exclusive unlock")
	}
	if !manager.Lock(identity, 2, 40, 8, false, false) {
		t.Fatal("shared locks did not overlap")
	}
	if !manager.CanRead(identity, 2, 40, 8) {
		t.Fatal("shared owner cannot read the range")
	}
	if !manager.Unlock(identity, 1, 40, 8) {
		t.Fatal("shared unlock failed")
	}
	if manager.Unlock(identity, 1, 40, 8) {
		t.Fatal("third unlock succeeded")
	}
	if !manager.Unlock(identity, 2, 40, 8) {
		t.Fatal("second owner's shared unlock failed")
	}
}

func TestFileLockManagerBlockingAndRelease(t *testing.T) {
	manager := NewFileLockManager()
	identity := testFileIdentity(3)
	if !manager.Lock(identity, 1, 0, 16, true, false) {
		t.Fatal("initial lock failed")
	}

	acquired := make(chan bool, 1)
	go func() {
		acquired <- manager.Lock(identity, 2, 0, 16, true, true)
	}()
	select {
	case <-acquired:
		t.Fatal("blocking lock completed before release")
	case <-time.After(20 * time.Millisecond):
	}

	manager.ReleaseOwner(1)
	select {
	case ok := <-acquired:
		if !ok {
			t.Fatal("blocking lock failed after release")
		}
	case <-time.After(time.Second):
		t.Fatal("blocking lock was not awakened")
	}
}

func TestFileLockManagerBlockingCancellation(t *testing.T) {
	manager := NewFileLockManager()
	identity := testFileIdentity(4)
	if !manager.Lock(identity, 1, 0, 16, true, false) {
		t.Fatal("initial lock failed")
	}
	cancel := make(chan struct{})
	result := make(chan bool, 1)
	go func() {
		result <- manager.LockCancelable(identity, 2, 0, 16, true, true, cancel)
	}()
	close(cancel)
	select {
	case acquired := <-result:
		if acquired {
			t.Fatal("cancelled lock was acquired")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled lock did not return")
	}
}

func TestFileLocksForSharedAcrossHandleTables(t *testing.T) {
	fs := vfs.New()
	first := &TrapContext{FS: fs, Handles: NewHandleTable()}
	second := &TrapContext{FS: fs, Handles: NewHandleTable()}
	firstFile := &FileHandle{}
	secondFile := &FileHandle{}
	first.Handles.Alloc(firstFile)
	second.Handles.Alloc(secondFile)

	firstManager := FileLocksFor(first.FS)
	secondManager := FileLocksFor(second.FS)
	if firstManager != secondManager {
		t.Fatal("contexts sharing a VFS received different lock managers")
	}

	identity := testFileIdentity(40)
	if !firstManager.Lock(
		identity,
		firstFile.LockOwner(),
		0,
		16,
		true,
		false,
	) {
		t.Fatal("first process lock failed")
	}
	if secondManager.Lock(
		identity,
		secondFile.LockOwner(),
		0,
		16,
		true,
		false,
	) {
		t.Fatal("second process bypassed the shared lock manager")
	}
}

func TestFileLockManagerDistinctIdentityShardsDoNotBlock(t *testing.T) {
	manager := NewFileLockManager()
	firstIdentity := testFileIdentity(41)
	secondIdentity := testFileIdentity(42)
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan bool, 1)

	go func() {
		firstDone <- manager.WithWriteAccess(
			firstIdentity,
			1,
			0,
			1,
			func() {
				close(entered)
				<-release
			},
		)
	}()
	<-entered

	secondDone := make(chan bool, 1)
	go func() {
		secondDone <- manager.Lock(
			secondIdentity,
			2,
			0,
			1,
			true,
			false,
		)
	}()
	select {
	case acquired := <-secondDone:
		if !acquired {
			t.Fatal("lock on an independent identity failed")
		}
	case <-time.After(time.Second):
		t.Fatal("independent identity was blocked by another shard")
	}

	close(release)
	select {
	case allowed := <-firstDone:
		if !allowed {
			t.Fatal("first identity write access failed")
		}
	case <-time.After(time.Second):
		t.Fatal("first identity did not resume")
	}
}

func TestFileLockManagerUnlockRequiresExactKey(t *testing.T) {
	manager := NewFileLockManager()
	identity := testFileIdentity(43)
	const (
		owner = uint64(1)
		key   = uint32(0x12345678)
	)

	if !manager.LockKey(identity, owner, 8, 12, key, true, false) {
		t.Fatal("keyed lock failed")
	}
	if manager.UnlockKey(identity, owner, 8, 12, key+1) {
		t.Fatal("unlock with a different key succeeded")
	}
	if manager.LockKey(identity, 2, 8, 12, key, true, false) {
		t.Fatal("wrong-key unlock removed the lock")
	}
	if !manager.UnlockKey(identity, owner, 8, 12, key) {
		t.Fatal("unlock with the exact key failed")
	}
	if !manager.LockKey(identity, 2, 8, 12, key, true, false) {
		t.Fatal("range remained locked after exact-key unlock")
	}
}

func TestFileLockManagerRangeBoundariesDoNotWrap(t *testing.T) {
	const highBit = uint64(1) << 63
	max := ^uint64(0)
	tests := []struct {
		name                      string
		firstStart, firstLength   uint64
		secondStart, secondLength uint64
		overlap                   bool
	}{
		{
			name:         "high-bit overlap",
			firstStart:   highBit,
			firstLength:  16,
			secondStart:  highBit + 15,
			secondLength: 1,
			overlap:      true,
		},
		{
			name:         "high-bit adjacency",
			firstStart:   highBit,
			firstLength:  16,
			secondStart:  highBit + 16,
			secondLength: 1,
		},
		{
			name:         "halves are adjacent",
			firstStart:   0,
			firstLength:  highBit,
			secondStart:  highBit,
			secondLength: highBit,
		},
		{
			name:         "upper half reaches max",
			firstStart:   highBit,
			firstLength:  highBit,
			secondStart:  max,
			secondLength: 1,
			overlap:      true,
		},
		{
			name:         "max range does not wrap to zero",
			firstStart:   max,
			firstLength:  max,
			secondStart:  0,
			secondLength: 1,
		},
		{
			name:         "range ending before max",
			firstStart:   0,
			firstLength:  max,
			secondStart:  max,
			secondLength: 1,
		},
		{
			name:         "range includes byte before max",
			firstStart:   0,
			firstLength:  max,
			secondStart:  max - 1,
			secondLength: 1,
			overlap:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := fileRangesOverlap(
				test.firstStart,
				test.firstLength,
				test.secondStart,
				test.secondLength,
			); got != test.overlap {
				t.Fatalf("fileRangesOverlap() = %t, want %t", got, test.overlap)
			}
			if got := fileRangesOverlap(
				test.secondStart,
				test.secondLength,
				test.firstStart,
				test.firstLength,
			); got != test.overlap {
				t.Fatalf(
					"fileRangesOverlap() reversed = %t, want %t",
					got,
					test.overlap,
				)
			}
		})
	}

	manager := NewFileLockManager()
	identity := testFileIdentity(45)
	if !manager.Lock(identity, 1, highBit, highBit, true, false) {
		t.Fatal("upper-half lock failed")
	}
	if manager.Lock(identity, 2, max, 1, true, false) {
		t.Fatal("overlapping MaxUint64 byte lock succeeded")
	}
	if !manager.Lock(identity, 2, 0, highBit, true, false) {
		t.Fatal("adjacent lower-half lock conflicted")
	}
}

func TestFileLockManagerReleaseOwnerCancelsLateWaiter(t *testing.T) {
	manager := NewFileLockManager()
	identity := testFileIdentity(5)
	if !manager.Lock(identity, 1, 0, 16, true, false) {
		t.Fatal("initial lock failed")
	}

	start := make(chan struct{})
	result := make(chan bool, 1)
	go func() {
		<-start
		result <- manager.Lock(identity, 2, 0, 16, true, true)
	}()

	manager.ReleaseOwner(2)
	close(start)
	select {
	case acquired := <-result:
		if acquired {
			t.Fatal("released owner acquired a late-starting lock")
		}
	case <-time.After(time.Second):
		t.Fatal("late-starting waiter did not observe owner release")
	}
}

func TestFileRangeOverlapHandlesOverflow(t *testing.T) {
	max := ^uint64(0)
	if !fileRangesOverlap(max, 1, max, 1) {
		t.Fatal("last byte does not overlap itself")
	}
	if !fileRangesOverlap(max-3, 8, max, 1) {
		t.Fatal("overflowing interval did not overlap")
	}
	if fileRangesOverlap(0, 0, 0, 1) {
		t.Fatal("empty interval overlaps")
	}
}

func TestFileHandleLockOwnerSurvivesCopy(t *testing.T) {
	file := &FileHandle{}
	owner := file.LockOwner()
	copy := *file
	if copy.LockOwner() != owner {
		t.Fatal("copied file handle changed lock owner")
	}
}

func TestNtFileLockHandlersPE32AndPE64(t *testing.T) {
	for _, mode32 := range []bool{true, false} {
		name := "PE64"
		if mode32 {
			name = "PE32"
		}
		t.Run(name, func(t *testing.T) {
			tc := newIoCompletionABITestContext(t, mode32)
			tc.ctx.FS = vfs.New()
			firstFD, err := tc.ctx.FS.Open("/nt-lock.txt", vfs.O_CREAT|vfs.O_RDWR)
			if err != nil {
				t.Fatal(err)
			}
			secondFD, err := tc.ctx.FS.Open("/nt-lock.txt", vfs.O_RDWR)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tc.ctx.FS.Pwrite(firstFD, []byte("payload"), 0); err != nil {
				t.Fatal(err)
			}
			first := tc.ctx.Handles.Alloc(&FileHandle{
				FD: firstFD, Path: "/nt-lock.txt", Access: 0xC0000000,
			})
			second := tc.ctx.Handles.Alloc(&FileHandle{
				FD: secondFD, Path: "/nt-lock.txt", Access: 0xC0000000,
			})
			ioStatus := tc.base + 0x100
			offset := tc.base + 0x140
			length := tc.base + 0x150
			buffer := tc.base + 0x180
			if err := tc.mem.Write64(offset, 2); err != nil {
				t.Fatal(err)
			}
			if err := tc.mem.Write64(length, 3); err != nil {
				t.Fatal(err)
			}

			tc.setArgs(
				t,
				uint64(first),
				0,
				0,
				0,
				ioStatus,
				offset,
				length,
				0,
				1,
				1,
			)
			if status := handleNtLockFile(tc.ctx); status != StatusSuccess {
				t.Fatalf("first NtLockFile status = %#x", status)
			}
			tc.setArgs(
				t,
				uint64(second),
				0,
				0,
				0,
				ioStatus,
				offset,
				length,
				0,
				1,
				0,
			)
			if status := handleNtLockFile(tc.ctx); status != StatusLockNotGranted {
				t.Fatalf("conflicting NtLockFile status = %#x", status)
			}
			tc.setArgs(
				t,
				uint64(second),
				0,
				0,
				0,
				ioStatus,
				buffer,
				1,
				offset,
				0,
			)
			if status := handleNtReadFile(tc.ctx); status != StatusFileLockConflict {
				t.Fatalf("locked NtReadFile status = %#x", status)
			}
			tc.setArgs(
				t,
				uint64(first),
				0,
				0,
				0,
				ioStatus,
				buffer,
				1,
				offset,
				0,
			)
			if status := handleNtWriteFile(tc.ctx); status != StatusSuccess {
				t.Fatalf("owner NtWriteFile status = %#x", status)
			}
			tc.setArgs(t, uint64(first), ioStatus, offset, length, 0)
			if status := handleNtUnlockFile(tc.ctx); status != StatusSuccess {
				t.Fatalf("NtUnlockFile status = %#x", status)
			}
			if status := handleNtUnlockFile(tc.ctx); status != StatusRangeNotLocked {
				t.Fatalf("second NtUnlockFile status = %#x", status)
			}
		})
	}
}
