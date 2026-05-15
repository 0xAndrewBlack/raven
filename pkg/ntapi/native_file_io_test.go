//go:build guest_windows

package ntapi

import (
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntobj"
	"github.com/mirkobrombin/Raven/pkg/vfs"
)

const (
	nativeLockStart  = uint64(32)
	nativeLockLength = uint64(8)
	nativeLockKey    = uint32(0x44556677)
)

type nativeFileIOTestContext struct {
	*ioCompletionABITestContext
	manager       *FileLockManager
	identity      vfs.FileIdentity
	blocker       *FileHandle
	blockerHandle Handle
	pending       *FileHandle
	pendingHandle Handle
	port          *IoCompletionPortHandle
	completionKey uint64
	offsetAddress uint64
	lengthAddress uint64
}

type nativePendingLock struct {
	ioStatus    uint64
	event       *EventHandle
	eventHandle Handle
	apcContext  uint64
	operation   *nativeIOOperation
}

func newNativeFileIOTestContext(t *testing.T) *nativeFileIOTestContext {
	return newNativeFileIOTestContextMode(t, false)
}

func newNativeFileIOTestContextMode(
	t *testing.T,
	mode32 bool,
) *nativeFileIOTestContext {
	t.Helper()
	abi := newIoCompletionABITestContext(t, mode32)
	abi.ctx.FS = vfs.New()
	abi.ctx.State = &ProcessState{ThreadId: 1}

	blockerFD, err := abi.ctx.FS.Open(
		"/native-file-io-lock.txt",
		vfs.O_CREAT|vfs.O_RDWR,
	)
	if err != nil {
		t.Fatal(err)
	}
	pendingFD, err := abi.ctx.FS.Open(
		"/native-file-io-lock.txt",
		vfs.O_RDWR,
	)
	if err != nil {
		t.Fatal(err)
	}
	blocker := &FileHandle{
		FD:     blockerFD,
		Path:   "/native-file-io-lock.txt",
		Access: 0xC0000000,
	}
	pending := &FileHandle{
		FD:     pendingFD,
		Path:   "/native-file-io-lock.txt",
		Access: 0xC0000000,
		Flags:  0x40000000,
	}
	blockerHandle := abi.ctx.Handles.Alloc(blocker)
	pendingHandle := abi.ctx.Handles.Alloc(pending)
	identity, ok := abi.ctx.FS.FileIdentity(blockerFD)
	if !ok {
		t.Fatal("file identity unavailable")
	}
	manager := FileLocksFor(abi.ctx.FS)
	if !manager.LockKey(
		identity,
		blocker.LockOwner(),
		nativeLockStart,
		nativeLockLength,
		0,
		true,
		false,
	) {
		t.Fatal("blocking lock failed")
	}

	port := &IoCompletionPortHandle{}
	const completionKey = uint64(0x1122334455667788)
	if !pending.AssociateCompletion(port, completionKey) {
		t.Fatal("completion port association failed")
	}
	context := &nativeFileIOTestContext{
		ioCompletionABITestContext: abi,
		manager:                    manager,
		identity:                   identity,
		blocker:                    blocker,
		blockerHandle:              blockerHandle,
		pending:                    pending,
		pendingHandle:              pendingHandle,
		port:                       port,
		completionKey:              completionKey,
		offsetAddress:              abi.base + 0x100,
		lengthAddress:              abi.base + 0x108,
	}
	if err := abi.mem.Write64(context.offsetAddress, nativeLockStart); err != nil {
		t.Fatal(err)
	}
	if err := abi.mem.Write64(context.lengthAddress, nativeLockLength); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		CancelNativeIOForHandle(abi.ctx.Handles, pendingHandle)
		manager.ReleaseOwner(blocker.LockOwner())
		manager.ReleaseOwner(pending.LockOwner())
	})
	return context
}

func (context *nativeFileIOTestContext) startPendingLock(
	t *testing.T,
	threadID uint32,
	ioStatus, eventAddress, apcContext uint64,
) nativePendingLock {
	t.Helper()
	context.ctx.State.ThreadId = threadID
	event := NewEvent(true, true)
	eventHandle := context.ctx.Handles.Alloc(event)
	context.setArgs(
		t,
		uint64(context.pendingHandle),
		uint64(eventHandle),
		0,
		apcContext,
		ioStatus,
		context.offsetAddress,
		context.lengthAddress,
		uint64(nativeLockKey),
		0,
		1,
	)
	if status := handleNtLockFile(context.ctx); status != StatusPending {
		t.Fatalf("NtLockFile status = %#x, want %#x", status, StatusPending)
	}
	if event.PeekSignaled() {
		t.Fatal("pending NtLockFile left its event signaled")
	}
	nativeAssertIOStatus(t, context.mem, ioStatus, StatusPending, 0)
	operation := nativeFindOperation(t, context.ctx.Handles, ioStatus)
	return nativePendingLock{
		ioStatus:    ioStatus,
		event:       event,
		eventHandle: eventHandle,
		apcContext:  apcContext,
		operation:   operation,
	}
}

func nativeFindOperation(
	t *testing.T,
	handles *HandleTable,
	ioStatus uint64,
) *nativeIOOperation {
	t.Helper()
	registry := nativeIOFor(handles)
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for _, operation := range registry.byID {
		if operation.ioStatus == ioStatus {
			return operation
		}
	}
	t.Fatalf("native operation for IOSB %#x not found", ioStatus)
	return nil
}

func nativeOperationCount(handles *HandleTable) int {
	registry := nativeIOFor(handles)
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return len(registry.byID)
}

func nativeAwaitDone(t *testing.T, operation *nativeIOOperation) {
	t.Helper()
	select {
	case <-operation.done:
	case <-time.After(time.Second):
		t.Fatal("native operation did not complete")
	}
}

func nativeAwaitEvent(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal("native operation event was not signaled")
	}
}

func (context *nativeFileIOTestContext) startAsyncRegularFileIO(
	t *testing.T,
	write bool,
	threadID uint32,
	ioStatus, buffer, length, byteOffset uint64,
	apcRoutine, apcContext uint64,
) (nativePendingLock, <-chan struct{}) {
	t.Helper()
	context.ctx.State.ThreadId = threadID
	offsetAddress := context.base + 0x500
	if err := context.mem.Write64(offsetAddress, byteOffset); err != nil {
		t.Fatal(err)
	}
	event := NewEvent(true, false)
	eventHandle := context.ctx.Handles.Alloc(event)

	state := context.manager.stateFor(context.identity)
	state.mu.Lock()
	defer state.mu.Unlock()
	context.setArgs(
		t,
		uint64(context.pendingHandle),
		uint64(eventHandle),
		apcRoutine,
		apcContext,
		ioStatus,
		buffer,
		length,
		offsetAddress,
		0,
	)
	var status uint32
	if write {
		status = handleNtWriteFile(context.ctx)
	} else {
		status = handleNtReadFile(context.ctx)
	}
	if status != StatusPending {
		t.Fatalf(
			"asynchronous file handler status = %#x, want %#x",
			status,
			StatusPending,
		)
	}
	nativeAssertIOStatus(t, context.mem, ioStatus, StatusPending, 0)
	if event.PeekSignaled() {
		t.Fatal("pending file operation left its event signaled")
	}
	operation := nativeFindOperation(t, context.ctx.Handles, ioStatus)
	return nativePendingLock{
		ioStatus:    ioStatus,
		event:       event,
		eventHandle: eventHandle,
		apcContext:  apcContext,
		operation:   operation,
	}, event.WaitChan()
}

func nativeAssertIOStatus(
	t *testing.T,
	memory *mmu.MMU,
	address uint64,
	wantStatus uint32,
	wantInformation uint64,
) {
	t.Helper()
	status, err := memory.Read32(address)
	if err != nil {
		t.Fatal(err)
	}
	if status != wantStatus {
		t.Fatalf(
			"IOSB %#x status = %#x, want %#x",
			address,
			status,
			wantStatus,
		)
	}
	var information uint64
	if memory.Mode32 {
		value, readErr := memory.Read32(address + 4)
		if readErr != nil {
			t.Fatal(readErr)
		}
		information = uint64(value)
	} else {
		information, err = memory.Read64(address + 8)
		if err != nil {
			t.Fatal(err)
		}
	}
	if information != wantInformation {
		t.Fatalf(
			"IOSB %#x information = %#x, want %#x",
			address,
			information,
			wantInformation,
		)
	}
}

func nativeAssertCompletion(
	t *testing.T,
	context *nativeFileIOTestContext,
	pending nativePendingLock,
	wantStatus uint32,
) {
	t.Helper()
	nativeAssertCompletionWithInformation(
		t,
		context,
		pending,
		wantStatus,
		0,
	)
}

func nativeAssertCompletionWithInformation(
	t *testing.T,
	context *nativeFileIOTestContext,
	pending nativePendingLock,
	wantStatus uint32,
	wantInformation uint32,
) {
	t.Helper()
	packet, result := context.port.RemoveEx(0)
	if result != IoCompletionRemoved {
		t.Fatalf("IOCP remove result = %d", result)
	}
	if packet.CompletionKey != context.completionKey {
		t.Fatalf(
			"completion key = %#x, want %#x",
			packet.CompletionKey,
			context.completionKey,
		)
	}
	if packet.Overlapped != pending.apcContext {
		t.Fatalf(
			"APC context = %#x, want %#x",
			packet.Overlapped,
			pending.apcContext,
		)
	}
	if packet.Status != wantStatus {
		t.Fatalf("completion status = %#x, want %#x", packet.Status, wantStatus)
	}
	if packet.BytesTransferred != wantInformation {
		t.Fatalf(
			"completion information = %#x, want %#x",
			packet.BytesTransferred,
			wantInformation,
		)
	}
	if packet.FileHandle != context.pendingHandle {
		t.Fatalf(
			"completion file handle = %#x, want %#x",
			packet.FileHandle,
			context.pendingHandle,
		)
	}
	if packet.OperationID != pending.operation.id {
		t.Fatalf(
			"completion operation ID = %#x, want %#x",
			packet.OperationID,
			pending.operation.id,
		)
	}
}

func nativeAssertNoSecondCompletion(
	t *testing.T,
	port *IoCompletionPortHandle,
) {
	t.Helper()
	if _, result := port.RemoveEx(0); result != IoCompletionTimedOut {
		t.Fatalf("second IOCP remove result = %d", result)
	}
}

func (context *nativeFileIOTestContext) releaseBlockerAndAssertNoLeak(
	t *testing.T,
) {
	t.Helper()
	context.manager.ReleaseOwner(context.blocker.LockOwner())
	verifier := (&FileHandle{}).LockOwner()
	if !context.manager.LockKey(
		context.identity,
		verifier,
		nativeLockStart,
		nativeLockLength,
		nativeLockKey,
		true,
		false,
	) {
		t.Fatal("range remained locked after terminal cancellation")
	}
	if context.manager.UnlockKey(
		context.identity,
		context.pending.LockOwner(),
		nativeLockStart,
		nativeLockLength,
		nativeLockKey,
	) {
		t.Fatal("cancelled native operation leaked its range lock")
	}
	if !context.manager.UnlockKey(
		context.identity,
		verifier,
		nativeLockStart,
		nativeLockLength,
		nativeLockKey,
	) {
		t.Fatal("verifier lock cleanup failed")
	}
}

func TestNtReadFileAsyncRegularFilePE32AndPE64(t *testing.T) {
	for _, mode32 := range []bool{true, false} {
		name := "PE64"
		if mode32 {
			name = "PE32"
		}
		t.Run(name, func(t *testing.T) {
			context := newNativeFileIOTestContextMode(t, mode32)
			payload := []byte("raven")
			if _, err := context.ctx.FS.Pwrite(
				context.pending.FD,
				payload,
				0,
			); err != nil {
				t.Fatal(err)
			}
			ioStatus := context.base + 0x600
			buffer := context.base + 0x640
			if err := context.mem.WriteBytes(buffer, make([]byte, len(payload))); err != nil {
				t.Fatal(err)
			}
			pending, eventSignal := context.startAsyncRegularFileIO(
				t,
				false,
				601,
				ioStatus,
				buffer,
				uint64(len(payload)),
				0,
				0,
				0x1616,
			)

			nativeAwaitDone(t, pending.operation)
			nativeAwaitEvent(t, eventSignal)
			nativeAssertIOStatus(
				t,
				context.mem,
				ioStatus,
				StatusSuccess,
				uint64(len(payload)),
			)
			if !pending.event.PeekSignaled() {
				t.Fatal("completed NtReadFile did not signal its event")
			}
			nativeAssertCompletionWithInformation(
				t,
				context,
				pending,
				StatusSuccess,
				uint32(len(payload)),
			)
			nativeAssertNoSecondCompletion(t, context.port)
			got, err := context.mem.ReadBytes(buffer, len(payload))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(payload) {
				t.Fatalf("read buffer = %q, want %q", got, payload)
			}
			if count := nativeOperationCount(context.ctx.Handles); count != 0 {
				t.Fatalf("native operation registry contains %d entries", count)
			}
		})
	}
}

func TestNtWriteFileAsyncRegularFilePE32AndPE64(t *testing.T) {
	for _, mode32 := range []bool{true, false} {
		name := "PE64"
		if mode32 {
			name = "PE32"
		}
		t.Run(name, func(t *testing.T) {
			context := newNativeFileIOTestContextMode(t, mode32)
			payload := []byte("write")
			ioStatus := context.base + 0x700
			buffer := context.base + 0x740
			if err := context.mem.WriteBytes(buffer, payload); err != nil {
				t.Fatal(err)
			}
			pending, eventSignal := context.startAsyncRegularFileIO(
				t,
				true,
				701,
				ioStatus,
				buffer,
				uint64(len(payload)),
				0,
				0,
				0x1717,
			)

			nativeAwaitDone(t, pending.operation)
			nativeAwaitEvent(t, eventSignal)
			nativeAssertIOStatus(
				t,
				context.mem,
				ioStatus,
				StatusSuccess,
				uint64(len(payload)),
			)
			if !pending.event.PeekSignaled() {
				t.Fatal("completed NtWriteFile did not signal its event")
			}
			nativeAssertCompletionWithInformation(
				t,
				context,
				pending,
				StatusSuccess,
				uint32(len(payload)),
			)
			nativeAssertNoSecondCompletion(t, context.port)
			got := make([]byte, len(payload))
			n, err := context.ctx.FS.Pread(context.blocker.FD, got, 0)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(payload) || string(got) != string(payload) {
				t.Fatalf(
					"written file = %q (%d bytes), want %q (%d bytes)",
					got,
					n,
					payload,
					len(payload),
				)
			}
			if count := nativeOperationCount(context.ctx.Handles); count != 0 {
				t.Fatalf("native operation registry contains %d entries", count)
			}
		})
	}
}

func TestNtReadFileAsyncQueuesOneAPC(t *testing.T) {
	context := newNativeFileIOTestContextMode(t, false)
	payload := []byte("apc")
	if _, err := context.ctx.FS.Pwrite(context.pending.FD, payload, 0); err != nil {
		t.Fatal(err)
	}
	const threadID = uint64(0x7F001234)
	ObjMgr.DiscardAPCs(threadID)
	t.Cleanup(func() {
		ObjMgr.DiscardAPCs(threadID)
	})
	context.cpu.pc = 0x12345678
	context.cpu.result = 0x87654321
	ioStatus := context.base + 0x800
	buffer := context.base + 0x840
	apcRoutine := context.base + 0x1000
	const apcContext = uint64(0x1818)
	pending, eventSignal := context.startAsyncRegularFileIO(
		t,
		false,
		uint32(threadID),
		ioStatus,
		buffer,
		uint64(len(payload)),
		0,
		apcRoutine,
		apcContext,
	)

	nativeAwaitDone(t, pending.operation)
	nativeAwaitEvent(t, eventSignal)
	waitCode, callbacks := ObjMgr.WaitEx(
		nil,
		false,
		threadID,
		0,
		true,
	)
	if waitCode != ntobj.WaitIOCompletion {
		t.Fatalf(
			"alertable wait = %#x, want WAIT_IO_COMPLETION",
			waitCode,
		)
	}
	if len(callbacks) != 1 || callbacks[0] == nil {
		t.Fatalf("queued APC callback count = %d, want 1", len(callbacks))
	}
	callbacks[0] = nil
	callbacks = nil
	if context.cpu.pc != 0x12345678 || context.cpu.result != 0x87654321 {
		t.Fatal("guest APC routine executed while inspecting the queue")
	}
	secondCode, secondCallbacks := ObjMgr.WaitEx(
		nil,
		false,
		threadID,
		0,
		true,
	)
	if secondCode != ntobj.WaitTimeout || len(secondCallbacks) != 0 {
		t.Fatalf(
			"second alertable wait = %#x with %d callbacks",
			secondCode,
			len(secondCallbacks),
		)
	}
	nativeAssertIOStatus(
		t,
		context.mem,
		ioStatus,
		StatusSuccess,
		uint64(len(payload)),
	)
	nativeAssertCompletionWithInformation(
		t,
		context,
		pending,
		StatusSuccess,
		uint32(len(payload)),
	)
	nativeAssertNoSecondCompletion(t, context.port)
}

func TestNtAsyncRegularFileRejectsInvalidOffsets(t *testing.T) {
	maxInt64 := uint64(1<<63 - 1)
	offsets := []struct {
		name   string
		offset uint64
	}{
		{name: "HighBit", offset: uint64(1) << 63},
		{name: "MaxInt64PlusLength", offset: maxInt64},
	}
	operations := []struct {
		name  string
		write bool
	}{
		{name: "Read"},
		{name: "Write", write: true},
	}
	for _, mode32 := range []bool{true, false} {
		modeName := "PE64"
		if mode32 {
			modeName = "PE32"
		}
		for _, operation := range operations {
			for _, offset := range offsets {
				t.Run(
					modeName+"/"+operation.name+"/"+offset.name,
					func(t *testing.T) {
						context := newNativeFileIOTestContextMode(t, mode32)
						ioStatus := context.base + 0x900
						buffer := context.base + 0x940
						offsetAddress := context.base + 0x980
						if err := context.mem.Write8(buffer, 0x5A); err != nil {
							t.Fatal(err)
						}
						if err := context.mem.Write64(
							offsetAddress,
							offset.offset,
						); err != nil {
							t.Fatal(err)
						}
						event := NewEvent(true, false)
						eventHandle := context.ctx.Handles.Alloc(event)
						context.setArgs(
							t,
							uint64(context.pendingHandle),
							uint64(eventHandle),
							0,
							0x1919,
							ioStatus,
							buffer,
							1,
							offsetAddress,
							0,
						)
						state := context.manager.stateFor(context.identity)
						state.mu.Lock()
						var status uint32
						if operation.write {
							status = handleNtWriteFile(context.ctx)
						} else {
							status = handleNtReadFile(context.ctx)
						}
						ioStatusValue, statusErr := context.mem.Read32(ioStatus)
						informationAddress := ioStatus + 8
						if mode32 {
							informationAddress = ioStatus + 4
						}
						var information uint64
						var informationErr error
						if mode32 {
							var value uint32
							value, informationErr = context.mem.Read32(
								informationAddress,
							)
							information = uint64(value)
						} else {
							information, informationErr = context.mem.Read64(
								informationAddress,
							)
						}
						eventSignaled := event.PeekSignaled()
						operationCount := nativeOperationCount(
							context.ctx.Handles,
						)
						state.mu.Unlock()

						if status != StatusInvalidParameter {
							t.Errorf(
								"file handler status = %#x, want %#x",
								status,
								StatusInvalidParameter,
							)
						}
						if statusErr != nil {
							t.Error(statusErr)
						} else if ioStatusValue != StatusInvalidParameter {
							t.Errorf(
								"IOSB status = %#x, want %#x",
								ioStatusValue,
								StatusInvalidParameter,
							)
						}
						if informationErr != nil {
							t.Error(informationErr)
						} else if information != 0 {
							t.Errorf("IOSB information = %#x, want 0", information)
						}
						if eventSignaled {
							t.Error("invalid operation signaled its event")
						}
						if operationCount != 0 {
							t.Errorf(
								"invalid operation registered %d entries",
								operationCount,
							)
						}
						if status == StatusInvalidParameter &&
							operationCount == 0 {
							nativeAssertNoSecondCompletion(t, context.port)
						}
					},
				)
			}
		}
	}
}

func TestNtAsyncRegularFileRequiresExplicitOffsetPE32AndPE64(t *testing.T) {
	for _, mode32 := range []bool{true, false} {
		name := "PE64"
		if mode32 {
			name = "PE32"
		}
		t.Run(name, func(t *testing.T) {
			context := newNativeFileIOTestContextMode(t, mode32)
			for _, write := range []bool{false, true} {
				ioStatus := context.base + 0xA00
				buffer := context.base + 0xA40
				context.setArgs(
					t,
					uint64(context.pendingHandle),
					0,
					0,
					0,
					ioStatus,
					buffer,
					1,
					0,
					0,
				)
				var status uint32
				if write {
					status = handleNtWriteFile(context.ctx)
				} else {
					status = handleNtReadFile(context.ctx)
				}
				if status != StatusInvalidParameter {
					t.Fatalf(
						"write=%t status = %#x, want %#x",
						write,
						status,
						StatusInvalidParameter,
					)
				}
				nativeAssertIOStatus(
					t,
					context.mem,
					ioStatus,
					StatusInvalidParameter,
					0,
				)
				if count := nativeOperationCount(
					context.ctx.Handles,
				); count != 0 {
					t.Fatalf("write=%t registered %d operations", write, count)
				}
			}
		})
	}
}

func TestNtSynchronousFileOffsetsUpdateSharedPositionPE32AndPE64(t *testing.T) {
	for _, mode32 := range []bool{true, false} {
		name := "PE64"
		if mode32 {
			name = "PE32"
		}
		t.Run(name, func(t *testing.T) {
			context := newNativeFileIOTestContextMode(t, mode32)
			context.pending.Flags = 0
			context.pending.completion = nil
			if _, err := context.ctx.FS.Pwrite(
				context.pending.FD,
				[]byte("abcdef"),
				0,
			); err != nil {
				t.Fatal(err)
			}
			ioStatus := context.base + 0xB00
			buffer := context.base + 0xB40
			offsetAddress := context.base + 0xB80
			call := func(write bool, offset uint64, data []byte) {
				t.Helper()
				if err := context.mem.Write64(offsetAddress, offset); err != nil {
					t.Fatal(err)
				}
				if write {
					if err := context.mem.WriteBytes(buffer, data); err != nil {
						t.Fatal(err)
					}
				}
				context.setArgs(
					t,
					uint64(context.pendingHandle),
					0,
					0,
					0,
					ioStatus,
					buffer,
					uint64(len(data)),
					offsetAddress,
					0,
				)
				var status uint32
				if write {
					status = handleNtWriteFile(context.ctx)
				} else {
					status = handleNtReadFile(context.ctx)
				}
				if status != StatusSuccess {
					t.Fatalf(
						"write=%t offset=%#x status = %#x",
						write,
						offset,
						status,
					)
				}
			}

			call(false, 2, []byte{0, 0})
			read, err := context.mem.ReadBytes(buffer, 2)
			if err != nil || string(read) != "cd" {
				t.Fatalf("explicit read = %q, err=%v", read, err)
			}
			if position, err := context.ctx.FS.Lseek(
				context.pending.FD,
				0,
				1,
			); err != nil || position != 4 {
				t.Fatalf("position after explicit read = %d, err=%v", position, err)
			}

			call(true, nativeUseFilePointer, []byte("XY"))
			call(true, nativeWriteToEndOfFile, []byte("ZZ"))
			data := make([]byte, 8)
			n, err := context.ctx.FS.Pread(context.pending.FD, data, 0)
			if err != nil || n != len(data) || string(data) != "abcdXYZZ" {
				t.Fatalf("file data = %q (%d bytes), err=%v", data, n, err)
			}
			if position, err := context.ctx.FS.Lseek(
				context.pending.FD,
				0,
				1,
			); err != nil || position != 8 {
				t.Fatalf("final position = %d, err=%v", position, err)
			}
		})
	}
}

func TestNtCancelIoFileExCompletesPendingLock(t *testing.T) {
	context := newNativeFileIOTestContext(t)
	pending := context.startPendingLock(
		t,
		101,
		context.base+0x200,
		context.base+0x220,
		0xAABBCCDD,
	)
	cancelIOStatus := context.base + 0x240
	context.setArgs(
		t,
		uint64(context.pendingHandle),
		pending.ioStatus,
		cancelIOStatus,
	)

	if status := handleNtCancelIoFileEx(context.ctx); status != StatusSuccess {
		t.Fatalf("NtCancelIoFileEx status = %#x", status)
	}
	nativeAwaitDone(t, pending.operation)
	nativeAssertIOStatus(
		t,
		context.mem,
		pending.ioStatus,
		StatusCancelled,
		0,
	)
	nativeAssertIOStatus(t, context.mem, cancelIOStatus, StatusSuccess, 0)
	if !pending.event.PeekSignaled() {
		t.Fatal("cancelled NtLockFile did not signal its event")
	}
	nativeAssertCompletion(t, context, pending, StatusCancelled)
	nativeAssertNoSecondCompletion(t, context.port)
	if count := nativeOperationCount(context.ctx.Handles); count != 0 {
		t.Fatalf("native operation registry contains %d entries", count)
	}
	context.releaseBlockerAndAssertNoLeak(t)
}

func TestNtCancelIoFileOnlyCancelsCallingThread(t *testing.T) {
	context := newNativeFileIOTestContext(t)
	first := context.startPendingLock(
		t,
		201,
		context.base+0x280,
		context.base+0x2A0,
		0x1111,
	)
	second := context.startPendingLock(
		t,
		202,
		context.base+0x2C0,
		context.base+0x2E0,
		0x2222,
	)
	cancelIOStatus := context.base + 0x300
	context.ctx.State.ThreadId = 201
	context.setArgs(t, uint64(context.pendingHandle), cancelIOStatus)

	if status := handleNtCancelIoFile(context.ctx); status != StatusSuccess {
		t.Fatalf("NtCancelIoFile status = %#x", status)
	}
	nativeAwaitDone(t, first.operation)
	nativeAssertIOStatus(t, context.mem, first.ioStatus, StatusCancelled, 0)
	nativeAssertIOStatus(t, context.mem, cancelIOStatus, StatusSuccess, 0)
	if !first.event.PeekSignaled() {
		t.Fatal("calling thread operation event was not signaled")
	}
	nativeAssertIOStatus(t, context.mem, second.ioStatus, StatusPending, 0)
	if second.event.PeekSignaled() {
		t.Fatal("other thread operation event was signaled")
	}
	if count := nativeOperationCount(context.ctx.Handles); count != 1 {
		t.Fatalf("native operation registry contains %d entries, want 1", count)
	}
	if got := nativeFindOperation(
		t,
		context.ctx.Handles,
		second.ioStatus,
	); got != second.operation {
		t.Fatal("other thread operation was replaced")
	}

	context.ctx.State.ThreadId = 202
	context.setArgs(t, uint64(context.pendingHandle), cancelIOStatus)
	if status := handleNtCancelIoFile(context.ctx); status != StatusSuccess {
		t.Fatalf("second NtCancelIoFile status = %#x", status)
	}
	nativeAwaitDone(t, second.operation)
	nativeAssertIOStatus(t, context.mem, second.ioStatus, StatusCancelled, 0)
}

func TestNtCancelIoFileExRejectsUnmatchedIOSB(t *testing.T) {
	context := newNativeFileIOTestContext(t)
	pending := context.startPendingLock(
		t,
		301,
		context.base+0x320,
		context.base+0x340,
		0x3333,
	)
	unmatchedIOStatus := context.base + 0x360
	cancelIOStatus := context.base + 0x380
	context.setArgs(
		t,
		uint64(context.pendingHandle),
		unmatchedIOStatus,
		cancelIOStatus,
	)

	if status := handleNtCancelIoFileEx(context.ctx); status != StatusNotFound {
		t.Fatalf(
			"NtCancelIoFileEx status = %#x, want %#x",
			status,
			StatusNotFound,
		)
	}
	nativeAssertIOStatus(t, context.mem, cancelIOStatus, StatusNotFound, 0)
	nativeAssertIOStatus(t, context.mem, pending.ioStatus, StatusPending, 0)
	if pending.event.PeekSignaled() {
		t.Fatal("unmatched cancellation signaled the pending operation")
	}
	if count := nativeOperationCount(context.ctx.Handles); count != 1 {
		t.Fatalf("native operation registry contains %d entries, want 1", count)
	}
}

func TestNtCloseCancelsPendingNativeLock(t *testing.T) {
	context := newNativeFileIOTestContext(t)
	pending := context.startPendingLock(
		t,
		401,
		context.base+0x3A0,
		context.base+0x3C0,
		0x4444,
	)
	context.setArgs(t, uint64(context.pendingHandle))

	if status := handleNtClose(context.ctx); status != StatusSuccess {
		t.Fatalf("NtClose status = %#x", status)
	}
	nativeAwaitDone(t, pending.operation)
	if context.ctx.Handles.Get(context.pendingHandle) != nil {
		t.Fatal("NtClose left the file handle allocated")
	}
	nativeAssertIOStatus(t, context.mem, pending.ioStatus, StatusCancelled, 0)
	if !pending.event.PeekSignaled() {
		t.Fatal("NtClose cancellation did not signal the event")
	}
	nativeAssertCompletion(t, context, pending, StatusCancelled)
	nativeAssertNoSecondCompletion(t, context.port)
	if count := nativeOperationCount(context.ctx.Handles); count != 0 {
		t.Fatalf("native operation registry contains %d entries", count)
	}
	context.releaseBlockerAndAssertNoLeak(t)
}

func TestNtLockFileCancelVsGrantHasOneTerminalResult(t *testing.T) {
	context := newNativeFileIOTestContext(t)
	pending := context.startPendingLock(
		t,
		501,
		context.base+0x400,
		context.base+0x420,
		0x5555,
	)
	cancelIOStatus := context.base + 0x440
	context.setArgs(
		t,
		uint64(context.pendingHandle),
		pending.ioStatus,
		cancelIOStatus,
	)

	start := make(chan struct{})
	cancelResult := make(chan uint32, 1)
	releaseDone := make(chan struct{})
	go func() {
		<-start
		cancelResult <- handleNtCancelIoFileEx(context.ctx)
	}()
	go func() {
		<-start
		context.manager.ReleaseOwner(context.blocker.LockOwner())
		close(releaseDone)
	}()
	close(start)

	var cancelStatus uint32
	select {
	case cancelStatus = <-cancelResult:
	case <-time.After(time.Second):
		t.Fatal("NtCancelIoFileEx did not return")
	}
	select {
	case <-releaseDone:
	case <-time.After(time.Second):
		t.Fatal("blocking lock release did not return")
	}
	nativeAwaitDone(t, pending.operation)

	terminalStatus, err := context.mem.Read32(pending.ioStatus)
	if err != nil {
		t.Fatal(err)
	}
	switch terminalStatus {
	case StatusCancelled:
		if cancelStatus != StatusSuccess {
			t.Fatalf(
				"cancel status = %#x after cancellation, want %#x",
				cancelStatus,
				StatusSuccess,
			)
		}
		nativeAssertIOStatus(t, context.mem, cancelIOStatus, StatusSuccess, 0)
		if context.manager.UnlockKey(
			context.identity,
			context.pending.LockOwner(),
			nativeLockStart,
			nativeLockLength,
			nativeLockKey,
		) {
			t.Fatal("cancelled race outcome leaked its range lock")
		}
	case StatusSuccess:
		if cancelStatus != StatusNotFound && cancelStatus != StatusSuccess {
			t.Fatalf(
				"cancel status = %#x after grant",
				cancelStatus,
			)
		}
		nativeAssertIOStatus(t, context.mem, cancelIOStatus, cancelStatus, 0)
		if !context.manager.UnlockKey(
			context.identity,
			context.pending.LockOwner(),
			nativeLockStart,
			nativeLockLength,
			nativeLockKey,
		) {
			t.Fatal("granted race outcome did not own its range lock")
		}
	default:
		t.Fatalf("terminal IOSB status = %#x", terminalStatus)
	}
	if !pending.event.PeekSignaled() {
		t.Fatal("terminal race outcome did not signal the event")
	}
	nativeAssertCompletion(t, context, pending, terminalStatus)
	nativeAssertNoSecondCompletion(t, context.port)
	if count := nativeOperationCount(context.ctx.Handles); count != 0 {
		t.Fatalf("native operation registry contains %d entries", count)
	}

	verifier := (&FileHandle{}).LockOwner()
	if !context.manager.LockKey(
		context.identity,
		verifier,
		nativeLockStart,
		nativeLockLength,
		nativeLockKey,
		true,
		false,
	) {
		t.Fatal("cancel-vs-grant left the range locked")
	}
	if !context.manager.UnlockKey(
		context.identity,
		verifier,
		nativeLockStart,
		nativeLockLength,
		nativeLockKey,
	) {
		t.Fatal("verifier lock cleanup failed")
	}
}
