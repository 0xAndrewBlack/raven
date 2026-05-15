//go:build guest_windows

package main

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func writeKernel32TestString(t *testing.T, mem *mmu.MMU, value string, wide bool) uint64 {
	t.Helper()
	size := uint64(len(value) + 1)
	if wide {
		size *= 2
	}
	address := mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
	if wide {
		for index, char := range utf16Encode(value) {
			if err := mem.Write16(address+uint64(index)*2, char); err != nil {
				t.Fatal(err)
			}
		}
		if err := mem.Write16(address+uint64(len(utf16Encode(value)))*2, 0); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := mem.WriteBytes(address, append([]byte(value), 0)); err != nil {
			t.Fatal(err)
		}
	}
	return address
}

func kernel32TestLastError(t *testing.T, hctx *HandlerCtx, mem *mmu.MMU, is32 bool) uint32 {
	t.Helper()
	offset := uint64(ntapi.TebLastErrorValue)
	if is32 {
		offset = ntapi.Teb32LastErrorValue
	}
	value, err := mem.Read32(hctx.ProcState.TEBAddr + offset)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestNormalizeWin32ReadResult(t *testing.T) {
	tests := []struct {
		name    string
		n       int
		err     error
		wantN   int
		wantErr error
	}{
		{name: "eof", err: io.EOF},
		{name: "partial eof", n: 23, err: io.EOF, wantN: 23},
		{name: "success", n: 7, wantN: 7},
		{name: "failure", err: io.ErrUnexpectedEOF, wantErr: io.ErrUnexpectedEOF},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotN, gotErr := normalizeWin32ReadResult(tc.n, tc.err)
			if gotN != tc.wantN {
				t.Fatalf("byte count = %d, want %d", gotN, tc.wantN)
			}
			if !errors.Is(gotErr, tc.wantErr) {
				t.Fatalf("error = %v, want %v", gotErr, tc.wantErr)
			}
		})
	}
}

func TestFlushFileBuffersRejectsInvalidAndReadOnlyHandles(t *testing.T) {
	hctx, mem, _ := newToolbarDispatchTestContext(t)
	kernel32 := hctx.SynthByName["kernel32.dll"]
	call := func(handle uint64) uint64 {
		return callSubclassTestExport(t, hctx.Disp, kernel32, mem, false, "FlushFileBuffers", handle)
	}
	lastError := func() uint32 {
		value, err := mem.Read32(hctx.ProcState.TEBAddr + ntapi.TebLastErrorValue)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}

	if result := call(0xDEADBEEF); result != 0 {
		t.Fatalf("FlushFileBuffers(invalid) = %d, want 0", result)
	}
	if value := lastError(); value != 6 {
		t.Fatalf("FlushFileBuffers(invalid) LastError = %d, want 6", value)
	}

	handle := hctx.Handles.Alloc(&ntapi.FileHandle{
		FD: -1, Path: "/read-only.txt", Access: 0x80000000,
	})
	if result := call(uint64(handle)); result != 0 {
		t.Fatalf("FlushFileBuffers(read-only) = %d, want 0", result)
	}
	if value := lastError(); value != 5 {
		t.Fatalf("FlushFileBuffers(read-only) LastError = %d, want 5", value)
	}
}

func TestCreateFileReadWriteAccessPE32AndPE64(t *testing.T) {
	for _, test := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			hctx, mem, _ := newToolbarDispatchTestContext(t)
			hctx.ProcState.Is32 = test.is32
			mem.Mode32 = test.is32
			kernel32 := hctx.SynthByName["kernel32.dll"]
			call := func(name string, args ...uint64) uint64 {
				return callSubclassTestExport(t, hctx.Disp, kernel32, mem, test.is32, name, args...)
			}
			path := writeKernel32TestString(t, mem, `C:\tmp\access-`+test.name+`.txt`, true)
			data := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
			if err := mem.WriteBytes(data, []byte("original")); err != nil {
				t.Fatal(err)
			}
			byteCount := data + 0x100

			handle := call("CreateFileW", path, 0xC0000000, 0, 0, 2, 0, 0)
			if handle == 0 || handle == 0xFFFFFFFF || handle == 0xFFFFFFFFFFFFFFFF {
				t.Fatalf("CreateFileW(CREATE_ALWAYS) = %#x", handle)
			}
			if result := call("WriteFile", handle, data, 8, byteCount, 0); result != 1 {
				t.Fatalf("WriteFile(read/write) = %d, LastError=%d", result, kernel32TestLastError(t, hctx, mem, test.is32))
			}
			call("CloseHandle", handle)

			for _, denied := range []struct {
				name        string
				export      string
				path        uint64
				disposition uint64
			}{
				{name: "CreateFileW CREATE_ALWAYS", export: "CreateFileW", path: path, disposition: 2},
				{
					name:        "CreateFileA TRUNCATE_EXISTING",
					export:      "CreateFileA",
					path:        writeKernel32TestString(t, mem, `C:\tmp\access-`+test.name+`.txt`, false),
					disposition: 5,
				},
			} {
				result := call(denied.export, denied.path, 0x80000000, 0, 0, denied.disposition, 0, 0)
				if result != 0xFFFFFFFF && result != 0xFFFFFFFFFFFFFFFF {
					t.Fatalf("%s = %#x, want INVALID_HANDLE_VALUE", denied.name, result)
				}
				if value := kernel32TestLastError(t, hctx, mem, test.is32); value != 5 {
					t.Fatalf("%s LastError = %d, want 5", denied.name, value)
				}
			}

			readOnly := call("CreateFileW", path, 0x80000000, 0, 0, 3, 0, 0)
			if fh := hctx.Handles.GetFile(ntapi.Handle(readOnly)); fh == nil || fh.Access != 0x80000000 {
				t.Fatalf("read-only handle = %#x, object=%+v", readOnly, fh)
			}
			if result := call("WriteFile", readOnly, data, 8, byteCount, 0); result != 0 {
				t.Fatalf("WriteFile(read-only) = %d, want 0", result)
			}
			if value := kernel32TestLastError(t, hctx, mem, test.is32); value != 5 {
				t.Fatalf("WriteFile(read-only) LastError = %d, want 5", value)
			}
			if value, err := mem.Read32(byteCount); err != nil || value != 0 {
				t.Fatalf("WriteFile(read-only) bytes written = %d, err=%v", value, err)
			}
			if result := call("ReadFile", readOnly, data+0x200, 8, byteCount, 0); result != 1 {
				t.Fatalf("ReadFile(read-only) = %d, LastError=%d", result, kernel32TestLastError(t, hctx, mem, test.is32))
			}
			got, err := mem.ReadBytes(data+0x200, 8)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "original" {
				t.Fatalf("file contents = %q, want original", got)
			}
			call("CloseHandle", readOnly)

			writeOnly := call("CreateFileW", path, 0x40000000, 0, 0, 3, 0, 0)
			if fh := hctx.Handles.GetFile(ntapi.Handle(writeOnly)); fh == nil || fh.Access != 0x40000000 {
				t.Fatalf("write-only handle = %#x, object=%+v", writeOnly, fh)
			}
			if result := call("ReadFile", writeOnly, data+0x200, 8, byteCount, 0); result != 0 {
				t.Fatalf("ReadFile(write-only) = %d, want 0", result)
			}
			if value := kernel32TestLastError(t, hctx, mem, test.is32); value != 5 {
				t.Fatalf("ReadFile(write-only) LastError = %d, want 5", value)
			}
			if value, err := mem.Read32(byteCount); err != nil || value != 0 {
				t.Fatalf("ReadFile(write-only) bytes read = %d, err=%v", value, err)
			}
			call("CloseHandle", writeOnly)

			specificWrite := call("CreateFileW", path, 0x00000002, 0, 0, 3, 0, 0)
			if result := call("WriteFile", specificWrite, data, 8, byteCount, 0); result != 1 {
				t.Fatalf("WriteFile(FILE_WRITE_DATA) = %d, LastError=%d", result, kernel32TestLastError(t, hctx, mem, test.is32))
			}
			call("CloseHandle", specificWrite)

			specificRead := call("CreateFileW", path, 0x00000001, 0, 0, 3, 0, 0)
			if result := call("ReadFile", specificRead, data+0x200, 8, byteCount, 0); result != 1 {
				t.Fatalf("ReadFile(FILE_READ_DATA) = %d, LastError=%d", result, kernel32TestLastError(t, hctx, mem, test.is32))
			}
			call("CloseHandle", specificRead)

			ansiPath := writeKernel32TestString(t, mem, `C:\tmp\access-`+test.name+`.txt`, false)
			specificANSIWrite := call("CreateFileA", ansiPath, 0x00000002, 0, 0, 3, 0, 0)
			if result := call("WriteFile", specificANSIWrite, data, 8, byteCount, 0); result != 1 {
				t.Fatalf("WriteFile(CreateFileA FILE_WRITE_DATA) = %d, LastError=%d", result, kernel32TestLastError(t, hctx, mem, test.is32))
			}
			call("CloseHandle", specificANSIWrite)

			appendRead := call("CreateFileW", path, 0x00000005, 0, 0, 3, 0, 0)
			if result := call("WriteFile", appendRead, data, 1, byteCount, 0); result != 1 {
				t.Fatalf("WriteFile(FILE_READ_DATA|FILE_APPEND_DATA) = %d, LastError=%d", result, kernel32TestLastError(t, hctx, mem, test.is32))
			}
			call("CloseHandle", appendRead)
			verifyAppend := call("CreateFileW", path, 0x00000001, 0, 0, 3, 0, 0)
			if result := call("ReadFile", verifyAppend, data+0x200, 9, byteCount, 0); result != 1 {
				t.Fatalf("ReadFile(append result) = %d", result)
			}
			appended, err := mem.ReadBytes(data+0x200, 9)
			if err != nil {
				t.Fatal(err)
			}
			if string(appended) != "originalo" {
				t.Fatalf("append-only contents = %q, want originalo", appended)
			}
			call("CloseHandle", verifyAppend)
		})
	}
}

func TestLegacyFileAPIsTrackAccess(t *testing.T) {
	hctx, mem, _ := newToolbarDispatchTestContext(t)
	kernel32 := hctx.SynthByName["kernel32.dll"]
	call := func(name string, args ...uint64) uint64 {
		return callSubclassTestExport(t, hctx.Disp, kernel32, mem, false, name, args...)
	}
	path := writeKernel32TestString(t, mem, `C:\tmp\legacy-access.txt`, false)

	created := call("_lcreat", path, 0)
	if fh := hctx.Handles.GetFile(ntapi.Handle(created)); fh == nil || fh.Access != 0xC0000000 {
		t.Fatalf("_lcreat handle = %#x, object=%+v", created, fh)
	}
	if result := call("_lclose", created); result != 0 {
		t.Fatalf("_lclose(_lcreat) = %#x", result)
	}

	for _, test := range []struct {
		name       string
		mode       uint64
		wantAccess uint32
	}{
		{name: "read", mode: 0, wantAccess: 0x80000000},
		{name: "write", mode: 1, wantAccess: 0x40000000},
		{name: "read-write", mode: 2, wantAccess: 0xC0000000},
	} {
		t.Run(test.name, func(t *testing.T) {
			handle := call("_lopen", path, test.mode)
			if fh := hctx.Handles.GetFile(ntapi.Handle(handle)); fh == nil || fh.Access != test.wantAccess {
				t.Fatalf("_lopen handle = %#x, object=%+v, want access %#x", handle, fh, test.wantAccess)
			}
			if result := call("_lclose", handle); result != 0 {
				t.Fatalf("_lclose(_lopen) = %#x", result)
			}
		})
	}
}

func TestFileByteRangeLocksPE32AndPE64(t *testing.T) {
	for _, test := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			hctx, mem, _ := newToolbarDispatchTestContext(t)
			hctx.ProcState.Is32 = test.is32
			mem.Mode32 = test.is32
			kernel32 := hctx.SynthByName["kernel32.dll"]
			call := func(name string, args ...uint64) uint64 {
				return callSubclassTestExport(
					t,
					hctx.Disp,
					kernel32,
					mem,
					test.is32,
					name,
					args...,
				)
			}
			lastError := func() uint32 {
				return kernel32TestLastError(t, hctx, mem, test.is32)
			}
			path := writeKernel32TestString(
				t,
				mem,
				`C:\tmp\range-lock-`+test.name+`.txt`,
				true,
			)
			data := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
			if err := mem.WriteBytes(data, []byte("abcdefghijklmnop")); err != nil {
				t.Fatal(err)
			}
			count := data + 0x100

			first := call("CreateFileW", path, 0xC0000000, 0, 0, 2, 0, 0)
			second := call("CreateFileW", path, 0xC0000000, 0, 0, 3, 0, 0)
			if first == 0 || second == 0 ||
				first == 0xFFFFFFFFFFFFFFFF || second == 0xFFFFFFFFFFFFFFFF {
				t.Fatalf("CreateFileW handles = %#x, %#x", first, second)
			}
			if result := call("WriteFile", first, data, 16, count, 0); result != 1 {
				t.Fatalf("initial WriteFile = %d, LastError=%d", result, lastError())
			}
			if result := call("LockFile", first, 4, 0, 4, 0); result != 1 {
				t.Fatalf("LockFile = %d, LastError=%d", result, lastError())
			}
			if result := call("SetFilePointerEx", second, 0, 0, 0); result != 1 {
				t.Fatal("SetFilePointerEx(non-overlap) failed")
			}
			if result := call("ReadFile", second, data+0x200, 4, count, 0); result != 1 {
				t.Fatalf("non-overlapping ReadFile = %d, LastError=%d", result, lastError())
			}
			if result := call("SetFilePointerEx", second, 4, 0, 0); result != 1 {
				t.Fatal("SetFilePointerEx(overlap read) failed")
			}
			if result := call("ReadFile", second, data+0x200, 1, count, 0); result != 0 {
				t.Fatalf("locked ReadFile = %d, want 0", result)
			}
			if value := lastError(); value != 33 {
				t.Fatalf("locked ReadFile LastError = %d, want 33", value)
			}
			if result := call("SetFilePointerEx", second, 4, 0, 0); result != 1 {
				t.Fatal("SetFilePointerEx(overlap write) failed")
			}
			if result := call("WriteFile", second, data, 1, count, 0); result != 0 {
				t.Fatalf("locked WriteFile = %d, want 0", result)
			}
			if value := lastError(); value != 33 {
				t.Fatalf("locked WriteFile LastError = %d, want 33", value)
			}
			if result := call("SetFilePointerEx", first, 4, 0, 0); result != 1 {
				t.Fatal("SetFilePointerEx(owner) failed")
			}
			if result := call("WriteFile", first, data, 1, count, 0); result != 1 {
				t.Fatalf("owner WriteFile = %d, LastError=%d", result, lastError())
			}
			if result := call("LockFile", first, 6, 0, 2, 0); result != 0 {
				t.Fatalf("same-owner overlapping LockFile = %d, want 0", result)
			}
			if value := lastError(); value != 33 {
				t.Fatalf("overlapping LockFile LastError = %d, want 33", value)
			}
			if result := call("UnlockFile", first, 4, 0, 3, 0); result != 0 {
				t.Fatalf("inexact UnlockFile = %d, want 0", result)
			}
			if value := lastError(); value != 158 {
				t.Fatalf("inexact UnlockFile LastError = %d, want 158", value)
			}
			if result := call("UnlockFile", first, 4, 0, 4, 0); result != 1 {
				t.Fatalf("UnlockFile = %d, LastError=%d", result, lastError())
			}

			overlappedSize := uint64(32)
			if test.is32 {
				overlappedSize = 20
			}
			guarded := mem.Mmap(0, overlappedSize+16, mmu.PermRead|mmu.PermWrite)
			if err := mem.WriteBytes(guarded, make([]byte, overlappedSize+16)); err != nil {
				t.Fatal(err)
			}
			overlapped := guarded + 8
			if err := mem.Write8(overlapped-1, 0xCC); err != nil {
				t.Fatal(err)
			}
			if err := mem.Write8(overlapped+overlappedSize, 0xCC); err != nil {
				t.Fatal(err)
			}
			layout := guestOverlappedLayout(test.is32)
			if err := mem.Write32(overlapped+layout.offset, 8); err != nil {
				t.Fatal(err)
			}
			if result := call("LockFileEx", first, 1, 0, 4, 0, overlapped); result != 1 {
				t.Fatalf("shared LockFileEx = %d, LastError=%d", result, lastError())
			}
			if result := call("SetFilePointerEx", second, 8, 0, 0); result != 1 {
				t.Fatal("SetFilePointerEx(shared read) failed")
			}
			if result := call("ReadFile", second, data+0x200, 1, count, 0); result != 1 {
				t.Fatalf("shared ReadFile = %d, LastError=%d", result, lastError())
			}
			for _, handle := range []uint64{first, second} {
				if result := call("SetFilePointerEx", handle, 8, 0, 0); result != 1 {
					t.Fatal("SetFilePointerEx(shared write) failed")
				}
				if result := call("WriteFile", handle, data, 1, count, 0); result != 0 {
					t.Fatalf("shared WriteFile(%#x) = %d, want 0", handle, result)
				}
				if value := lastError(); value != 33 {
					t.Fatalf("shared WriteFile LastError = %d, want 33", value)
				}
			}
			if result := call("UnlockFileEx", first, 0, 4, 0, overlapped); result != 1 {
				t.Fatalf("UnlockFileEx = %d, LastError=%d", result, lastError())
			}
			before, _ := mem.Read8(overlapped - 1)
			after, _ := mem.Read8(overlapped + overlappedSize)
			if before != 0xCC || after != 0xCC {
				t.Fatalf("OVERLAPPED guard bytes = %#x, %#x", before, after)
			}

			if result := call("LockFile", first, 3, 1, 2, 0); result != 1 {
				t.Fatalf("high-offset LockFile = %d, LastError=%d", result, lastError())
			}
			if result := call("LockFile", second, 4, 1, 1, 0); result != 0 {
				t.Fatalf("high-offset conflicting LockFile = %d, want 0", result)
			}
			if value := lastError(); value != 33 {
				t.Fatalf("high-offset LockFile LastError = %d, want 33", value)
			}
			if result := call("UnlockFile", first, 3, 1, 2, 0); result != 1 {
				t.Fatalf("high-offset UnlockFile = %d", result)
			}

			if result := call("LockFile", first, 12, 0, 2, 0); result != 1 {
				t.Fatalf("close-release LockFile = %d", result)
			}
			if result := call("CloseHandle", first); result != 1 {
				t.Fatalf("CloseHandle(first) = %d", result)
			}
			if result := call("LockFile", second, 12, 0, 2, 0); result != 1 {
				t.Fatalf("LockFile after close = %d, LastError=%d", result, lastError())
			}
			if result := call("UnlockFile", second, 12, 0, 2, 0); result != 1 {
				t.Fatalf("UnlockFile(second) = %d", result)
			}
			if result := call("CloseHandle", second); result != 1 {
				t.Fatalf("CloseHandle(second) = %d", result)
			}

			specific := call("CreateFileW", path, 0x00000003, 0, 0, 3, 0, 0)
			if result := call("LockFile", specific, 0, 0, 1, 0); result != 0 {
				t.Fatalf("LockFile(specific access) = %d, want 0", result)
			}
			if value := lastError(); value != 5 {
				t.Fatalf("LockFile(specific access) LastError = %d, want 5", value)
			}
			call("CloseHandle", specific)

			if result := call("LockFile", 0xDEADBEEF, 0, 0, 1, 0); result != 0 {
				t.Fatalf("LockFile(invalid) = %d, want 0", result)
			}
			if value := lastError(); value != 6 {
				t.Fatalf("LockFile(invalid) LastError = %d, want 6", value)
			}
		})
	}
}

func TestLockFileExAsyncCompletionPE32AndPE64(t *testing.T) {
	for _, test := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			hctx, mem, _ := newToolbarDispatchTestContext(t)
			hctx.ProcState.Is32 = test.is32
			mem.Mode32 = test.is32
			kernel32 := hctx.SynthByName["kernel32.dll"]
			call := func(name string, args ...uint64) uint64 {
				return callSubclassTestExport(
					t,
					hctx.Disp,
					kernel32,
					mem,
					test.is32,
					name,
					args...,
				)
			}
			path := writeKernel32TestString(
				t,
				mem,
				`C:\tmp\async-range-lock-`+test.name+`.txt`,
				true,
			)
			first := call("CreateFileW", path, 0xC0000000, 0, 0, 2, 0, 0)
			second := call("CreateFileW", path, 0xC0000000, 0, 0, 3, 0x40000000, 0)
			if result := call("LockFile", first, 0, 0, 8, 0); result != 1 {
				t.Fatalf("LockFile = %d", result)
			}
			event := call("CreateEventW", 0, 1, 0, 0)
			overlappedSize := uint64(32)
			if test.is32 {
				overlappedSize = 20
			}
			overlapped := mem.Mmap(0, overlappedSize, mmu.PermRead|mmu.PermWrite)
			layout := guestOverlappedLayout(test.is32)
			layout.writePointer(mem, overlapped+layout.event, event)

			if result := call("LockFileEx", second, 2, 0, 8, 0, overlapped); result != 0 {
				t.Fatalf("pending LockFileEx = %d, want 0", result)
			}
			if value := kernel32TestLastError(t, hctx, mem, test.is32); value != 997 {
				t.Fatalf("pending LockFileEx LastError = %d, want 997", value)
			}
			if status := uint32(layout.readPointer(mem, overlapped+layout.internal)); status != overlappedStatusPending {
				t.Fatalf("pending status = %#x, want %#x", status, overlappedStatusPending)
			}
			if result := call("UnlockFile", first, 0, 0, 8, 0); result != 1 {
				t.Fatalf("UnlockFile(first) = %d", result)
			}
			completionEvent := hctx.Handles.GetEvent(ntapi.Handle(event))
			if completionEvent == nil {
				t.Fatal("completion event handle is invalid")
			}
			deadline := time.Now().Add(time.Second)
			for !completionEvent.IsSignaled() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if status := uint32(layout.readPointer(mem, overlapped+layout.internal)); status != overlappedStatusSuccess {
				t.Fatalf("completed status = %#x, want success", status)
			}
			if !completionEvent.IsSignaled() {
				t.Fatal("completion event was not signaled")
			}
			if result := call("UnlockFileEx", second, 0, 8, 0, overlapped); result != 1 {
				t.Fatalf("UnlockFileEx(second) = %d", result)
			}
			call("CloseHandle", uint64(event))
			call("CloseHandle", first)
			call("CloseHandle", second)
		})
	}
}

func TestOverlappedLockConflictDoesNotSignalOrPostPE32AndPE64(t *testing.T) {
	for _, test := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			hctx, mem, _ := newToolbarDispatchTestContext(t)
			hctx.ProcState.Is32 = test.is32
			mem.Mode32 = test.is32
			kernel32 := hctx.SynthByName["kernel32.dll"]
			call := func(name string, args ...uint64) uint64 {
				return callSubclassTestExport(
					t,
					hctx.Disp,
					kernel32,
					mem,
					test.is32,
					name,
					args...,
				)
			}
			path := writeKernel32TestString(
				t,
				mem,
				`C:\tmp\sync-lock-conflict-`+test.name+`.txt`,
				true,
			)
			first := call("CreateFileW", path, 0xC0000000, 0, 0, 2, 0, 0)
			second := call(
				"CreateFileW",
				path,
				0xC0000000,
				0,
				0,
				3,
				0x40000000,
				0,
			)
			if result := call("LockFile", first, 0, 0, 8, 0); result != 1 {
				t.Fatalf("LockFile = %d", result)
			}
			file := hctx.Handles.GetFile(ntapi.Handle(second))
			port := &ntapi.IoCompletionPortHandle{}
			if file == nil || !file.AssociateCompletion(port, 0xA55A) {
				t.Fatal("failed to associate completion port")
			}
			eventObject := ntapi.NewEvent(true, true)
			event := hctx.Handles.Alloc(eventObject)
			overlappedSize := uint64(32)
			if test.is32 {
				overlappedSize = 20
			}
			overlapped := mem.Mmap(
				0,
				overlappedSize,
				mmu.PermRead|mmu.PermWrite,
			)
			layout := guestOverlappedLayout(test.is32)
			layout.writePointer(mem, overlapped+layout.event, uint64(event))
			buffer := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
			if err := mem.WriteBytes(buffer, []byte("data")); err != nil {
				t.Fatal(err)
			}

			for _, operation := range []string{"ReadFile", "WriteFile"} {
				eventObject.Set()
				if result := call(
					operation,
					second,
					buffer,
					4,
					buffer+0x100,
					overlapped,
				); result != 0 {
					t.Fatalf("%s = %d, want FALSE", operation, result)
				}
				if value := kernel32TestLastError(
					t,
					hctx,
					mem,
					test.is32,
				); value != 33 {
					t.Fatalf("%s LastError = %d, want 33", operation, value)
				}
				if eventObject.IsSignaled() {
					t.Fatalf("%s signaled the event", operation)
				}
				if packet, ok := port.Remove(0); ok {
					t.Fatalf("%s posted IOCP packet %+v", operation, packet)
				}
			}

			call("UnlockFile", first, 0, 0, 8, 0)
			call("CloseHandle", uint64(event))
			call("CloseHandle", first)
			call("CloseHandle", second)
		})
	}
}

func TestOverlappedFileOffsetOverflowPE32AndPE64(t *testing.T) {
	for _, test := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			hctx, mem, _ := newToolbarDispatchTestContext(t)
			hctx.ProcState.Is32 = test.is32
			mem.Mode32 = test.is32
			kernel32 := hctx.SynthByName["kernel32.dll"]
			call := func(name string, args ...uint64) uint64 {
				return callSubclassTestExport(
					t,
					hctx.Disp,
					kernel32,
					mem,
					test.is32,
					name,
					args...,
				)
			}
			path := writeKernel32TestString(
				t,
				mem,
				`C:\tmp\offset-overflow-`+test.name+`.txt`,
				true,
			)
			handle := call(
				"CreateFileW",
				path,
				0xC0000000,
				0,
				0,
				2,
				0x40000000,
				0,
			)
			overlappedSize := uint64(32)
			if test.is32 {
				overlappedSize = 20
			}
			overlapped := mem.Mmap(
				0,
				overlappedSize,
				mmu.PermRead|mmu.PermWrite,
			)
			buffer := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
			layout := guestOverlappedLayout(test.is32)

			for _, offset := range []uint64{1 << 63, 1<<63 - 1} {
				mem.Write32(overlapped+layout.offset, uint32(offset))
				mem.Write32(
					overlapped+layout.offsetHigh,
					uint32(offset>>32),
				)
				for _, operation := range []string{"ReadFile", "WriteFile"} {
					if result := call(
						operation,
						handle,
						buffer,
						2,
						buffer+0x100,
						overlapped,
					); result != 0 {
						t.Fatalf(
							"%s(offset=%#x) = %d, want FALSE",
							operation,
							offset,
							result,
						)
					}
					if value := kernel32TestLastError(
						t,
						hctx,
						mem,
						test.is32,
					); value != 87 {
						t.Fatalf(
							"%s(offset=%#x) LastError = %d, want 87",
							operation,
							offset,
							value,
						)
					}
					if status := uint32(
						layout.readPointer(
							mem,
							overlapped+layout.internal,
						),
					); status != overlappedStatusInvalidParam {
						t.Fatalf(
							"%s(offset=%#x) status = %#x",
							operation,
							offset,
							status,
						)
					}
				}
			}
			call("CloseHandle", handle)
		})
	}
}

func TestCreatePipeUsesVFSAndGuestPointerWidthPE32AndPE64(t *testing.T) {
	for _, test := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			hctx, mem, _ := newToolbarDispatchTestContext(t)
			hctx.ProcState.Is32 = test.is32
			mem.Mode32 = test.is32
			kernel32 := hctx.SynthByName["kernel32.dll"]
			call := func(name string, args ...uint64) uint64 {
				return callSubclassTestExport(t, hctx.Disp, kernel32, mem, test.is32, name, args...)
			}
			storage := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
			pointerSize := uint64(8)
			if test.is32 {
				pointerSize = 4
			}
			readOut := storage + 0x20
			writeOut := storage + 0x40
			const guard = uint32(0xA5C35A69)
			mem.Write32(readOut+pointerSize, guard)
			mem.Write32(writeOut+pointerSize, guard)

			if result := call("CreatePipe", readOut, writeOut, 0, 0); result != 1 {
				t.Fatalf("CreatePipe = %d, LastError=%d", result, kernel32TestLastError(t, hctx, mem, test.is32))
			}
			readHandle, err := readGuestPointer(mem, readOut, test.is32)
			if err != nil {
				t.Fatal(err)
			}
			writeHandle, err := readGuestPointer(mem, writeOut, test.is32)
			if err != nil {
				t.Fatal(err)
			}
			for name, address := range map[string]uint64{"read": readOut, "write": writeOut} {
				if value, err := mem.Read32(address + pointerSize); err != nil || value != guard {
					t.Fatalf("%s handle guard = %#x, err=%v", name, value, err)
				}
			}
			if result := call("GetFileType", readHandle); result != 3 {
				t.Fatalf("GetFileType(read) = %d, want FILE_TYPE_PIPE", result)
			}
			if result := call("GetFileType", writeHandle); result != 3 {
				t.Fatalf("GetFileType(write) = %d, want FILE_TYPE_PIPE", result)
			}
			if result := call("GetFileType", 0x101); result != 2 {
				t.Fatalf("GetFileType(stdout) = %d, want FILE_TYPE_CHAR", result)
			}
			console := hctx.Handles.Alloc(ntapi.NewConsoleScreenBuffer())
			if result := call("GetFileType", uint64(console)); result != 2 {
				t.Fatalf("GetFileType(console buffer) = %d, want FILE_TYPE_CHAR", result)
			}
			hctx.Handles.Close(console)
			if result := call("GetFileType", 0xDEADBEEF); result != 0 {
				t.Fatalf("GetFileType(invalid) = %d, want FILE_TYPE_UNKNOWN", result)
			}
			if value := kernel32TestLastError(t, hctx, mem, test.is32); value != 6 {
				t.Fatalf("GetFileType(invalid) LastError = %d, want 6", value)
			}

			buffer := storage + 0x100
			count := storage + 0x180
			if err := mem.WriteBytes(buffer, []byte("pipe data")); err != nil {
				t.Fatal(err)
			}
			if result := call("WriteFile", writeHandle, buffer, 9, count, 0); result != 1 {
				t.Fatalf("WriteFile(pipe) = %d, LastError=%d", result, kernel32TestLastError(t, hctx, mem, test.is32))
			}
			if result := call("ReadFile", readHandle, buffer+0x40, 16, count, 0); result != 1 {
				t.Fatalf("ReadFile(pipe) = %d, LastError=%d", result, kernel32TestLastError(t, hctx, mem, test.is32))
			}
			n, err := mem.Read32(count)
			if err != nil {
				t.Fatal(err)
			}
			got, err := mem.ReadBytes(buffer+0x40, int(n))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "pipe data" {
				t.Fatalf("pipe payload = %q", got)
			}

			if result := call("WriteFile", readHandle, buffer, 9, count, 0); result != 0 {
				t.Fatalf("WriteFile(read end) = %d, want 0", result)
			}
			if value := kernel32TestLastError(t, hctx, mem, test.is32); value != 5 {
				t.Fatalf("WriteFile(read end) LastError = %d, want 5", value)
			}
			if result := call("ReadFile", writeHandle, buffer+0x40, 16, count, 0); result != 0 {
				t.Fatalf("ReadFile(write end) = %d, want 0", result)
			}
			if value := kernel32TestLastError(t, hctx, mem, test.is32); value != 5 {
				t.Fatalf("ReadFile(write end) LastError = %d, want 5", value)
			}

			if result := call("CloseHandle", readHandle); result != 1 {
				t.Fatalf("CloseHandle(read) = %d", result)
			}
			if result := call("CloseHandle", writeHandle); result != 1 {
				t.Fatalf("CloseHandle(write) = %d", result)
			}
		})
	}
}

func TestCreatePipeRejectsInvalidOutputsBeforeAllocationPE32AndPE64(t *testing.T) {
	for _, test := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			hctx, mem, _ := newToolbarDispatchTestContext(t)
			hctx.ProcState.Is32 = test.is32
			mem.Mode32 = test.is32
			kernel32 := hctx.SynthByName["kernel32.dll"]
			call := func(name string, args ...uint64) uint64 {
				return callSubclassTestExport(t, hctx.Disp, kernel32, mem, test.is32, name, args...)
			}
			storage := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
			readOut := storage + 0x20
			writeOut := storage + 0x40

			if result := call("CreatePipe", readOut, 0xDEADBEEF, 0, 0); result != 0 {
				t.Fatalf("CreatePipe(invalid output) = %d, want 0", result)
			}
			if value := kernel32TestLastError(t, hctx, mem, test.is32); value != 998 {
				t.Fatalf("CreatePipe(invalid output) LastError = %d, want 998", value)
			}
			if result := call("CreatePipe", readOut, readOut, 0, 0); result != 0 {
				t.Fatalf("CreatePipe(alias outputs) = %d, want 0", result)
			}
			if value := kernel32TestLastError(t, hctx, mem, test.is32); value != 87 {
				t.Fatalf("CreatePipe(alias outputs) LastError = %d, want 87", value)
			}

			if result := call("CreatePipe", readOut, writeOut, 0, 0); result != 1 {
				t.Fatalf("CreatePipe(valid) = %d", result)
			}
			readHandle, err := readGuestPointer(mem, readOut, test.is32)
			if err != nil {
				t.Fatal(err)
			}
			writeHandle, err := readGuestPointer(mem, writeOut, test.is32)
			if err != nil {
				t.Fatal(err)
			}
			if readHandle != 0x200 || writeHandle != 0x204 {
				t.Fatalf("handles after rejected calls = (%#x, %#x), want (0x200, 0x204)", readHandle, writeHandle)
			}
			readFile := hctx.Handles.GetFile(ntapi.Handle(readHandle))
			writeFile := hctx.Handles.GetFile(ntapi.Handle(writeHandle))
			if readFile == nil || writeFile == nil || readFile.FD != 3 || writeFile.FD != 4 {
				t.Fatalf("VFS descriptors after rejected calls = (%+v, %+v), want 3 and 4", readFile, writeFile)
			}
			call("CloseHandle", readHandle)
			call("CloseHandle", writeHandle)
		})
	}
}
