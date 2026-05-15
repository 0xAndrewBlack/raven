//go:build guest_windows

package ntapi

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/vfs"
)

type handleTakeResult struct {
	obj        HandleObject
	objectRefs int
	ownerRefs  int
	ok         bool
}

type handleDuplicateResult struct {
	handle Handle
	obj    HandleObject
	ok     bool
}

type handleCloneResult struct {
	handle     Handle
	source     HandleObject
	objectRefs int
	ownerRefs  int
	ok         bool
}

func TestHandleTableTakeFileReferenceCounts(t *testing.T) {
	handles := NewHandleTable()
	file := &FileHandle{FD: -1}
	first := handles.Alloc(file)
	second := handles.Alloc(file)
	sibling := *file
	third := handles.Alloc(&sibling)
	owner := file.LockOwner()

	obj, objectRefs, ownerRefs, ok := handles.Take(first)
	if !ok || obj != file {
		t.Fatalf("Take(first) = (%p, %v), want (%p, true)", obj, ok, file)
	}
	if objectRefs != 1 || ownerRefs != 2 {
		t.Fatalf("Take(first) refs = (%d, %d), want (1, 2)", objectRefs, ownerRefs)
	}
	if handles.ReferenceCount(file) != 1 || handles.FileOwnerReferenceCount(owner) != 2 {
		t.Fatal("first take returned counts inconsistent with the live table")
	}

	if obj, objectRefs, ownerRefs, ok := handles.Take(first); ok || obj != nil || objectRefs != 0 || ownerRefs != 0 {
		t.Fatalf("second Take(first) = (%v, %d, %d, %v)", obj, objectRefs, ownerRefs, ok)
	}

	if obj, objectRefs, ownerRefs, ok := handles.Take(second); !ok || obj != file || objectRefs != 0 || ownerRefs != 1 {
		t.Fatalf("Take(second) = (%p, %d, %d, %v)", obj, objectRefs, ownerRefs, ok)
	}
	if obj, objectRefs, ownerRefs, ok := handles.Take(third); !ok || obj != &sibling || objectRefs != 0 || ownerRefs != 0 {
		t.Fatalf("Take(third) = (%p, %d, %d, %v)", obj, objectRefs, ownerRefs, ok)
	}
}

func TestHandleTableDuplicateFilePreservesSource(t *testing.T) {
	handles := NewHandleTable()
	file := &FileHandle{FD: -1}
	source := handles.Alloc(file)
	owner := file.LockOwner()

	duplicate, obj, ok := handles.Duplicate(source, false)
	if !ok || obj != file {
		t.Fatalf("Duplicate = (%#x, %p, %v), want original object", duplicate, obj, ok)
	}
	if duplicate == source {
		t.Fatal("Duplicate reused the source handle value")
	}
	if handles.Get(source) != file || handles.Get(duplicate) != file {
		t.Fatal("Duplicate did not preserve both live handles")
	}
	if handles.ReferenceCount(file) != 2 || handles.FileOwnerReferenceCount(owner) != 2 {
		t.Fatal("Duplicate returned inconsistent object or owner reference counts")
	}
}

func TestHandleTableDuplicateFileTransfersSource(t *testing.T) {
	handles := NewHandleTable()
	file := &FileHandle{FD: -1}
	source := handles.Alloc(file)
	sibling := *file
	siblingHandle := handles.Alloc(&sibling)
	owner := file.LockOwner()

	duplicate, obj, ok := handles.Duplicate(source, true)
	if !ok || obj != file {
		t.Fatalf("Duplicate(closeSource) = (%#x, %p, %v)", duplicate, obj, ok)
	}
	if handles.Get(source) != nil {
		t.Fatal("source remained live after atomic transfer")
	}
	if handles.Get(duplicate) != file || handles.Get(siblingHandle) != &sibling {
		t.Fatal("transfer lost the source object or its owner sibling")
	}
	if handles.ReferenceCount(file) != 1 || handles.FileOwnerReferenceCount(owner) != 2 {
		t.Fatal("transfer changed the live owner reference count")
	}
}

func TestHandleTableCloneFileTransfersSharedState(t *testing.T) {
	fs := vfs.New()
	fd, err := fs.Open("/handles-atomic-position.txt", vfs.O_CREAT|vfs.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(fd)
	if _, err := fs.Pwrite(fd, []byte("abcdef"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Lseek(fd, 0, vfs.SEEK_SET); err != nil {
		t.Fatal(err)
	}

	handles := NewHandleTable()
	file := &FileHandle{FD: fd, Path: "/handles-atomic-position.txt"}
	port := &IoCompletionPortHandle{}
	if !file.AssociateCompletion(port, 0x1234) {
		t.Fatal("initial completion association failed")
	}
	source := handles.Alloc(file)
	owner := file.LockOwner()
	duplicateFD := -1

	duplicate, returnedSource, objectRefs, ownerRefs, ok := handles.Clone(
		source,
		true,
		func(obj HandleObject) (HandleObject, bool) {
			original := obj.(*FileHandle)
			newFD, err := fs.Dup(original.FD)
			if err != nil {
				return nil, false
			}
			duplicateFD = newFD
			original.completionState()
			cloned := *original
			cloned.FD = newFD
			return &cloned, true
		},
	)
	if duplicateFD >= 0 {
		defer fs.Close(duplicateFD)
	}
	if !ok || returnedSource != file {
		t.Fatalf("Clone(closeSource) = (%#x, %p, %v)", duplicate, returnedSource, ok)
	}
	if handles.Get(source) != nil {
		t.Fatal("source remained live after clone transfer")
	}
	cloned, ok := handles.Get(duplicate).(*FileHandle)
	if !ok {
		t.Fatalf("cloned handle object = %T, want *FileHandle", handles.Get(duplicate))
	}
	if cloned == file || cloned.FD == file.FD {
		t.Fatal("clone did not create a distinct file handle and VFS descriptor")
	}
	if cloned.LockOwner() != owner || cloned.completion != file.completion {
		t.Fatal("clone did not share lock owner and completion state")
	}
	if gotPort, key, associated := cloned.CompletionAssociation(); !associated || gotPort != port || key != 0x1234 {
		t.Fatal("clone lost its completion association")
	}
	if objectRefs != 0 || ownerRefs != 1 {
		t.Fatalf("Clone refs = (%d, %d), want (0, 1)", objectRefs, ownerRefs)
	}

	first := make([]byte, 2)
	if n, err := fs.Read(cloned.FD, first); err != nil || n != len(first) || string(first) != "ab" {
		t.Fatalf("clone read = (%q, %d, %v), want (ab, 2, nil)", first, n, err)
	}
	second := make([]byte, 2)
	if n, err := fs.Read(file.FD, second); err != nil || n != len(second) || string(second) != "cd" {
		t.Fatalf("source descriptor read = (%q, %d, %v), want shared offset cd", second, n, err)
	}
}

func TestHandleTableDuplicateTransfersFileName(t *testing.T) {
	handles := NewHandleTable()
	file := &FileHandle{FD: -1}
	source, created := handles.AllocNamed(`Local\handles-atomic-file`, file)
	if !created {
		t.Fatal("named source was not created")
	}

	duplicate, _, ok := handles.Duplicate(source, true)
	if !ok {
		t.Fatal("named source transfer failed")
	}
	if got := handles.GetNamed(`Global\handles-atomic-file`); got != duplicate {
		t.Fatalf("named lookup = %#x, want %#x", got, duplicate)
	}
	if _, ok := handles.NameOf(source); ok {
		t.Fatal("source retained its name after transfer")
	}
	if name, ok := handles.NameOf(duplicate); !ok || name != "handles-atomic-file" {
		t.Fatalf("duplicate name = (%q, %v)", name, ok)
	}
	if _, _, _, ok := handles.Take(duplicate); !ok {
		t.Fatal("taking named duplicate failed")
	}
	if got := handles.GetNamed("handles-atomic-file"); got != 0 {
		t.Fatalf("name survived final take as handle %#x", got)
	}
}

func TestHandleTableConcurrentTakeAndDuplicateTransfer(t *testing.T) {
	const iterations = 128
	for i := 0; i < iterations; i++ {
		handles := NewHandleTable()
		file := &FileHandle{FD: -1}
		source := handles.Alloc(file)
		owner := file.LockOwner()
		ready := make(chan struct{}, 2)
		start := make(chan struct{})
		takeDone := make(chan handleTakeResult, 1)
		duplicateDone := make(chan handleDuplicateResult, 1)

		go func() {
			ready <- struct{}{}
			<-start
			obj, objectRefs, ownerRefs, ok := handles.Take(source)
			takeDone <- handleTakeResult{obj, objectRefs, ownerRefs, ok}
		}()
		go func() {
			ready <- struct{}{}
			<-start
			handle, obj, ok := handles.Duplicate(source, true)
			duplicateDone <- handleDuplicateResult{handle, obj, ok}
		}()
		<-ready
		<-ready
		close(start)
		taken := <-takeDone
		duplicated := <-duplicateDone

		if taken.ok == duplicated.ok {
			t.Fatalf("iteration %d: Take ok=%v, Duplicate ok=%v", i, taken.ok, duplicated.ok)
		}
		if taken.objectRefs < 0 || taken.ownerRefs < 0 {
			t.Fatalf("iteration %d: negative Take counts (%d, %d)", i, taken.objectRefs, taken.ownerRefs)
		}
		if taken.ok {
			if taken.obj != file || taken.objectRefs != 0 || taken.ownerRefs != 0 {
				t.Fatalf("iteration %d: incoherent Take winner %#v", i, taken)
			}
			if duplicated.handle != 0 || duplicated.obj != nil || handles.Count() != 0 {
				t.Fatalf("iteration %d: failed duplicate left a live handle", i)
			}
			continue
		}
		if taken.obj != nil || taken.objectRefs != 0 || taken.ownerRefs != 0 {
			t.Fatalf("iteration %d: failed Take returned state %#v", i, taken)
		}
		if duplicated.obj != file || handles.Get(duplicated.handle) != file {
			t.Fatalf("iteration %d: duplicate winner lost its object", i)
		}
		if handles.ReferenceCount(file) != 1 || handles.FileOwnerReferenceCount(owner) != 1 {
			t.Fatalf("iteration %d: duplicate winner has premature reference counts", i)
		}
	}
}

func TestHandleTableConcurrentTakeAndCloneTransfer(t *testing.T) {
	const iterations = 128
	for i := 0; i < iterations; i++ {
		handles := NewHandleTable()
		file := &FileHandle{FD: -1}
		source := handles.Alloc(file)
		owner := file.LockOwner()
		ready := make(chan struct{}, 2)
		start := make(chan struct{})
		takeDone := make(chan handleTakeResult, 1)
		cloneDone := make(chan handleCloneResult, 1)

		go func() {
			ready <- struct{}{}
			<-start
			obj, objectRefs, ownerRefs, ok := handles.Take(source)
			takeDone <- handleTakeResult{obj, objectRefs, ownerRefs, ok}
		}()
		go func() {
			ready <- struct{}{}
			<-start
			handle, returnedSource, objectRefs, ownerRefs, ok := handles.Clone(
				source,
				true,
				func(obj HandleObject) (HandleObject, bool) {
					cloned := *(obj.(*FileHandle))
					return &cloned, true
				},
			)
			cloneDone <- handleCloneResult{
				handle,
				returnedSource,
				objectRefs,
				ownerRefs,
				ok,
			}
		}()
		<-ready
		<-ready
		close(start)
		taken := <-takeDone
		cloned := <-cloneDone

		if taken.ok == cloned.ok {
			t.Fatalf("iteration %d: Take ok=%v, Clone ok=%v", i, taken.ok, cloned.ok)
		}
		if taken.objectRefs < 0 || taken.ownerRefs < 0 ||
			cloned.objectRefs < 0 || cloned.ownerRefs < 0 {
			t.Fatalf(
				"iteration %d: negative counts Take=(%d, %d) Clone=(%d, %d)",
				i,
				taken.objectRefs,
				taken.ownerRefs,
				cloned.objectRefs,
				cloned.ownerRefs,
			)
		}
		if taken.ok {
			if taken.obj != file || taken.objectRefs != 0 || taken.ownerRefs != 0 {
				t.Fatalf("iteration %d: incoherent Take winner %#v", i, taken)
			}
			if cloned.handle != 0 || cloned.source != nil || handles.Count() != 0 {
				t.Fatalf("iteration %d: failed clone left a live handle", i)
			}
			continue
		}
		if taken.obj != nil || taken.objectRefs != 0 || taken.ownerRefs != 0 {
			t.Fatalf("iteration %d: failed Take returned state %#v", i, taken)
		}
		if cloned.source != file || cloned.objectRefs != 0 || cloned.ownerRefs != 1 {
			t.Fatalf("iteration %d: incoherent Clone winner %#v", i, cloned)
		}
		clonedFile, ok := handles.Get(cloned.handle).(*FileHandle)
		if !ok || clonedFile == file || clonedFile.LockOwner() != owner {
			t.Fatalf("iteration %d: clone winner lost shared owner state", i)
		}
		if handles.ReferenceCount(file) != 0 || handles.FileOwnerReferenceCount(owner) != 1 {
			t.Fatalf("iteration %d: clone winner has premature reference counts", i)
		}
	}
}
