//go:build guest_windows

package ntapi

import (
	"testing"
	"time"
)

func TestIoCompletionCloseWakesBlockedRemove(t *testing.T) {
	port := &IoCompletionPortHandle{}
	result := make(chan IoCompletionRemoveResult, 1)
	go func() {
		_, removeResult := port.RemoveEx(-1)
		result <- removeResult
	}()

	time.Sleep(10 * time.Millisecond)
	port.Close()

	select {
	case removeResult := <-result:
		if removeResult != IoCompletionClosed {
			t.Fatalf("remove result = %d", removeResult)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake blocked remove")
	}
}

func TestIoCompletionRejectsPostAfterClose(t *testing.T) {
	port := &IoCompletionPortHandle{}
	port.Close()
	port.PostForFile(0x44, 0x55, 0x66, 7, 0)

	if _, result := port.RemoveEx(0); result != IoCompletionClosed {
		t.Fatalf("remove result = %d", result)
	}
}

func TestIoCompletionPacketPreservesFileHandle(t *testing.T) {
	port := &IoCompletionPortHandle{}
	port.PostForFileOperation(0x44, 0x55, 0x66, 7, 0, 0x77)

	packet, result := port.RemoveEx(0)
	if result != IoCompletionRemoved {
		t.Fatalf("remove result = %d", result)
	}
	if packet.FileHandle != 0x44 {
		t.Fatalf("file handle = %#x", packet.FileHandle)
	}
	if packet.OperationID != 0x77 {
		t.Fatalf("operation ID = %#x", packet.OperationID)
	}
}

func TestFileCompletionAssociationSurvivesObjectCopy(t *testing.T) {
	file := &FileHandle{}
	file.completionState()
	duplicate := *file
	port := &IoCompletionPortHandle{}

	if !file.AssociateCompletion(port, 0x1234) {
		t.Fatal("failed to associate source file")
	}
	gotPort, key, ok := duplicate.CompletionAssociation()
	if !ok || gotPort != port || key != 0x1234 {
		t.Fatalf("duplicate association port=%p key=%#x ok=%t", gotPort, key, ok)
	}
	if duplicate.AssociateCompletion(port, 0x5678) {
		t.Fatal("duplicate accepted a second completion association")
	}
}

func TestHandleTableCountsSharedObjects(t *testing.T) {
	handles := NewHandleTable()
	port := &IoCompletionPortHandle{}
	first := handles.Alloc(port)
	second := handles.Alloc(port)
	if got := handles.ReferenceCount(port); got != 2 {
		t.Fatalf("reference count = %d", got)
	}
	handles.Close(first)
	if got := handles.ReferenceCount(port); got != 1 {
		t.Fatalf("reference count after close = %d", got)
	}
	handles.Close(second)
	if got := handles.ReferenceCount(port); got != 0 {
		t.Fatalf("final reference count = %d", got)
	}
}
