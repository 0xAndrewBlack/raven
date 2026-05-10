package vfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestOpenAtCreateAndRead(t *testing.T) {
	fs := New()
	fd, err := fs.OpenAt(-100, "/tmp/test.txt", O_CREAT|O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello world")
	n, err := fs.Write(fd, data)
	if err != nil || n != len(data) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	// Seek back to beginning
	pos, err := fs.Lseek(fd, 0, SEEK_SET)
	if err != nil || pos != 0 {
		t.Fatalf("Lseek: pos=%d err=%v", pos, err)
	}
	// Read back
	buf := make([]byte, 64)
	rn, err := fs.Read(fd, buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:rn]) != "hello world" {
		t.Fatalf("Read: got %q", string(buf[:rn]))
	}
}

func TestHostPassthroughOpenFlags(t *testing.T) {
	fs := New()
	path := filepath.Join(t.TempDir(), "passthrough.txt")

	fd, err := fs.OpenAt(-100, path, O_CREAT|O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Write(fd, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(fd); err != nil {
		t.Fatal(err)
	}

	fd, err = fs.OpenAt(-100, path, O_WRONLY|O_APPEND, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Write(fd, []byte("-second")); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(fd); err != nil {
		t.Fatal(err)
	}
	appended, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(appended) != "first-second" {
		t.Fatalf("appended host file = %q, want %q", appended, "first-second")
	}

	fd, err = fs.OpenAt(-100, path, O_WRONLY|O_TRUNC, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Write(fd, []byte("final")); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(fd); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "final" {
		t.Fatalf("host file = %q, want %q", got, "final")
	}
}

func TestReadDirMergesVirtualAndHostEntries(t *testing.T) {
	fs := New()
	hostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostDir, "host.txt"), []byte("host"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "COLLIDE.TXT"), []byte("host collision"), 0644); err != nil {
		t.Fatal(err)
	}
	fs.MkdirAll(hostDir)
	if err := fs.CreateFile(filepath.Join(hostDir, "virtual.txt"), []byte("virtual"), ModeRead); err != nil {
		t.Fatal(err)
	}
	if err := fs.CreateFile(filepath.Join(hostDir, "collide.txt"), []byte("virtual collision"), ModeRead); err != nil {
		t.Fatal(err)
	}

	entries, err := fs.ReadDir(strings.ToUpper(hostDir))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	if len(entries) != 3 ||
		entries[0].Name() != "collide.txt" ||
		entries[1].Name() != "host.txt" ||
		entries[2].Name() != "virtual.txt" {
		t.Fatalf("entries = %v", names)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() || info.Size() != int64(len("virtual collision")) {
		t.Fatalf("virtual info = size %d, dir %t", info.Size(), info.IsDir())
	}
}

func TestReadDirReportsVirtualFileTypes(t *testing.T) {
	fs := New()
	entries, err := fs.ReadDir("/dev")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "null" {
			continue
		}
		if entry.Type()&(os.ModeDevice|os.ModeCharDevice) != os.ModeDevice|os.ModeCharDevice {
			t.Fatalf("null type = %v", entry.Type())
		}
		return
	}
	t.Fatal("/dev/null missing")
}

func TestReadDirConcurrentMutation(t *testing.T) {
	fs := New()
	fs.MkdirAll("/work")
	fd, err := fs.Open("/work/data.txt", O_CREAT|O_RDWR|O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(fd)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if _, err := fs.Write(fd, []byte("x")); err != nil {
				t.Errorf("Write: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			fs.MkdirAll(fmt.Sprintf("/work/dir-%d", i))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if _, err := fs.ReadDir("/work"); err != nil {
				t.Errorf("ReadDir: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

func TestDup(t *testing.T) {
	fs := New()
	fd, err := fs.OpenAt(-100, "/tmp/dup.txt", O_CREAT|O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	fs.Write(fd, []byte("data"))

	fd2, err := fs.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	if fd2 == fd {
		t.Fatal("Dup returned same fd")
	}
	// Both fds should share the same node
	node1 := fs.Stat(fd)
	node2 := fs.Stat(fd2)
	if node1.Ino != node2.Ino {
		t.Fatal("Dup'd fds don't share inode")
	}
}

func TestDup3(t *testing.T) {
	fs := New()
	// Dup stdout (fd=1) to fd 10
	err := fs.Dup3(1, 10)
	if err != nil {
		t.Fatal(err)
	}
	node := fs.Stat(10)
	if node == nil {
		t.Fatal("fd 10 not open after Dup3")
	}
}

func TestPipe2(t *testing.T) {
	fs := New()
	rfd, wfd, err := fs.Pipe2(0)
	if err != nil {
		t.Fatal(err)
	}
	// Write into pipe
	fs.Write(wfd, []byte("pipe data"))
	// Read from pipe
	buf := make([]byte, 64)
	n, err := fs.Read(rfd, buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "pipe data" {
		t.Fatalf("Pipe: got %q", string(buf[:n]))
	}
}

func TestLseek(t *testing.T) {
	fs := New()
	fd, _ := fs.OpenAt(-100, "/tmp/seek.txt", O_CREAT|O_RDWR, 0644)
	fs.Write(fd, []byte("0123456789"))

	// SEEK_SET to 5
	pos, _ := fs.Lseek(fd, 5, SEEK_SET)
	if pos != 5 {
		t.Fatalf("SEEK_SET: expected 5, got %d", pos)
	}
	// SEEK_CUR +2
	pos, _ = fs.Lseek(fd, 2, SEEK_CUR)
	if pos != 7 {
		t.Fatalf("SEEK_CUR: expected 7, got %d", pos)
	}
	// SEEK_END -3
	pos, _ = fs.Lseek(fd, -3, SEEK_END)
	if pos != 7 {
		t.Fatalf("SEEK_END: expected 7, got %d", pos)
	}
}

func TestLseekCharDevice(t *testing.T) {
	fs := New()
	// stdout is a char device - lseek should fail
	_, err := fs.Lseek(1, 0, SEEK_SET)
	if err == nil {
		t.Fatal("Lseek on char device should fail")
	}
}

func TestReadlinkatProcSelfExe(t *testing.T) {
	fs := New()
	fs.ElfPath = "/usr/bin/test"
	target, err := fs.Readlinkat(-100, "/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if target != "/usr/bin/test" {
		t.Fatalf("Expected /usr/bin/test, got %s", target)
	}
}

func TestStatInode(t *testing.T) {
	fs := New()
	fd, _ := fs.OpenAt(-100, "/tmp/stat.txt", O_CREAT|O_RDWR, 0644)
	node := fs.Stat(fd)
	if node == nil {
		t.Fatal("Stat returned nil")
	}
	if node.Ino == 0 {
		t.Fatal("Inode should be non-zero")
	}
	if node.FileMode&S_IFREG == 0 {
		t.Fatalf("Expected regular file, got mode 0x%x", node.FileMode)
	}
}

func TestDevNull(t *testing.T) {
	fs := New()
	fd, err := fs.OpenAt(-100, "/dev/null", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Write should succeed
	n, err := fs.Write(fd, []byte("garbage"))
	if err != nil || n != 7 {
		t.Fatalf("Write to /dev/null: n=%d err=%v", n, err)
	}
	// Read should return EOF
	buf := make([]byte, 10)
	rn, _ := fs.Read(fd, buf)
	if rn != 0 {
		t.Fatalf("Read from /dev/null: expected 0, got %d", rn)
	}
}

func TestGetdents64(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/a.txt", []byte("a"), ModeRead)
	fs.CreateFile("/tmp/b.txt", []byte("b"), ModeRead)
	fd, _ := fs.OpenAt(-100, "/tmp", 0, 0)
	entries := fs.Getdents64(fd)
	if len(entries) < 2 {
		t.Fatalf("Expected at least 2 entries, got %d", len(entries))
	}
}

func TestUnlinkat(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/todelete.txt", []byte("gone"), ModeRead)
	// Verify exists
	_, err := fs.StatPath(-100, "/tmp/todelete.txt")
	if err != nil {
		t.Fatal("file should exist before unlink")
	}
	// Unlink it
	if err := fs.Unlinkat(-100, "/tmp/todelete.txt", 0); err != nil {
		t.Fatal(err)
	}
	// Verify gone
	_, err = fs.StatPath(-100, "/tmp/todelete.txt")
	if err == nil {
		t.Fatal("file should not exist after unlink")
	}
}

func TestRemoveAll(t *testing.T) {
	fs := New()
	fs.MkdirAll("/tmp/tree/nested")
	fs.CreateFile("/tmp/tree/nested/file.txt", []byte("gone"), ModeRead)
	if err := fs.RemoveAll(-100, "/TMP/TREE"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.StatPath(-100, "/tmp/tree"); err == nil {
		t.Fatal("directory tree still exists")
	}
	if err := fs.RemoveAll(-100, "/tmp/missing"); err != nil {
		t.Fatalf("missing path: %v", err)
	}
	if err := fs.RemoveAll(-100, "/"); err == nil {
		t.Fatal("VFS root removal succeeded")
	}
}

func TestFtruncate(t *testing.T) {
	fs := New()
	fd, _ := fs.OpenAt(-100, "/tmp/trunc.txt", O_CREAT|O_RDWR, 0644)
	fs.Write(fd, []byte("hello world"))
	// Truncate to 5
	if err := fs.Ftruncate(fd, 5); err != nil {
		t.Fatal(err)
	}
	node := fs.Stat(fd)
	if node.Size != 5 {
		t.Fatalf("expected size 5, got %d", node.Size)
	}
	// Extend to 20
	if err := fs.Ftruncate(fd, 20); err != nil {
		t.Fatal(err)
	}
	node = fs.Stat(fd)
	if node.Size != 20 {
		t.Fatalf("expected size 20, got %d", node.Size)
	}
}

func TestChdir(t *testing.T) {
	fs := New()
	fs.MkdirAll("/home/user")
	if err := fs.Chdir("/home/user"); err != nil {
		t.Fatal(err)
	}
	if fs.Getcwd() != "/home/user" {
		t.Fatalf("expected /home/user, got %s", fs.Getcwd())
	}
}

func TestRenameat(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/old.txt", []byte("data"), ModeRead)
	if err := fs.Renameat(-100, "/tmp/old.txt", -100, "/tmp/new.txt"); err != nil {
		t.Fatal(err)
	}
	_, err := fs.StatPath(-100, "/tmp/old.txt")
	if err == nil {
		t.Fatal("old path should not exist after rename")
	}
	_, err = fs.StatPath(-100, "/tmp/new.txt")
	if err != nil {
		t.Fatal("new path should exist after rename")
	}
}

func TestRenameatWithCommitLeavesEntriesUnchangedOnFailure(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/old.txt", []byte("source"), ModeRead)
	fs.CreateFile("/tmp/new.txt", []byte("destination"), ModeRead)
	commitErr := errors.New("commit failed")
	var committedData []byte

	err := fs.RenameatWithCommit(-100, "/tmp/old.txt", -100, "/tmp/new.txt", RenameOptions{ReplaceExisting: true}, func(source RenameCommitSource) (RenameCommitResult, error) {
		committedData = source.Data
		return RenameCommitResult{}, commitErr
	})
	if !errors.Is(err, commitErr) {
		t.Fatalf("RenameatWithCommit error = %v, want %v", err, commitErr)
	}
	if string(committedData) != "source" {
		t.Fatalf("commit data = %q, want source", committedData)
	}
	oldNode, err := fs.StatPath(-100, "/tmp/old.txt")
	if err != nil {
		t.Fatalf("old entry is missing: %v", err)
	}
	if string(oldNode.Data) != "source" {
		t.Fatalf("old entry data = %q, want source", oldNode.Data)
	}
	newNode, err := fs.StatPath(-100, "/tmp/new.txt")
	if err != nil {
		t.Fatalf("new entry is missing: %v", err)
	}
	if string(newNode.Data) != "destination" {
		t.Fatalf("new entry data = %q, want destination", newNode.Data)
	}
}

func TestRenameatWithCommitRejectsExistingDestinationBeforeCommit(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/old.txt", []byte("source"), ModeRead)
	fs.CreateFile("/tmp/new.txt", []byte("destination"), ModeRead)
	commitCalled := false

	err := fs.RenameatWithCommit(-100, "/tmp/old.txt", -100, "/tmp/new.txt", RenameOptions{}, func(RenameCommitSource) (RenameCommitResult, error) {
		commitCalled = true
		return RenameCommitResult{}, nil
	})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("RenameatWithCommit error = %v, want destination-exists error", err)
	}
	if commitCalled {
		t.Fatal("external commit ran after destination conflict")
	}
	oldNode, _ := fs.StatPath(-100, "/tmp/old.txt")
	newNode, _ := fs.StatPath(-100, "/tmp/new.txt")
	if string(oldNode.Data) != "source" || string(newNode.Data) != "destination" {
		t.Fatalf("entries changed: old=%q new=%q", oldNode.Data, newNode.Data)
	}
}

func TestRenameatWithCommitRejectsNonDirectoryParent(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/old.txt", []byte("source"), ModeRead)
	fs.CreateFile("/tmp/not-a-directory", []byte("file"), ModeRead)

	err := fs.RenameatWithCommit(-100, "/tmp/old.txt", -100, "/tmp/not-a-directory/new.txt", RenameOptions{}, nil)
	if !errors.Is(err, ErrRenameParentNotFound) {
		t.Fatalf("RenameatWithCommit error = %v, want parent error", err)
	}
	if _, err := fs.StatPath(-100, "/tmp/old.txt"); err != nil {
		t.Fatalf("source entry was removed: %v", err)
	}
}

func TestRenameatRejectsDirectoryMovedIntoDescendant(t *testing.T) {
	fs := New()
	fs.MkdirAll("/tmp/tree/sub")

	err := fs.Renameat(-100, "/tmp/tree", -100, "/tmp/tree/sub/moved")
	if !errors.Is(err, ErrInvalidPathAlias) {
		t.Fatalf("Renameat error = %v, want invalid alias", err)
	}
	if _, err := fs.StatPath(-100, "/tmp/tree/sub"); err != nil {
		t.Fatalf("source tree changed after failed rename: %v", err)
	}
}

func TestRenameatWithCommitRejectsExistingDirectoryForWindowsMove(t *testing.T) {
	fs := New()
	fs.MkdirAll("/tmp/source")
	fs.MkdirAll("/tmp/destination")
	commitCalled := false

	err := fs.RenameatWithCommit(-100, "/tmp/source", -100, "/tmp/destination", RenameOptions{
		ReplaceExisting:         true,
		RejectExistingDirectory: true,
	}, func(RenameCommitSource) (RenameCommitResult, error) {
		commitCalled = true
		return RenameCommitResult{}, nil
	})
	if err == nil {
		t.Fatal("existing destination directory was replaced")
	}
	if commitCalled {
		t.Fatal("external commit ran before directory conflict was rejected")
	}
	if _, err := fs.StatPath(-100, "/tmp/source"); err != nil {
		t.Fatalf("source directory was removed: %v", err)
	}
}

func TestRenameatUsesCaseInsensitiveEntryNames(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/Old.txt", []byte("source"), ModeRead)
	fs.CreateFile("/tmp/Target.txt", []byte("destination"), ModeRead)

	if err := fs.Renameat(-100, "/TMP/OLD.TXT", -100, "/tmp/TARGET.TXT"); err != nil {
		t.Fatal(err)
	}
	parent, err := fs.Resolve("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if len(parent.Children) != 1 {
		t.Fatalf("directory has %d entries, want 1", len(parent.Children))
	}
	node := parent.Children["TARGET.TXT"]
	if node == nil || string(node.Data) != "source" {
		t.Fatalf("renamed entry = %#v", node)
	}
}

func TestRenameatWithCommitCanRetainSource(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/old.txt", []byte("source"), ModeRead)

	err := fs.RenameatWithCommit(-100, "/tmp/old.txt", -100, "/tmp/new.txt", RenameOptions{}, func(RenameCommitSource) (RenameCommitResult, error) {
		return RenameCommitResult{KeepSource: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	oldNode, err := fs.StatPath(-100, "/tmp/old.txt")
	if err != nil {
		t.Fatal(err)
	}
	newNode, err := fs.StatPath(-100, "/tmp/new.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(oldNode.Data) != "source" || string(newNode.Data) != "source" {
		t.Fatalf("source data = %q, destination data = %q", oldNode.Data, newNode.Data)
	}
	if oldNode.Ino == newNode.Ino {
		t.Fatalf("copied entries share inode %d", oldNode.Ino)
	}
	if oldNode.Mode != newNode.Mode || oldNode.FileMode != newNode.FileMode ||
		oldNode.Uid != newNode.Uid || oldNode.Gid != newNode.Gid ||
		oldNode.Size != newNode.Size {
		t.Fatalf("copied metadata differs: old=%#v new=%#v", oldNode, newNode)
	}
}

func TestSymlinkat(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/target.txt", []byte("content"), ModeRead)
	if err := fs.Symlinkat("/tmp/target.txt", -100, "/tmp/link.txt"); err != nil {
		t.Fatal(err)
	}
	target, err := fs.Readlinkat(-100, "/tmp/link.txt")
	if err != nil {
		t.Fatal(err)
	}
	if target != "/tmp/target.txt" {
		t.Fatalf("expected /tmp/target.txt, got %s", target)
	}
}

func TestOpenAtReadsHostTemporaryFile(t *testing.T) {
	hostPath := filepath.Join(t.TempDir(), "host.txt")
	if err := os.WriteFile(hostPath, []byte("host data"), 0600); err != nil {
		t.Fatal(err)
	}

	fs := New()
	fd, err := fs.OpenAt(-100, hostPath, O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(fd)

	buf := make([]byte, 32)
	n, err := fs.Read(fd, buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "host data" {
		t.Fatalf("Read: got %q", got)
	}
}
