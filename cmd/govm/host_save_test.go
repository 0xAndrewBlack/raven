//go:build guest_windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/vfs"
)

func TestFlushHostSavePathPersistsRepeatedSaves(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/save")
	if err := fs.CreateFile("/save/document.txt", []byte("first"), 0644); err != nil {
		t.Fatal(err)
	}
	hostPath := filepath.Join(t.TempDir(), "document.txt")
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath("/save/document.txt", hostPath)
	if err := hctx.flushHostSavePath(fs, "/save/document.txt"); err != nil {
		t.Fatal(err)
	}
	if err := fs.CreateFile("/save/document.txt", []byte("second"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := hctx.flushHostSavePath(fs, "/save/document.txt"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Fatalf("saved content = %q, want second", got)
	}
}

func TestFlushHostSavePathUsesCaseInsensitiveBinding(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/save")
	if err := fs.CreateFile("/save/Document.txt", []byte("updated"), 0644); err != nil {
		t.Fatal(err)
	}
	hostPath := filepath.Join(t.TempDir(), "Document.txt")
	if err := os.WriteFile(hostPath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath("/save/Document.txt", hostPath)

	if err := hctx.flushHostSavePath(fs, "/SAVE/DOCUMENT.TXT"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "updated" {
		t.Fatalf("saved content = %q, want updated", got)
	}
}

func TestFlushHostSavePathReportsHostWriteFailure(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/save")
	if err := fs.CreateFile("/save/document.txt", []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath("/save/document.txt", t.TempDir())
	if err := hctx.flushHostSavePath(fs, "/save/document.txt"); err == nil {
		t.Fatal("host write failure was ignored")
	}
}

func TestFlushHostFileBuffersPersistsBoundVirtualFile(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/save")
	if err := fs.CreateFile("/save/document.txt", []byte("updated"), 0644); err != nil {
		t.Fatal(err)
	}
	fd, err := fs.Open("/save/document.txt", vfs.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(fd)
	hostPath := filepath.Join(t.TempDir(), "document.txt")
	if err := os.WriteFile(hostPath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath("/save/document.txt", hostPath)

	if err := hctx.flushHostFileBuffers(fs, fd, "/save/document.txt"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "updated" {
		t.Fatalf("host data = %q, want updated", data)
	}
}

func TestFlushHostFileBuffersSyncsHostBackedFile(t *testing.T) {
	hostPath := filepath.Join(t.TempDir(), "document.txt")
	hostFile, err := os.OpenFile(hostPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fs := vfs.New()
	fd := fs.AllocHostFile(hostFile)
	defer fs.Close(fd)
	if _, err := fs.Write(fd, []byte("updated")); err != nil {
		t.Fatal(err)
	}

	if err := (&HandlerCtx{}).flushHostFileBuffers(fs, fd, hostPath); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "updated" {
		t.Fatalf("host data = %q, want updated", data)
	}
}

func TestFlushHostSavePathWaitsForRenameBindingCommit(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/save")
	if err := fs.CreateFile("/save/document.txt", []byte("updated"), 0644); err != nil {
		t.Fatal(err)
	}
	hostDir := t.TempDir()
	oldHost := filepath.Join(hostDir, "document.txt")
	newHost := filepath.Join(hostDir, "renamed.txt")
	if err := os.WriteFile(oldHost, []byte("updated"), 0o644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath("/save/document.txt", oldHost)
	hctx.bindHostSavePath("/save/renamed.txt", newHost)

	renamed := make(chan struct{})
	resumeRename := make(chan struct{})
	ops := defaultHostSaveRenameOps
	ops.rename = func(sourcePath, targetPath string, _ bool) error {
		if err := os.Rename(sourcePath, targetPath); err != nil {
			return err
		}
		close(renamed)
		<-resumeRename
		return nil
	}
	renameDone := make(chan error, 1)
	go func() {
		_, err := hctx.commitHostSaveRenameWithOps(
			"/save/document.txt",
			"/save/renamed.txt",
			vfs.RenameCommitSource{Data: []byte("updated")},
			hostSaveRenameOptions{},
			ops,
		)
		renameDone <- err
	}()
	select {
	case <-renamed:
	case err := <-renameDone:
		t.Fatalf("rename completed before synchronization point: %v", err)
	}

	flushDone := make(chan error, 1)
	go func() {
		flushDone <- hctx.flushHostSavePath(fs, "/save/document.txt")
	}()
	select {
	case err := <-flushDone:
		t.Fatalf("flush completed before rename binding commit: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(resumeRename)
	if err := <-renameDone; err != nil {
		t.Fatal(err)
	}
	if err := <-flushDone; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldHost); !os.IsNotExist(err) {
		t.Fatalf("flush recreated the renamed host path: %v", err)
	}
	if data, err := os.ReadFile(newHost); err != nil || string(data) != "updated" {
		t.Fatalf("renamed host data = %q, err=%v", data, err)
	}
}

func TestFlushHostSavePathSnapshotsOutsideHostIOLock(t *testing.T) {
	hostPath := filepath.Join(t.TempDir(), "document.txt")
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath("/save/document.txt", hostPath)

	err := hctx.flushHostSavePathWithSnapshot("/save/document.txt", func() ([]byte, error) {
		if !hctx.HostSaveIOMu.TryLock() {
			t.Fatal("snapshot ran while HostSaveIOMu was held")
		}
		hctx.HostSaveIOMu.Unlock()
		return []byte("updated"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(hostPath); err != nil || string(data) != "updated" {
		t.Fatalf("host data = %q, err=%v", data, err)
	}
}

func TestSyncHostSaveRenamePersistsAtomicReplacement(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/save")
	if err := fs.CreateFile("/save/document.txt", []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := fs.CreateFile("/save/document.tmp", []byte("replacement"), 0644); err != nil {
		t.Fatal(err)
	}
	hostPath := filepath.Join(t.TempDir(), "document.txt")
	if err := os.WriteFile(hostPath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath("/save/document.txt", hostPath)
	err := fs.RenameatWithCommit(-1, "/save/document.tmp", -1, "/save/document.txt", vfs.RenameOptions{ReplaceExisting: true, RejectExistingDirectory: true}, func(source vfs.RenameCommitSource) (vfs.RenameCommitResult, error) {
		return hctx.commitHostSaveRename("/save/document.tmp", "/save/document.txt", source, hostSaveRenameOptions{
			replaceExisting: true,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "replacement" {
		t.Fatalf("saved content = %q, want replacement", got)
	}
	if hctx.HostSavePaths["/save/document.txt"] != hostPath {
		t.Fatalf("destination binding = %q", hctx.HostSavePaths["/save/document.txt"])
	}
}

func TestSyncHostSaveRenameMovesBoundHostFile(t *testing.T) {
	hostDir := t.TempDir()
	oldHost := filepath.Join(hostDir, "old.txt")
	newHost := filepath.Join(hostDir, "new.txt")
	if err := os.WriteFile(oldHost, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldVFS := filepath.ToSlash(oldHost)
	newVFS := filepath.ToSlash(newHost)
	fs := vfs.New()
	fs.MkdirAll(filepath.ToSlash(hostDir))
	if err := fs.CreateFile(oldVFS, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath(oldVFS, oldHost)
	err := fs.RenameatWithCommit(-1, oldVFS, -1, newVFS, vfs.RenameOptions{RejectExistingDirectory: true}, func(source vfs.RenameCommitSource) (vfs.RenameCommitResult, error) {
		return hctx.commitHostSaveRename(oldVFS, newVFS, source, hostSaveRenameOptions{
			allowCopy: true,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldHost); !os.IsNotExist(err) {
		t.Fatalf("old host file still exists, err=%v", err)
	}
	if data, err := os.ReadFile(newHost); err != nil || string(data) != "content" {
		t.Fatalf("new host data = %q, err=%v", data, err)
	}
	if hctx.HostSavePaths[newVFS] != newHost {
		t.Fatalf("destination binding = %q", hctx.HostSavePaths[newVFS])
	}
}

func TestCommitHostSaveRenameMovesBetweenBoundHostFiles(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/save")
	if err := fs.CreateFile("/save/old.txt", []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	hostDir := t.TempDir()
	oldHost := filepath.Join(hostDir, "old.txt")
	newHost := filepath.Join(hostDir, "selected.txt")
	if err := os.WriteFile(oldHost, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newHost, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath("/save/old.txt", oldHost)
	hctx.bindHostSavePath("/save/new.txt", newHost)

	err := fs.RenameatWithCommit(-1, "/save/old.txt", -1, "/save/new.txt", vfs.RenameOptions{ReplaceExisting: true, RejectExistingDirectory: true}, func(source vfs.RenameCommitSource) (vfs.RenameCommitResult, error) {
		return hctx.commitHostSaveRename("/save/old.txt", "/save/new.txt", source, hostSaveRenameOptions{
			replaceExisting: true,
			allowCopy:       true,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldHost); !os.IsNotExist(err) {
		t.Fatalf("old host file still exists, err=%v", err)
	}
	if data, err := os.ReadFile(newHost); err != nil || string(data) != "content" {
		t.Fatalf("new host data = %q, err=%v", data, err)
	}
	if _, ok := hctx.HostSavePaths["/save/old.txt"]; ok {
		t.Fatal("source binding still exists")
	}
	if hctx.HostSavePaths["/save/new.txt"] != newHost {
		t.Fatalf("destination binding = %q", hctx.HostSavePaths["/save/new.txt"])
	}
}

func TestCommitHostSaveRenameUsesDestinationDirectory(t *testing.T) {
	hostRoot := t.TempDir()
	sourceDir := filepath.Join(hostRoot, "source")
	targetDir := filepath.Join(hostRoot, "target")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	oldHost := filepath.Join(sourceDir, "old.txt")
	newHost := filepath.Join(targetDir, "new.txt")
	if err := os.WriteFile(oldHost, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldVFS := filepath.ToSlash(oldHost)
	newVFS := filepath.ToSlash(newHost)
	fs := vfs.New()
	fs.MkdirAll(filepath.ToSlash(sourceDir))
	fs.MkdirAll(filepath.ToSlash(targetDir))
	if err := fs.CreateFile(oldVFS, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath(oldVFS, oldHost)

	err := fs.RenameatWithCommit(-1, oldVFS, -1, newVFS, vfs.RenameOptions{RejectExistingDirectory: true}, func(source vfs.RenameCommitSource) (vfs.RenameCommitResult, error) {
		return hctx.commitHostSaveRename(oldVFS, newVFS, source, hostSaveRenameOptions{
			allowCopy: true,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sourceDir, "new.txt")); !os.IsNotExist(err) {
		t.Fatalf("file was moved within the source directory, err=%v", err)
	}
	if data, err := os.ReadFile(newHost); err != nil || string(data) != "content" {
		t.Fatalf("destination data = %q, err=%v", data, err)
	}
}

func TestCommitHostSaveRenameDoesNotReplaceUnboundHostTarget(t *testing.T) {
	hostDir := t.TempDir()
	oldHost := filepath.Join(hostDir, "old.txt")
	newHost := filepath.Join(hostDir, "new.txt")
	if err := os.WriteFile(oldHost, []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newHost, []byte("destination"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldVFS := filepath.ToSlash(oldHost)
	newVFS := filepath.ToSlash(newHost)
	fs := vfs.New()
	fs.MkdirAll(filepath.ToSlash(hostDir))
	if err := fs.CreateFile(oldVFS, []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath(oldVFS, oldHost)

	err := fs.RenameatWithCommit(-1, oldVFS, -1, newVFS, vfs.RenameOptions{RejectExistingDirectory: true}, func(source vfs.RenameCommitSource) (vfs.RenameCommitResult, error) {
		return hctx.commitHostSaveRename(oldVFS, newVFS, source, hostSaveRenameOptions{
			allowCopy: true,
		})
	})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("rename error = %v, want destination-exists error", err)
	}
	if data, err := os.ReadFile(oldHost); err != nil || string(data) != "source" {
		t.Fatalf("source host data = %q, err=%v", data, err)
	}
	if data, err := os.ReadFile(newHost); err != nil || string(data) != "destination" {
		t.Fatalf("destination host data = %q, err=%v", data, err)
	}
	if _, err := fs.StatPath(-1, oldVFS); err != nil {
		t.Fatalf("source VFS entry was removed: %v", err)
	}
	if _, err := fs.Resolve(newVFS); err == nil {
		t.Fatal("destination VFS entry was created after failed rename")
	}
}

func TestCommitHostSaveRenameKeepsSourceWhenCrossVolumeDeleteFails(t *testing.T) {
	hostDir := t.TempDir()
	oldHost := filepath.Join(hostDir, "old.txt")
	newHost := filepath.Join(hostDir, "new.txt")
	if err := os.WriteFile(oldHost, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldVFS := filepath.ToSlash(oldHost)
	newVFS := filepath.ToSlash(newHost)
	fs := vfs.New()
	fs.MkdirAll(filepath.ToSlash(hostDir))
	if err := fs.CreateFile(oldVFS, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath(oldVFS, oldHost)
	ops := defaultHostSaveRenameOps
	ops.rename = func(_, _ string, _ bool) error { return syscall.EXDEV }
	ops.remove = func(string) error { return syscall.EPERM }

	err := fs.RenameatWithCommit(-1, oldVFS, -1, newVFS, vfs.RenameOptions{RejectExistingDirectory: true}, func(source vfs.RenameCommitSource) (vfs.RenameCommitResult, error) {
		return hctx.commitHostSaveRenameWithOps(oldVFS, newVFS, source, hostSaveRenameOptions{
			allowCopy: true,
		}, ops)
	})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(oldHost); err != nil || string(data) != "content" {
		t.Fatalf("source host data = %q, err=%v", data, err)
	}
	if data, err := os.ReadFile(newHost); err != nil || string(data) != "content" {
		t.Fatalf("destination host data = %q, err=%v", data, err)
	}
	if _, err := fs.StatPath(-1, oldVFS); err != nil {
		t.Fatalf("source VFS entry is missing: %v", err)
	}
	if _, err := fs.StatPath(-1, newVFS); err != nil {
		t.Fatalf("destination VFS entry is missing: %v", err)
	}
	if hctx.HostSavePaths[oldVFS] != oldHost {
		t.Fatalf("source binding = %q", hctx.HostSavePaths[oldVFS])
	}
	if hctx.HostSavePaths[newVFS] != newHost {
		t.Fatalf("destination binding = %q", hctx.HostSavePaths[newVFS])
	}
}

func TestCommitHostSaveRenameRejectsCrossVolumeMoveWithoutCopy(t *testing.T) {
	hostDir := t.TempDir()
	oldHost := filepath.Join(hostDir, "old.txt")
	newHost := filepath.Join(hostDir, "new.txt")
	if err := os.WriteFile(oldHost, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldVFS := filepath.ToSlash(oldHost)
	newVFS := filepath.ToSlash(newHost)
	fs := vfs.New()
	fs.MkdirAll(filepath.ToSlash(hostDir))
	if err := fs.CreateFile(oldVFS, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath(oldVFS, oldHost)
	ops := defaultHostSaveRenameOps
	ops.rename = func(_, _ string, _ bool) error { return syscall.EXDEV }

	err := fs.RenameatWithCommit(-1, oldVFS, -1, newVFS, vfs.RenameOptions{RejectExistingDirectory: true}, func(source vfs.RenameCommitSource) (vfs.RenameCommitResult, error) {
		return hctx.commitHostSaveRenameWithOps(oldVFS, newVFS, source, hostSaveRenameOptions{}, ops)
	})
	if !errors.Is(err, syscall.EXDEV) {
		t.Fatalf("rename error = %v, want EXDEV", err)
	}
	if _, err := os.Stat(oldHost); err != nil {
		t.Fatalf("source host file is missing: %v", err)
	}
	if _, err := os.Stat(newHost); !os.IsNotExist(err) {
		t.Fatalf("destination host file exists, err=%v", err)
	}
	if _, err := fs.StatPath(-1, oldVFS); err != nil {
		t.Fatalf("source VFS entry is missing: %v", err)
	}
	if _, err := fs.StatPath(-1, newVFS); err == nil {
		t.Fatal("destination VFS entry exists after failed move")
	}
}

func TestCommitHostSaveRenameRejectsCrossVolumeDirectory(t *testing.T) {
	hostRoot := t.TempDir()
	oldHost := filepath.Join(hostRoot, "source")
	newHost := filepath.Join(hostRoot, "target")
	if err := os.Mkdir(oldHost, 0o755); err != nil {
		t.Fatal(err)
	}
	oldVFS := filepath.ToSlash(oldHost)
	newVFS := filepath.ToSlash(newHost)
	fs := vfs.New()
	fs.MkdirAll(oldVFS)
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath(oldVFS, oldHost)
	writeCalled := false
	ops := defaultHostSaveRenameOps
	ops.rename = func(_, _ string, _ bool) error { return syscall.EXDEV }
	ops.write = func(string, []byte, bool) error {
		writeCalled = true
		return nil
	}

	err := fs.RenameatWithCommit(-1, oldVFS, -1, newVFS, vfs.RenameOptions{RejectExistingDirectory: true}, func(source vfs.RenameCommitSource) (vfs.RenameCommitResult, error) {
		return hctx.commitHostSaveRenameWithOps(oldVFS, newVFS, source, hostSaveRenameOptions{
			allowCopy: true,
		}, ops)
	})
	if !errors.Is(err, syscall.EXDEV) {
		t.Fatalf("rename error = %v, want EXDEV", err)
	}
	if writeCalled {
		t.Fatal("cross-volume directory was copied as file data")
	}
	if info, err := os.Stat(oldHost); err != nil || !info.IsDir() {
		t.Fatalf("source host directory changed: info=%v err=%v", info, err)
	}
	if _, err := os.Stat(newHost); !os.IsNotExist(err) {
		t.Fatalf("destination host path exists, err=%v", err)
	}
	if node, err := fs.StatPath(-1, oldVFS); err != nil || !node.IsDir {
		t.Fatalf("source VFS directory changed: node=%v err=%v", node, err)
	}
}

func TestCommitHostSaveRenameRejectsUnboundDirectoryToBoundFile(t *testing.T) {
	hostDir := t.TempDir()
	targetHost := filepath.Join(hostDir, "target")
	sourceVFS := "/save/source"
	targetVFS := "/save/target"
	fs := vfs.New()
	fs.MkdirAll(sourceVFS)
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath(targetVFS, targetHost)

	err := fs.RenameatWithCommit(-1, sourceVFS, -1, targetVFS, vfs.RenameOptions{
		RejectExistingDirectory: true,
	}, func(source vfs.RenameCommitSource) (vfs.RenameCommitResult, error) {
		return hctx.commitHostSaveRename(sourceVFS, targetVFS, source, hostSaveRenameOptions{})
	})
	if !errors.Is(err, syscall.EISDIR) {
		t.Fatalf("rename error = %v, want EISDIR", err)
	}
	if _, err := os.Stat(targetHost); !os.IsNotExist(err) {
		t.Fatalf("bound host target was created, err=%v", err)
	}
	if node, err := fs.StatPath(-1, sourceVFS); err != nil || !node.IsDir {
		t.Fatalf("source VFS directory changed: node=%v err=%v", node, err)
	}
}

func TestCommitHostSaveRenameDoesNotReplaceExistingHostDirectory(t *testing.T) {
	hostRoot := t.TempDir()
	oldHost := filepath.Join(hostRoot, "source")
	newHost := filepath.Join(hostRoot, "target")
	if err := os.Mkdir(oldHost, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(newHost, 0o755); err != nil {
		t.Fatal(err)
	}
	oldVFS := filepath.ToSlash(oldHost)
	newVFS := filepath.ToSlash(newHost)
	fs := vfs.New()
	fs.MkdirAll(oldVFS)
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath(oldVFS, oldHost)

	err := fs.RenameatWithCommit(-1, oldVFS, -1, newVFS, vfs.RenameOptions{
		ReplaceExisting:         true,
		RejectExistingDirectory: true,
	}, func(source vfs.RenameCommitSource) (vfs.RenameCommitResult, error) {
		return hctx.commitHostSaveRename(oldVFS, newVFS, source, hostSaveRenameOptions{
			replaceExisting: true,
			allowCopy:       true,
		})
	})
	if !errors.Is(err, os.ErrExist) && !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("rename error = %v, want destination-exists error", err)
	}
	if info, err := os.Stat(oldHost); err != nil || !info.IsDir() {
		t.Fatalf("source host directory changed: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(newHost); err != nil || !info.IsDir() {
		t.Fatalf("destination host directory changed: info=%v err=%v", info, err)
	}
	if node, err := fs.StatPath(-1, oldVFS); err != nil || !node.IsDir {
		t.Fatalf("source VFS directory changed: node=%v err=%v", node, err)
	}
}

func TestCommitHostSaveRenameTreatsMissingCrossVolumeSourceAsDeleted(t *testing.T) {
	hostDir := t.TempDir()
	oldHost := filepath.Join(hostDir, "old.txt")
	newHost := filepath.Join(hostDir, "new.txt")
	if err := os.WriteFile(oldHost, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldVFS := filepath.ToSlash(oldHost)
	newVFS := filepath.ToSlash(newHost)
	fs := vfs.New()
	fs.MkdirAll(filepath.ToSlash(hostDir))
	if err := fs.CreateFile(oldVFS, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath(oldVFS, oldHost)
	ops := defaultHostSaveRenameOps
	ops.rename = func(_, _ string, _ bool) error { return syscall.EXDEV }
	ops.remove = func(path string) error {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		return os.ErrNotExist
	}

	err := fs.RenameatWithCommit(-1, oldVFS, -1, newVFS, vfs.RenameOptions{RejectExistingDirectory: true}, func(source vfs.RenameCommitSource) (vfs.RenameCommitResult, error) {
		return hctx.commitHostSaveRenameWithOps(oldVFS, newVFS, source, hostSaveRenameOptions{
			allowCopy: true,
		}, ops)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldHost); !os.IsNotExist(err) {
		t.Fatalf("source host file exists, err=%v", err)
	}
	if _, err := fs.StatPath(-1, oldVFS); err == nil {
		t.Fatal("source VFS entry remains after host source disappeared")
	}
	if data, err := os.ReadFile(newHost); err != nil || string(data) != "content" {
		t.Fatalf("destination host data = %q, err=%v", data, err)
	}
}

func TestCommitHostSaveRenameHandlesCaseOnlyNames(t *testing.T) {
	hostDir := t.TempDir()
	oldHost := filepath.Join(hostDir, "Document.txt")
	newHost := filepath.Join(hostDir, "document.TXT")
	if err := os.WriteFile(oldHost, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldVFS := filepath.ToSlash(oldHost)
	newVFS := filepath.ToSlash(newHost)
	fs := vfs.New()
	fs.MkdirAll(filepath.ToSlash(hostDir))
	if err := fs.CreateFile(oldVFS, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath(oldVFS, oldHost)

	err := fs.RenameatWithCommit(-1, strings.ToUpper(oldVFS), -1, newVFS, vfs.RenameOptions{RejectExistingDirectory: true}, func(source vfs.RenameCommitSource) (vfs.RenameCommitResult, error) {
		return hctx.commitHostSaveRename(strings.ToUpper(oldVFS), newVFS, source, hostSaveRenameOptions{
			allowCopy: true,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldHost); !os.IsNotExist(err) {
		t.Fatalf("old case-sensitive host path still exists, err=%v", err)
	}
	if data, err := os.ReadFile(newHost); err != nil || string(data) != "content" {
		t.Fatalf("new host data = %q, err=%v", data, err)
	}
	if len(hctx.HostSavePaths) != 1 || hctx.HostSavePaths[newVFS] != newHost {
		t.Fatalf("host bindings = %#v", hctx.HostSavePaths)
	}
}

func TestHostSavePathFromVFSMapsWindowsProfile(t *testing.T) {
	vfsPath := "/Users/" + shellUserName() + "/Documents/file.txt"
	want := filepath.Join(shellHomeDir(), "Documents", "file.txt")
	if got := hostSavePathFromVFS(vfsPath); got != want {
		t.Fatalf("host path = %q, want %q", got, want)
	}
}

func TestHostSaveMoveErrorCode(t *testing.T) {
	tests := []struct {
		err  error
		want uint32
	}{
		{err: os.ErrNotExist, want: 2},
		{err: os.ErrExist, want: 183},
		{err: syscall.EXDEV, want: 17},
		{err: syscall.ENOTDIR, want: 3},
		{err: syscall.EPERM, want: 5},
	}
	for _, test := range tests {
		if got := hostSaveMoveErrorCode(test.err); got != test.want {
			t.Errorf("hostSaveMoveErrorCode(%v) = %d, want %d", test.err, got, test.want)
		}
	}
}

func TestSyncHostSaveReplacePersistsTargetAndBackup(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/save")
	if err := fs.CreateFile("/save/document.txt", []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := fs.CreateFile("/save/document.tmp", []byte("replacement"), 0644); err != nil {
		t.Fatal(err)
	}
	hostDir := t.TempDir()
	targetHost := filepath.Join(hostDir, "document.txt")
	tempHost := filepath.Join(hostDir, "document.tmp")
	if err := os.WriteFile(targetHost, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tempHost, []byte("replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTargetInfo, err := os.Stat(targetHost)
	if err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath("/save/document.txt", targetHost)
	hctx.bindHostSavePath("/save/document.tmp", tempHost)
	tempInfo, err := os.Stat(tempHost)
	if err != nil {
		t.Fatal(err)
	}
	if err := replaceVFSFileWithHost(fs, hctx, "/save/document.txt", "/save/document.tmp", "/save/document.bak"); err != nil {
		t.Fatal(err)
	}

	if data, err := os.ReadFile(targetHost); err != nil || string(data) != "replacement" {
		t.Fatalf("target data = %q, err=%v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(hostDir, "document.bak")); err != nil || string(data) != "old" {
		t.Fatalf("backup data = %q, err=%v", data, err)
	}
	backupInfo, err := os.Stat(filepath.Join(hostDir, "document.bak"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(oldTargetInfo, backupInfo) {
		t.Fatal("backup did not preserve replaced host identity")
	}
	if _, err := os.Stat(tempHost); !os.IsNotExist(err) {
		t.Fatalf("temporary host file still exists, err=%v", err)
	}
	targetInfo, err := os.Stat(targetHost)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(tempInfo, targetInfo) {
		t.Fatal("target did not preserve replacement host identity")
	}
	if targetInfo.Mode().Perm() != 0o600 {
		t.Fatalf("target mode = %o, want 600", targetInfo.Mode().Perm())
	}
}

func TestSyncHostSaveReplaceKeepsBindingsOnWriteFailure(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/save")
	if err := fs.CreateFile("/save/document.txt", []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := fs.CreateFile("/save/document.tmp", []byte("replacement"), 0644); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{}
	targetHost := filepath.Join(t.TempDir(), "missing", "document.txt")
	tempHost := filepath.Join(t.TempDir(), "document.tmp")
	hctx.bindHostSavePath("/save/document.txt", targetHost)
	hctx.bindHostSavePath("/save/document.tmp", tempHost)

	if err := replaceVFSFileWithHost(fs, hctx, "/save/document.txt", "/save/document.tmp", "/save/document.bak"); err == nil {
		t.Fatal("host write failure was ignored")
	}
	if hctx.HostSavePaths["/save/document.txt"] != targetHost {
		t.Fatal("target binding changed after failure")
	}
	if hctx.HostSavePaths["/save/document.tmp"] != tempHost {
		t.Fatal("replacement binding changed after failure")
	}
	assertVFSFileData(t, fs, "/save/document.txt", "old")
	assertVFSFileData(t, fs, "/save/document.tmp", "replacement")
	if _, err := fs.StatPath(-1, "/save/document.bak"); err == nil {
		t.Fatal("VFS backup was created after host failure")
	}
}

func TestUnbindHostSavePathRemovesDirectoryDescendantsCaseInsensitively(t *testing.T) {
	hctx := &HandlerCtx{}
	hctx.bindHostSavePath("/Work/Tree", "/host/tree")
	hctx.bindHostSavePath("/work/tree/child.txt", "/host/tree/child.txt")
	hctx.bindHostSavePath("/work/other.txt", "/host/other.txt")

	hctx.unbindHostSavePath("/WORK/TREE")

	if len(hctx.HostSavePaths) != 1 || hctx.HostSavePaths["/work/other.txt"] != "/host/other.txt" {
		t.Fatalf("host bindings = %#v", hctx.HostSavePaths)
	}
}
