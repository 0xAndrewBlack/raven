//go:build guest_windows

package main

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/vfs"
)

func TestSHFileOperationLayouts(t *testing.T) {
	pe32 := shFileOperationLayoutFor(true)
	if pe32.functionOffset != 4 || pe32.fromOffset != 8 || pe32.toOffset != 12 || pe32.flagsOffset != 16 || pe32.abortedOffset != 20 {
		t.Fatalf("PE32 layout = %+v", pe32)
	}
	pe64 := shFileOperationLayoutFor(false)
	if pe64.functionOffset != 8 || pe64.fromOffset != 16 || pe64.toOffset != 24 || pe64.flagsOffset != 32 || pe64.abortedOffset != 36 {
		t.Fatalf("PE64 layout = %+v", pe64)
	}
}

func TestSHFileOperationDeleteMovesFileToTrash(t *testing.T) {
	dataHome := filepath.Join(t.TempDir(), "data home")
	t.Setenv("XDG_DATA_HOME", dataHome)
	sourceDir := t.TempDir()
	source := filepath.Join(sourceDir, "file with spaces.txt")
	if err := os.WriteFile(source, []byte("trash payload"), 0o640); err != nil {
		t.Fatal(err)
	}

	mem := mmu.New()
	const fileOp = uint64(0x4000)
	const from = uint64(0x5000)
	mem.MapRange(fileOp, mmu.PageSize*2, mmu.PermRead|mmu.PermWrite)
	layout := shFileOperationLayoutFor(false)
	mem.Write32(fileOp+layout.functionOffset, 3)
	writeGuestPointer(mem, fileOp+layout.fromOffset, from, false)
	mem.Write16(fileOp+layout.flagsOffset, 0x40)
	chars := writeWideString(mem, from, linuxToWinPath(source), 1024)
	mem.Write16(from+uint64(chars+1)*2, 0)

	if err := shFileOperationHost(mem, fileOp, true, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatalf("source still exists: %v", err)
	}
	trashed := filepath.Join(dataHome, "Trash", "files", filepath.Base(source))
	if data, err := os.ReadFile(trashed); err != nil || string(data) != "trash payload" {
		t.Fatalf("trashed data = %q, err = %v", data, err)
	}
	infoPath := filepath.Join(dataHome, "Trash", "info", filepath.Base(source)+".trashinfo")
	info, err := os.ReadFile(infoPath)
	if err != nil {
		t.Fatal(err)
	}
	escapedSource := (&url.URL{Path: source}).EscapedPath()
	if !strings.Contains(string(info), "Path="+escapedSource+"\n") || !strings.Contains(string(info), "DeletionDate=") {
		t.Fatalf("trash info = %q", info)
	}
	if aborted, _ := mem.Read32(fileOp + layout.abortedOffset); aborted != 0 {
		t.Fatalf("fAnyOperationsAborted = %d", aborted)
	}
}

func TestMoveHostPathToTrashUsesUniqueName(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	now := time.Date(2026, 7, 25, 12, 34, 56, 0, time.Local)
	for i, content := range []string{"first", "second"} {
		sourceDir := t.TempDir()
		source := filepath.Join(sourceDir, "duplicate.txt")
		if err := os.WriteFile(source, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := moveHostPathToTrash(source, now); err != nil {
			t.Fatalf("move %d: %v", i, err)
		}
	}
	for name, content := range map[string]string{"duplicate.txt": "first", "duplicate.txt.1": "second"} {
		data, err := os.ReadFile(filepath.Join(dataHome, "Trash", "files", name))
		if err != nil || string(data) != content {
			t.Fatalf("%s = %q, err = %v", name, data, err)
		}
	}
}

func TestSHFileOperationReadsPE32Structure(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	source := filepath.Join(t.TempDir(), "pe32.txt")
	if err := os.WriteFile(source, []byte("pe32"), 0o600); err != nil {
		t.Fatal(err)
	}

	mem := mmu.New()
	const fileOp = uint64(0x4000)
	const from = uint64(0x5000)
	mem.MapRange(fileOp, mmu.PageSize*2, mmu.PermRead|mmu.PermWrite)
	layout := shFileOperationLayoutFor(true)
	mem.Write32(fileOp+layout.functionOffset, 3)
	writeGuestPointer(mem, fileOp+layout.fromOffset, from, true)
	mem.Write16(fileOp+layout.flagsOffset, 0x40)
	chars := writeWideString(mem, from, linuxToWinPath(source), 1024)
	mem.Write16(from+uint64(chars+1)*2, 0)

	if err := shFileOperationHost(mem, fileOp, true, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataHome, "Trash", "files", "pe32.txt")); err != nil {
		t.Fatal(err)
	}
}

func TestCopyTrashPathCopiesReadOnlyDirectory(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	t.Cleanup(func() {
		os.Chmod(source, 0o755)
		os.Chmod(target, 0o755)
	})
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "child.txt"), []byte("child"), 0o600); err != nil {
		t.Fatal(err)
	}
	modTime := time.Date(2026, 7, 24, 1, 2, 3, 0, time.Local)
	if err := os.Chmod(source, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(source, modTime, modTime); err != nil {
		t.Fatal(err)
	}

	if err := copyTrashPath(source, target); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(target, "child.txt"))
	if err != nil || string(data) != "child" {
		t.Fatalf("copied child = %q, err = %v", data, err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o555 {
		t.Fatalf("target mode = %#o", info.Mode().Perm())
	}
	if !info.ModTime().Equal(modTime) {
		t.Fatalf("target mtime = %v, want %v", info.ModTime(), modTime)
	}
}

func TestCopyTrashPathPreservesRegularFileMetadata(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	target := filepath.Join(root, "target.txt")
	if err := os.WriteFile(source, []byte("metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source, 0o644); err != nil {
		t.Fatal(err)
	}
	accessTime := time.Date(2026, 7, 23, 1, 2, 3, 0, time.Local)
	modTime := time.Date(2026, 7, 24, 4, 5, 6, 0, time.Local)
	if err := os.Chtimes(source, accessTime, modTime); err != nil {
		t.Fatal(err)
	}
	oldUmask := syscall.Umask(0o077)
	defer syscall.Umask(oldUmask)

	if err := copyTrashPath(source, target); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("target mode = %#o", info.Mode().Perm())
	}
	if !info.ModTime().Equal(modTime) {
		t.Fatalf("target mtime = %v, want %v", info.ModTime(), modTime)
	}
	if got := trashAccessTime(info); !got.Equal(accessTime) {
		t.Fatalf("target atime = %v, want %v", got, accessTime)
	}
}

func TestMoveHostPathToTrashCrossDeviceStagesBeforeCopy(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	sourceDir := t.TempDir()
	source := filepath.Join(sourceDir, "source.txt")
	if err := os.WriteFile(source, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	ops := defaultTrashMoveOps
	ops.rename = func(string, string) error { return syscall.EXDEV }
	ops.copy = func(staged, target string) error {
		if filepath.Dir(staged) != sourceDir || staged == source {
			t.Fatalf("copy source was not staged: %q", staged)
		}
		if err := os.WriteFile(source, []byte("replacement"), 0o600); err != nil {
			return err
		}
		return copyTrashPath(staged, target)
	}

	if err := moveHostPathToTrashWithOps(source, time.Now(), ops); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(source); err != nil || string(data) != "replacement" {
		t.Fatalf("replacement source = %q, err = %v", data, err)
	}
	target := filepath.Join(dataHome, "Trash", "files", filepath.Base(source))
	if data, err := os.ReadFile(target); err != nil || string(data) != "original" {
		t.Fatalf("trashed data = %q, err = %v", data, err)
	}
	staged, err := filepath.Glob(filepath.Join(sourceDir, ".source.txt.raven-trash-*"))
	if err != nil || len(staged) != 0 {
		t.Fatalf("staged paths = %v, err = %v", staged, err)
	}
}

func TestMoveHostPathToTrashCrossDeviceDoesNotRemoveCollidingTarget(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	source := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(source, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	ops := defaultTrashMoveOps
	ops.rename = func(string, string) error { return syscall.EXDEV }
	collisionInjected := false
	ops.renameNoReplace = func(sourcePath, targetPath string, replaceExisting bool) error {
		if filepath.Base(sourcePath) == "payload" && !collisionInjected {
			collisionInjected = true
			if err := os.WriteFile(targetPath, []byte("foreign"), 0o600); err != nil {
				return err
			}
			return os.ErrExist
		}
		return renameHostSaveFile(sourcePath, targetPath, replaceExisting)
	}

	if err := moveHostPathToTrashWithOps(source, time.Now(), ops); err != nil {
		t.Fatal(err)
	}
	filesDir := filepath.Join(dataHome, "Trash", "files")
	if data, err := os.ReadFile(filepath.Join(filesDir, "source.txt")); err != nil || string(data) != "foreign" {
		t.Fatalf("colliding target = %q, err = %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(filesDir, "source.txt.1")); err != nil || string(data) != "original" {
		t.Fatalf("trashed target = %q, err = %v", data, err)
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("source still exists: %v", err)
	}
}

func TestMoveHostPathToTrashRollsBackFailedCrossDeviceCopy(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	sourceDir := t.TempDir()
	source := filepath.Join(sourceDir, "source.txt")
	if err := os.WriteFile(source, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	copyErr := errors.New("copy failed")
	ops := defaultTrashMoveOps
	ops.rename = func(string, string) error { return syscall.EXDEV }
	ops.copy = func(string, string) error { return copyErr }

	if err := moveHostPathToTrashWithOps(source, time.Now(), ops); !errors.Is(err, copyErr) {
		t.Fatalf("error = %v, want %v", err, copyErr)
	}
	if data, err := os.ReadFile(source); err != nil || string(data) != "original" {
		t.Fatalf("rolled back source = %q, err = %v", data, err)
	}
	staged, err := filepath.Glob(filepath.Join(sourceDir, ".source.txt.raven-trash-*"))
	if err != nil || len(staged) != 0 {
		t.Fatalf("staged paths = %v, err = %v", staged, err)
	}
	files, err := os.ReadDir(filepath.Join(dataHome, "Trash", "files"))
	if err != nil || len(files) != 0 {
		t.Fatalf("trash files = %v, err = %v", files, err)
	}
	info, err := os.ReadDir(filepath.Join(dataHome, "Trash", "info"))
	if err != nil || len(info) != 0 {
		t.Fatalf("trash info = %v, err = %v", info, err)
	}
}

func TestMoveHostPathToTrashPreservesCopyWhenCleanupFails(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	sourceDir := t.TempDir()
	source := filepath.Join(sourceDir, "source.txt")
	if err := os.WriteFile(source, []byte("recoverable"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanupErr := errors.New("cleanup failed")
	ops := defaultTrashMoveOps
	ops.rename = func(string, string) error { return syscall.EXDEV }
	ops.removeAll = func(string) error { return cleanupErr }

	if err := moveHostPathToTrashWithOps(source, time.Now(), ops); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dataHome, "Trash", "files", filepath.Base(source))
	if data, err := os.ReadFile(target); err != nil || string(data) != "recoverable" {
		t.Fatalf("trashed data = %q, err = %v", data, err)
	}
	info := filepath.Join(dataHome, "Trash", "info", filepath.Base(source)+".trashinfo")
	if _, err := os.Stat(info); err != nil {
		t.Fatal(err)
	}
	staged, err := filepath.Glob(filepath.Join(sourceDir, ".source.txt.raven-trash-*"))
	if err != nil || len(staged) != 1 {
		t.Fatalf("staged paths = %v, err = %v", staged, err)
	}
}

func TestSHFileOperationDeleteRemovesVFSAndHostBinding(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	source := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(source, []byte("host"), 0o600); err != nil {
		t.Fatal(err)
	}
	vfsPath := winPathToVFS(linuxToWinPath(source))
	fs := vfs.New()
	fs.MkdirAll(filepath.Dir(vfsPath))
	if err := fs.CreateFile(vfsPath, []byte("vfs"), vfs.ModeRead|vfs.ModeWrite); err != nil {
		t.Fatal(err)
	}
	hctx := &HandlerCtx{HostSavePaths: map[string]string{vfsPath: source}}

	mem := mmu.New()
	const fileOp = uint64(0x4000)
	const from = uint64(0x5000)
	mem.MapRange(fileOp, mmu.PageSize*2, mmu.PermRead|mmu.PermWrite)
	layout := shFileOperationLayoutFor(false)
	mem.Write32(fileOp+layout.functionOffset, 3)
	writeGuestPointer(mem, fileOp+layout.fromOffset, from, false)
	mem.Write16(fileOp+layout.flagsOffset, 0x40)
	chars := writeWideString(mem, from, linuxToWinPath(source), 1024)
	mem.Write16(from+uint64(chars+1)*2, 0)

	if err := shFileOperationHost(mem, fileOp, true, false, fs, hctx); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.StatPath(-1, vfsPath); err == nil {
		t.Fatal("deleted file remains in VFS")
	}
	if len(hctx.HostSavePaths) != 0 {
		t.Fatalf("host bindings = %#v", hctx.HostSavePaths)
	}
}

func TestTrashDataRootRejectsRelativeXDGDataHome(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "relative")
	if _, err := trashDataRoot(); err == nil {
		t.Fatal("relative XDG_DATA_HOME was accepted")
	}
}

func TestValidateShellDeletePathRejectsRoot(t *testing.T) {
	if err := validateShellDeletePath("/"); err == nil {
		t.Fatal("filesystem root was accepted")
	}
	if err := validateShellDeletePath("relative"); err == nil {
		t.Fatal("relative path was accepted")
	}
	if err := validateShellDeletePath(filepath.Join(t.TempDir(), "file.txt")); err != nil {
		t.Fatalf("safe path rejected: %v", err)
	}
}

func TestSHFileOperationClearsAbortedFlagOnError(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	mem := mmu.New()
	const fileOp = uint64(0x4000)
	const from = uint64(0x5000)
	mem.MapRange(fileOp, mmu.PageSize*2, mmu.PermRead|mmu.PermWrite)
	layout := shFileOperationLayoutFor(false)
	mem.Write32(fileOp+layout.functionOffset, 99)
	mem.Write32(fileOp+layout.abortedOffset, 1)
	writeGuestPointer(mem, fileOp+layout.fromOffset, from, false)
	chars := writeWideString(mem, from, linuxToWinPath(source), 1024)
	mem.Write16(from+uint64(chars+1)*2, 0)

	if err := shFileOperationHost(mem, fileOp, true, false, nil, nil); err == nil {
		t.Fatal("unsupported operation succeeded")
	}
	if aborted, _ := mem.Read32(fileOp + layout.abortedOffset); aborted != 0 {
		t.Fatalf("fAnyOperationsAborted = %d", aborted)
	}
}
