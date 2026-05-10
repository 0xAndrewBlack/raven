//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/vfs"
)

func TestReplaceVFSFileWithBackup(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/work")
	if err := fs.CreateFile("/work/document.txt", []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := fs.CreateFile("/work/replacement.tmp", []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	replacementBefore, err := fs.StatPath(-1, "/work/replacement.tmp")
	if err != nil {
		t.Fatal(err)
	}
	replacedBefore, err := fs.StatPath(-1, "/work/document.txt")
	if err != nil {
		t.Fatal(err)
	}

	if err := replaceVFSFile(fs, "/work/document.txt", "/work/replacement.tmp", "/work/document.bak"); err != nil {
		t.Fatal(err)
	}
	assertVFSFileData(t, fs, "/work/document.txt", "new")
	assertVFSFileData(t, fs, "/work/document.bak", "old")
	replacementAfter, _ := fs.StatPath(-1, "/work/document.txt")
	backupAfter, _ := fs.StatPath(-1, "/work/document.bak")
	if replacementAfter.Ino != replacementBefore.Ino {
		t.Fatalf("replacement inode changed from %d to %d", replacementBefore.Ino, replacementAfter.Ino)
	}
	if replacementAfter.Mode != replacedBefore.Mode {
		t.Fatalf("replacement mode = %o, want %o", replacementAfter.Mode, replacedBefore.Mode)
	}
	if !replacementAfter.Ctime.Equal(replacedBefore.Ctime) {
		t.Fatalf("replacement creation time = %v, want %v", replacementAfter.Ctime, replacedBefore.Ctime)
	}
	if backupAfter.Ino != replacedBefore.Ino {
		t.Fatalf("backup inode changed from %d to %d", replacedBefore.Ino, backupAfter.Ino)
	}
	if _, err := fs.StatPath(-1, "/work/replacement.tmp"); err == nil {
		t.Fatal("replacement file still exists")
	}
}

func TestReplaceVFSFileRejectsAliases(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/work")
	if err := fs.CreateFile("/work/document.txt", []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		replacement string
		backup      string
	}{
		{replacement: "/work/DOCUMENT.TXT"},
		{replacement: "/work/replacement.tmp", backup: "/work/document.txt"},
		{replacement: "/work/replacement.tmp", backup: "/work/REPLACEMENT.tmp"},
	} {
		if test.replacement != "/work/DOCUMENT.TXT" {
			if err := fs.CreateFile("/work/replacement.tmp", []byte("new"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		if err := replaceVFSFile(fs, "/work/document.txt", test.replacement, test.backup); err == nil {
			t.Fatalf("replace accepted alias replacement=%q backup=%q", test.replacement, test.backup)
		}
		assertVFSFileData(t, fs, "/work/document.txt", "content")
	}
}

func TestReplaceVFSFileUsesExistingCaseInsensitiveEntries(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/work")
	if err := fs.CreateFile("/work/Document.txt", []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := fs.CreateFile("/work/Replacement.tmp", []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := replaceVFSFile(fs, "/work/DOCUMENT.TXT", "/work/replacement.TMP", "/work/Document.bak"); err != nil {
		t.Fatal(err)
	}
	assertVFSFileData(t, fs, "/work/Document.txt", "new")
	assertVFSFileData(t, fs, "/work/document.bak", "old")
}

func TestReplaceVFSFileValidatesBeforeMutation(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/work")
	if err := fs.CreateFile("/work/document.txt", []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := replaceVFSFile(fs, "/work/document.txt", "/work/missing.tmp", "/missing/document.bak"); err == nil {
		t.Fatal("replace succeeded with a missing replacement")
	}
	assertVFSFileData(t, fs, "/work/document.txt", "old")
}

func TestReplaceVFSFileWithoutBackup(t *testing.T) {
	fs := vfs.New()
	fs.MkdirAll("/work")
	if err := fs.CreateFile("/work/document.txt", []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := fs.CreateFile("/work/replacement.tmp", []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := replaceVFSFile(fs, "/work/document.txt", "/work/replacement.tmp", ""); err != nil {
		t.Fatal(err)
	}
	assertVFSFileData(t, fs, "/work/document.txt", "new")
}

func TestSameWindowsVolume(t *testing.T) {
	if !sameWindowsVolume(`C:\work\one`, `c:\work\two`, `relative.bak`) {
		t.Fatal("same drive was rejected")
	}
	if sameWindowsVolume(`C:\work\one`, `D:\work\two`) {
		t.Fatal("different drives were accepted")
	}
	if sameWindowsVolume(`\\server\share\one`, `\\server\other\two`) {
		t.Fatal("different UNC shares were accepted")
	}
}

func assertVFSFileData(t *testing.T, fs *vfs.VFS, path, want string) {
	t.Helper()
	node, err := fs.StatPath(-1, path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(node.Data); got != want {
		t.Fatalf("%s data = %q, want %q", path, got, want)
	}
}
