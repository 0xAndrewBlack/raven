//go:build guest_windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/vfs"
)

func TestPreparePEGuestArgsImportsHostFile(t *testing.T) {
	hostPath := filepath.Join(t.TempDir(), "file with spaces.txt")
	if err := os.WriteFile(hostPath, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := vfs.New()
	args, hostPaths := preparePEGuestArgs(fs, "/opt/npp/notepad++.exe", []string{"notepad++.exe", hostPath})
	if args[0] != `C:\npp\notepad++.exe` {
		t.Fatalf("image argument = %q", args[0])
	}
	guestPath := linuxToWinPath(hostPath)
	if args[1] != guestPath {
		t.Fatalf("file argument = %q, want %q", args[1], guestPath)
	}
	vfsPath := winPathToVFS(guestPath)
	node, err := fs.Resolve(vfsPath)
	if err != nil || string(node.Data) != "fixture" {
		t.Fatalf("imported file = %q, err=%v", node.Data, err)
	}
	if hostPaths[vfsPath] != hostPath {
		t.Fatalf("host binding = %q, want %q", hostPaths[vfsPath], hostPath)
	}
}

func TestPreparePEGuestArgsPreservesUnicodePath(t *testing.T) {
	hostPath := filepath.Join(t.TempDir(), "unicode-\U0001f600-\u65e5\u672c\u8a9e.md")
	if err := os.WriteFile(hostPath, []byte("unicode"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := vfs.New()
	args, _ := preparePEGuestArgs(fs, "/opt/npp/notepad++.exe", []string{"notepad++.exe", hostPath})
	if args[1] != linuxToWinPath(hostPath) {
		t.Fatalf("file argument = %q, want %q", args[1], linuxToWinPath(hostPath))
	}
	if _, err := fs.Resolve(winPathToVFS(args[1])); err != nil {
		t.Fatalf("unicode guest file is missing: %v", err)
	}
}

func TestWindowsCommandLineQuotesSpacesAndQuotes(t *testing.T) {
	got := windowsCommandLine([]string{`C:\npp\notepad++.exe`, `C:\My Files\note.txt`, `a"b`})
	want := `C:\npp\notepad++.exe "C:\My Files\note.txt" "a\"b"`
	if got != want {
		t.Fatalf("command line = %q, want %q", got, want)
	}
}

func TestWindowsCommandLineQuotesEmptyAndTrailingBackslash(t *testing.T) {
	got := windowsCommandLine([]string{"", `C:\My Files\`})
	want := `"" "C:\My Files\\"`
	if got != want {
		t.Fatalf("command line = %q, want %q", got, want)
	}
}

func TestWindowsCommandLinePreservesUnicode(t *testing.T) {
	got := windowsCommandLine([]string{`C:\npp\notepad++.exe`, "unicode-\U0001f600-\u65e5\u672c\u8a9e.md"})
	want := "C:\\npp\\notepad++.exe unicode-\U0001f600-\u65e5\u672c\u8a9e.md"
	if got != want {
		t.Fatalf("command line = %q, want %q", got, want)
	}
}
