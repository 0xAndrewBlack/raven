//go:build guest_windows

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/vfs"
)

func TestPrintDialogStructLayout(t *testing.T) {
	if got := printDialogStructLayout(false); got.size != 66 || got.hDevModeOffset != 8 || got.hDCOffset != 16 || got.flagsOffset != 20 || got.copiesOffset != 32 {
		t.Fatalf("PE32 layout = %+v", got)
	}
	if got := printDialogStructLayout(true); got.size != 120 || got.hDevModeOffset != 16 || got.hDCOffset != 32 || got.flagsOffset != 40 || got.copiesOffset != 52 {
		t.Fatalf("PE32+ layout = %+v", got)
	}
}

func TestAllocPrintDevMode(t *testing.T) {
	for _, tc := range []struct {
		name       string
		wide       bool
		sizeOffset uint64
		wantSize   uint16
	}{
		{name: "ANSI", sizeOffset: 36, wantSize: 156},
		{name: "Unicode", wide: true, sizeOffset: 68, wantSize: 220},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem := mmu.New()
			hctx := &HandlerCtx{Mem: mem}
			addr := allocPrintDevMode(hctx, tc.wide)
			got, err := mem.Read16(addr + tc.sizeOffset)
			if err != nil || got != tc.wantSize {
				t.Fatalf("dmSize = %d, err=%v", got, err)
			}
		})
	}
}

func TestPrintDevModeCopies(t *testing.T) {
	for _, wide := range []bool{false, true} {
		mem := mmu.New()
		hctx := &HandlerCtx{Mem: mem}
		addr := allocPrintDevMode(hctx, wide)
		setPrintDevModeCopies(mem, addr, wide, 3)
		if got := printDevModeCopies(mem, addr, wide); got != 3 {
			t.Fatalf("wide=%v copies=%d", wide, got)
		}
		fieldsOffset := uint64(40)
		if wide {
			fieldsOffset = 72
		}
		fields, _ := mem.Read32(addr + fieldsOffset)
		if fields&dmCopies == 0 {
			t.Fatalf("wide=%v dmFields=0x%x", wide, fields)
		}
	}
}

func TestAllocPrintDevNames(t *testing.T) {
	for _, wide := range []bool{false, true} {
		mem := mmu.New()
		hctx := &HandlerCtx{Mem: mem}
		addr := allocPrintDevNames(hctx, wide)
		driver, _ := mem.Read16(addr)
		device, _ := mem.Read16(addr + 2)
		output, _ := mem.Read16(addr + 4)
		isDefault, _ := mem.Read16(addr + 6)
		wantDriver := uint16(8)
		if wide {
			wantDriver = 4
		}
		if driver != wantDriver || device <= driver || output <= device || isDefault != 1 {
			t.Fatalf("wide=%v offsets=(%d,%d,%d) default=%d", wide, driver, device, output, isDefault)
		}
	}
}

func TestPrintDialogGlobalsFreeIndependently(t *testing.T) {
	mem := mmu.New()
	hctx := &HandlerCtx{Mem: mem}
	devMode := allocPrintDevMode(hctx, true)
	devNames := allocPrintDevNames(hctx, true)
	size, ok := hctx.releaseGlobal(devMode)
	if !ok {
		t.Fatal("DEVMODE allocation was not tracked")
	}
	mem.Munmap(devMode, size)
	if _, err := mem.Read16(devNames); err != nil {
		t.Fatalf("freeing DEVMODE unmapped DEVNAMES: %v", err)
	}
	if size, ok = hctx.releaseGlobal(devNames); !ok {
		t.Fatal("DEVNAMES allocation was not tracked")
	}
	mem.Munmap(devNames, size)
}

func TestFileDialogOverride(t *testing.T) {
	t.Setenv("RAVEN_FILE_DIALOG_PATH", " /tmp/readme.txt ")
	path, ok := fileDialogOverride()
	if !ok || path != "/tmp/readme.txt" {
		t.Fatalf("override = %q, %v", path, ok)
	}
}

func TestFileDialogOverrideUnset(t *testing.T) {
	t.Setenv("RAVEN_FILE_DIALOG_PATH", "")
	if path, ok := fileDialogOverride(); ok || path != "" {
		t.Fatalf("override = %q, %v, want empty", path, ok)
	}
}

func TestScanPortalResponse(t *testing.T) {
	const handle = "/org/freedesktop/portal/desktop/request/1_42/raven"
	input := `signal time=1 sender=:1.1 -> destination=:1.2 serial=4 path=` + handle + `; interface=org.freedesktop.portal.Request; member=Response
   uint32 0
   array [
      dict entry(
         string "uris"
         variant             array [
               string "file:///tmp/Raven%20README.md"
            ]
      )
   ]
`
	path, ok := scanPortalResponse(bufio.NewScanner(strings.NewReader(input)), handle)
	if !ok || path != "/tmp/Raven README.md" {
		t.Fatalf("portal response = %q, %v", path, ok)
	}
}

func TestScanPortalResponseIgnoresOtherRequests(t *testing.T) {
	const handle = "/org/freedesktop/portal/desktop/request/1_42/raven"
	input := `signal time=1 sender=:1.1 -> destination=:1.2 serial=4 path=/org/freedesktop/portal/desktop/request/1_99/other; interface=org.freedesktop.portal.Request; member=Response
   uint32 0
   string "file:///tmp/wrong.txt"
signal time=2 sender=:1.1 -> destination=:1.2 serial=5 path=` + handle + `; interface=org.freedesktop.portal.Request; member=Response
   uint32 1
`
	path, ok := scanPortalResponse(bufio.NewScanner(strings.NewReader(input)), handle)
	if ok || path != "" {
		t.Fatalf("cancelled portal response = %q, %v", path, ok)
	}
}

func TestColorDialogOverride(t *testing.T) {
	t.Setenv("RAVEN_COLOR_DIALOG_VALUE", "#123456")
	color, ok := colorDialog(0)
	if !ok || color != 0x563412 {
		t.Fatalf("color = 0x%06x, %v", color, ok)
	}
}

func TestColorDialogOverrideCancel(t *testing.T) {
	t.Setenv("RAVEN_COLOR_DIALOG_VALUE", "")
	color, ok := colorDialog(0x112233)
	if ok || color != 0x112233 {
		t.Fatalf("color = 0x%06x, %v", color, ok)
	}
}

func TestPrepareDialogGuestFileImportsAndBindsOpenFile(t *testing.T) {
	hostPath := filepath.Join(t.TempDir(), "selected.txt")
	if err := os.WriteFile(hostPath, []byte("selected"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := vfs.New()
	hctx := &HandlerCtx{}
	guestPath := normalizeDialogGuestPath(hostPath)
	if err := prepareDialogGuestFile(hctx, fs, hostPath, guestPath, false); err != nil {
		t.Fatal(err)
	}
	vfsPath := winPathToVFS(guestPath)
	node, err := fs.Resolve(vfsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(node.Data) != "selected" {
		t.Fatalf("guest data = %q", node.Data)
	}
	if hctx.HostSavePaths[vfsPath] != hostPath {
		t.Fatalf("host binding = %q", hctx.HostSavePaths[vfsPath])
	}
	if err := fs.CreateFile(vfsPath, []byte("saved"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := hctx.flushHostSavePath(fs, vfsPath); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(hostPath); err != nil || string(data) != "saved" {
		t.Fatalf("host data = %q, err=%v", data, err)
	}
}

func TestPrepareDialogGuestFileCreatesSaveDestination(t *testing.T) {
	hostPath := filepath.Join(t.TempDir(), "new", "saved.txt")
	fs := vfs.New()
	hctx := &HandlerCtx{}
	guestPath := normalizeDialogGuestPath(hostPath)
	if err := prepareDialogGuestFile(hctx, fs, hostPath, guestPath, true); err != nil {
		t.Fatal(err)
	}
	vfsPath := winPathToVFS(guestPath)
	if _, err := fs.Resolve(vfsPath); err != nil {
		t.Fatal(err)
	}
	if hctx.HostSavePaths[vfsPath] != hostPath {
		t.Fatalf("host binding = %q", hctx.HostSavePaths[vfsPath])
	}
	if err := fs.CreateFile(vfsPath, []byte("saved as"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := hctx.flushHostSavePath(fs, vfsPath); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(hostPath); err != nil || string(data) != "saved as" {
		t.Fatalf("host data = %q, err=%v", data, err)
	}
}

func TestPrepareDialogGuestFileRejectsExistingDirectory(t *testing.T) {
	hostPath := t.TempDir()
	fs := vfs.New()
	hctx := &HandlerCtx{}
	guestPath := normalizeDialogGuestPath(hostPath)
	if err := prepareDialogGuestFile(hctx, fs, hostPath, guestPath, true); err == nil {
		t.Fatal("save dialog accepted an existing directory")
	}
	if len(hctx.HostSavePaths) != 0 {
		t.Fatalf("failed target was bound: %v", hctx.HostSavePaths)
	}
}
