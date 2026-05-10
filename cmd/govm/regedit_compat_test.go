//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/loader"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func TestRebindOrdinalImportsUsesNamedExport(t *testing.T) {
	mem := mmu.New()
	synth := ntapi.GenerateSynthDLL(mem, "comctl32.dll", []string{"DPA_Sort"}, 0x7000)
	iat := mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
	module := &loader.PEModule{
		Is64: true,
		Imports: []loader.PEImportEntry{{
			DLLName: "COMCTL32.dll",
			Ordinal: 338,
			IATSlot: iat,
		}},
	}
	hctx := &HandlerCtx{Mem: mem, MainModule: module}

	if got := rebindOrdinalImports(hctx, synth, "comctl32.dll", map[uint16]string{338: "DPA_Sort"}); got != 1 {
		t.Fatalf("rebound imports = %d, want 1", got)
	}
	want := synth.Exports["DPA_Sort"]
	got, err := mem.Read64(iat)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("IAT = %#x, want %#x", got, want)
	}
	if synth.ExportOrds[338] != want {
		t.Fatalf("ordinal export = %#x, want %#x", synth.ExportOrds[338], want)
	}
}

func TestRebindOrdinalImportsAliasesPlaceholderForPE32(t *testing.T) {
	mem := mmu.New()
	synth := ntapi.GenerateSynthDLL(mem, "shlwapi.dll", []string{"ord_219"}, 0x7100)
	iat := mem.Mmap(0, 4, mmu.PermRead|mmu.PermWrite)
	module := &loader.PEModule{
		Imports: []loader.PEImportEntry{{
			DLLName: "shlwapi.dll",
			Ordinal: 219,
			IATSlot: iat,
		}},
	}
	hctx := &HandlerCtx{Mem: mem, MainModule: module}

	if got := rebindOrdinalImports(hctx, synth, "shlwapi.dll", map[uint16]string{219: "QISearch"}); got != 1 {
		t.Fatalf("rebound imports = %d, want 1", got)
	}
	want := synth.Exports["ord_219"]
	got, err := mem.Read32(iat)
	if err != nil {
		t.Fatal(err)
	}
	if got != uint32(want) {
		t.Fatalf("IAT = %#x, want %#x", got, uint32(want))
	}
	if synth.Exports["QISearch"] != want {
		t.Fatalf("named alias = %#x, want %#x", synth.Exports["QISearch"], want)
	}
}

func TestRebindOrdinalImportsUsesLegacyComctlNames(t *testing.T) {
	mem := mmu.New()
	synth := ntapi.GenerateSynthDLL(mem, "comctl32.dll", []string{
		"FlatSB_ShowScrollBar",
		"FlatSB_GetScrollInfo",
		"MenuHelp",
		"GetEffectiveClientRect",
	}, 0x7200)
	iatMenuHelp := mem.Mmap(0, 4, mmu.PermRead|mmu.PermWrite)
	iatClientRect := mem.Mmap(0, 4, mmu.PermRead|mmu.PermWrite)
	module := &loader.PEModule{
		Imports: []loader.PEImportEntry{
			{DLLName: "comctl32.dll", Ordinal: 2, IATSlot: iatMenuHelp},
			{DLLName: "comctl32.dll", Ordinal: 4, IATSlot: iatClientRect},
		},
	}
	hctx := &HandlerCtx{Mem: mem, MainModule: module}
	bindings := map[uint16]string{
		2: "MenuHelp",
		4: "GetEffectiveClientRect",
	}

	if got := rebindOrdinalImports(hctx, synth, "comctl32.dll", bindings); got != 2 {
		t.Fatalf("rebound imports = %d, want 2", got)
	}
	for ordinal, iat := range map[uint16]uint64{2: iatMenuHelp, 4: iatClientRect} {
		got, err := mem.Read32(iat)
		if err != nil {
			t.Fatal(err)
		}
		want := synth.Exports[bindings[ordinal]]
		if got != uint32(want) {
			t.Fatalf("ordinal %d IAT = %#x, want %#x", ordinal, got, uint32(want))
		}
		if synth.ExportOrds[ordinal] != want {
			t.Fatalf("ordinal %d export = %#x, want %#x", ordinal, synth.ExportOrds[ordinal], want)
		}
	}
}

func TestRegeditAcceleratorFallback(t *testing.T) {
	module := &loader.PEModule{BaseAddr: 0x1000000, ResourceDirRVA: 0x5f000}
	hctx := &HandlerCtx{
		ImagePath:  `C:\Windows\regedit.exe`,
		MainModule: module,
		PeLoadRawResource: func(base uint64, resourceRVA, resourceType, resourceID uint32) (uint64, uint32, bool) {
			if base != module.BaseAddr || resourceRVA != module.ResourceDirRVA {
				t.Fatalf("resource module = %#x/%#x", base, resourceRVA)
			}
			if resourceType != 9 || resourceID != 100 {
				t.Fatalf("resource = %d/%d", resourceType, resourceID)
			}
			return 0, 0, false
		},
	}

	if got := regeditAcceleratorFallback(hctx, module.BaseAddr, 100); got != regeditFallbackAcceleratorHandle {
		t.Fatalf("fallback handle = %#x, want %#x", got, regeditFallbackAcceleratorHandle)
	}
	if got := regeditAcceleratorFallback(hctx, module.BaseAddr+0x1000, 100); got != 0 {
		t.Fatalf("foreign module fallback = %#x, want 0", got)
	}
	if got := regeditAcceleratorFallback(hctx, module.BaseAddr, 101); got != 0 {
		t.Fatalf("other resource fallback = %#x, want 0", got)
	}
}

func TestRegeditAcceleratorFallbackKeepsEmbeddedResource(t *testing.T) {
	module := &loader.PEModule{BaseAddr: 0x1000000, ResourceDirRVA: 0x5f000}
	hctx := &HandlerCtx{
		ImagePath:  "regedit.exe",
		MainModule: module,
		PeLoadRawResource: func(uint64, uint32, uint32, uint32) (uint64, uint32, bool) {
			return module.BaseAddr + 0x60000, 8, true
		},
	}

	if got := regeditAcceleratorFallback(hctx, module.BaseAddr, 100); got != 0 {
		t.Fatalf("embedded resource fallback = %#x, want 0", got)
	}
}

func TestRegeditAcceleratorFallbackRejectsOtherImages(t *testing.T) {
	module := &loader.PEModule{BaseAddr: 0x1000000, ResourceDirRVA: 0x5f000}
	hctx := &HandlerCtx{
		ImagePath:  "notepad.exe",
		MainModule: module,
		PeLoadRawResource: func(uint64, uint32, uint32, uint32) (uint64, uint32, bool) {
			t.Fatal("resource lookup should not run")
			return 0, 0, false
		},
	}

	if got := regeditAcceleratorFallback(hctx, module.BaseAddr, 100); got != 0 {
		t.Fatalf("other image fallback = %#x, want 0", got)
	}
}

func TestRegeditStringFallback(t *testing.T) {
	module := &loader.PEModule{BaseAddr: 0x1000000}
	hctx := &HandlerCtx{
		ImagePath:  "regedit.exe",
		MainModule: module,
		PeLoadStringW: func(uint32) (string, uint64, int) {
			return "", 0, 0
		},
	}

	for resource, want := range map[uint32]string{
		16: "Registry Editor",
		17: "Name",
		18: "Data",
		19: "Computer",
		20: "(Default)",
		27: "(value not set)",
		31: "Type",
	} {
		if got := regeditStringFallback(hctx, module.BaseAddr, resource); got != want {
			t.Errorf("resource %d fallback = %q, want %q", resource, got, want)
		}
	}
	if got := regeditStringFallback(hctx, module.BaseAddr, 99); got != "" {
		t.Fatalf("unknown resource fallback = %q, want empty", got)
	}
	if got := regeditStringFallback(hctx, module.BaseAddr+0x1000, 17); got != "" {
		t.Fatalf("foreign module fallback = %q, want empty", got)
	}
}

func TestRegeditStringFallbackKeepsEmbeddedResource(t *testing.T) {
	module := &loader.PEModule{BaseAddr: 0x1000000}
	hctx := &HandlerCtx{
		ImagePath:  "regedit.exe",
		MainModule: module,
		PeLoadStringW: func(resource uint32) (string, uint64, int) {
			if resource == 17 {
				return "Nom", 0x12000, 3
			}
			return "", 0, 0
		},
	}

	if got := regeditStringFallback(hctx, module.BaseAddr, 17); got != "" {
		t.Fatalf("embedded resource fallback = %q, want empty", got)
	}
}

func TestRegeditStringFallbackRejectsOtherImages(t *testing.T) {
	hctx := &HandlerCtx{
		ImagePath:  "notepad.exe",
		MainModule: &loader.PEModule{BaseAddr: 0x1000000},
		PeLoadStringW: func(uint32) (string, uint64, int) {
			t.Fatal("resource lookup should not run")
			return "", 0, 0
		},
	}

	if got := regeditStringFallback(hctx, hctx.MainModule.BaseAddr, 17); got != "" {
		t.Fatalf("other image fallback = %q, want empty", got)
	}
}

func TestIsRegeditImage(t *testing.T) {
	for _, imagePath := range []string{
		"regedit.exe",
		`C:\Windows\regedit.exe`,
		"/windows/system32/REGEDIT.EXE",
	} {
		if !isRegeditImage(imagePath) {
			t.Errorf("isRegeditImage(%q) = false, want true", imagePath)
		}
	}
	if isRegeditImage("notepad.exe") {
		t.Fatal("notepad.exe identified as regedit")
	}
}
