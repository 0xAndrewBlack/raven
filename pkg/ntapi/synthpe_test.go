//go:build guest_windows

package ntapi

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestGenerateUxthemeUsesStableDarkModeOrdinals(t *testing.T) {
	exports := []string{
		"OpenThemeData",
		"OpenNcThemeData",
		"RefreshImmersiveColorPolicyState",
		"GetIsImmersiveColorUsingHighContrast",
		"ShouldAppsUseDarkMode",
		"AllowDarkModeForWindow",
		"SetPreferredAppMode",
		"FlushMenuThemes",
		"IsDarkModeAllowedForWindow",
		"ShouldSystemUseDarkMode",
	}
	want := map[uint16]string{
		49:  "OpenNcThemeData",
		104: "RefreshImmersiveColorPolicyState",
		106: "GetIsImmersiveColorUsingHighContrast",
		132: "ShouldAppsUseDarkMode",
		133: "AllowDarkModeForWindow",
		135: "SetPreferredAppMode",
		136: "FlushMenuThemes",
		137: "IsDarkModeAllowedForWindow",
		138: "ShouldSystemUseDarkMode",
	}

	mem := mmu.New()
	synth := GenerateSynthDLL(mem, "UXTHEME.DLL", exports, AutoSynthIDBase)
	for ordinal, name := range want {
		if got := synth.ExportOrds[ordinal]; got != synth.Exports[name] {
			t.Fatalf("ordinal %d = %#x, want %s at %#x", ordinal, got, name, synth.Exports[name])
		}
	}
	if got := synth.ExportOrds[0]; got != synth.Exports["OpenThemeData"] {
		t.Fatalf("ordinary export ordinal = %#x, want %#x", got, synth.Exports["OpenThemeData"])
	}

	assertSynthExportDirectoryOrdinals(t, mem, synth, want)
}

func TestDynamicUxthemeExportBindsKnownOrdinal(t *testing.T) {
	mem := mmu.New()
	synth := GenerateSynthDLL(mem, "uxtheme.dll", nil, AutoSynthIDBase)
	if id := synth.AddDynamicExport(mem, "ShouldAppsUseDarkMode", DynExportIDBase); id != DynExportIDBase {
		t.Fatalf("dynamic export ID = %#x", id)
	}
	if got := synth.ExportOrds[132]; got != synth.Exports["ShouldAppsUseDarkMode"] {
		t.Fatalf("dynamic ordinal = %#x, want %#x", got, synth.Exports["ShouldAppsUseDarkMode"])
	}
}

func assertSynthExportDirectoryOrdinals(t *testing.T, mem *mmu.MMU, synth *SynthPE, want map[uint16]string) {
	t.Helper()
	dataDir := synth.BaseAddr + 0x98 + 112
	edataRVA, err := mem.Read32(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	exportDir := synth.BaseAddr + uint64(edataRVA)
	numNames, err := mem.Read32(exportDir + 24)
	if err != nil {
		t.Fatal(err)
	}
	funcTableRVA, _ := mem.Read32(exportDir + 28)
	nameTableRVA, _ := mem.Read32(exportDir + 32)
	ordTableRVA, _ := mem.Read32(exportDir + 36)

	found := make(map[uint16]string)
	for i := uint32(0); i < numNames; i++ {
		nameRVA, err := mem.Read32(synth.BaseAddr + uint64(nameTableRVA) + uint64(i)*4)
		if err != nil {
			t.Fatal(err)
		}
		name := mem.ReadCString(synth.BaseAddr+uint64(nameRVA), 256)
		ordinal, err := mem.Read16(synth.BaseAddr + uint64(ordTableRVA) + uint64(i)*2)
		if err != nil {
			t.Fatal(err)
		}
		if expectedName, ok := want[ordinal]; ok {
			found[ordinal] = name
			funcRVA, err := mem.Read32(synth.BaseAddr + uint64(funcTableRVA) + uint64(ordinal)*4)
			if err != nil {
				t.Fatal(err)
			}
			if got := synth.BaseAddr + uint64(funcRVA); got != synth.Exports[expectedName] {
				t.Fatalf("raw ordinal %d address = %#x, want %#x", ordinal, got, synth.Exports[expectedName])
			}
		}
	}
	for ordinal, name := range want {
		if found[ordinal] != name {
			t.Fatalf("raw ordinal %d name = %q, want %q", ordinal, found[ordinal], name)
		}
	}
}
