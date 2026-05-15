//go:build guest_windows

package main

import (
	"bytes"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func TestResetWin32ThreadStackClearsRecycledPages(t *testing.T) {
	mem := mmu.New()
	const (
		base = uint64(0x62000000)
		size = 2 * mmu.PageSize
	)
	mem.MapRange(base, size, mmu.PermRead|mmu.PermWrite)
	if err := mem.WriteBytes(base, bytes.Repeat([]byte{0xA5}, int(size))); err != nil {
		t.Fatal(err)
	}

	resetWin32ThreadStack(mem, base, size)

	data, err := mem.ReadBytes(base, int(size))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, make([]byte, size)) {
		t.Fatal("recycled stack retained data from the previous thread")
	}
	_, _, mapped, perms := mem.QueryRegion(base)
	if !mapped || perms != mmu.PermRead|mmu.PermWrite {
		t.Fatalf("reset stack mapping = %t/%#x", mapped, perms)
	}
}

func TestReleaseLibraryReference(t *testing.T) {
	refs := map[uint64]uint32{0x1000: 2, 0x2000: 1}
	if !releaseLibraryReference(refs, 0x1000) || refs[0x1000] != 1 {
		t.Fatalf("first release = %v", refs)
	}
	if !releaseLibraryReference(refs, 0x1000) {
		t.Fatal("second release failed")
	}
	if _, ok := refs[0x1000]; ok {
		t.Fatalf("final release retained module: %v", refs)
	}
	if releaseLibraryReference(refs, 0) {
		t.Fatal("zero module was accepted")
	}
	if releaseLibraryReference(refs, 0x3000) {
		t.Fatal("unknown module was accepted")
	}
}

func TestHideGetProcAddressExport(t *testing.T) {
	if !hideGetProcAddressExport("ntdll.dll", "wine_get_version") ||
		!hideGetProcAddressExport("NTDLL.DLL", "WINE_GET_VERSION") {
		t.Fatal("Wine version detection export was visible")
	}
	if hideGetProcAddressExport("app.dll", "wine_get_version") {
		t.Fatal("application export was hidden")
	}
	if hideGetProcAddressExport("ntdll.dll", "RtlGetNtVersionNumbers") {
		t.Fatal("native NT version export was hidden")
	}
}

func TestAllowLazySynthExport(t *testing.T) {
	if allowLazySynthExport("ntdll.dll") || allowLazySynthExport("WIN32U.DLL") {
		t.Fatal("core DLL accepted a lazy export")
	}
	if !allowLazySynthExport("user32.dll") {
		t.Fatal("regular synthetic DLL rejected a lazy export")
	}
}

func TestGetProcAddressOrdinalDetectionUsesPointerValue(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   uint64
		ordinal uint16
		ok      bool
	}{
		{name: "PE32 resource", value: 135, ordinal: 135, ok: true},
		{name: "PE64 resource", value: 0x0000000000000084, ordinal: 132, ok: true},
		{name: "PE32 name pointer", value: 0x00120000},
		{name: "PE64 name pointer", value: 0x00007fff00120000},
	} {
		t.Run(test.name, func(t *testing.T) {
			ordinal, ok := getProcAddressOrdinal(test.value)
			if ordinal != test.ordinal || ok != test.ok {
				t.Fatalf("result = (%d, %v), want (%d, %v)", ordinal, ok, test.ordinal, test.ok)
			}
		})
	}
}

func TestGetProcAddressReturnsUxthemeDarkModeOrdinals(t *testing.T) {
	exports := []string{
		"OpenNcThemeData",
		"RefreshImmersiveColorPolicyState",
		"GetIsImmersiveColorUsingHighContrast",
		"ShouldAppsUseDarkMode",
		"AllowDarkModeForWindow",
		"SetPreferredAppMode",
		"FlushMenuThemes",
		"IsDarkModeAllowedForWindow",
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
	}

	mem := mmu.New()
	uxtheme := ntapi.GenerateSynthDLL(mem, "uxtheme.dll", exports, ntapi.AutoSynthIDBase)
	dispatcher := ntapi.NewDispatcher(mem, nil, nil, nil, nil, nil, nil)
	hctx := &HandlerCtx{
		Disp:        dispatcher,
		SynthByName: map[string]*ntapi.SynthPE{"uxtheme.dll": uxtheme},
	}
	for ordinal, name := range want {
		got := lookupGetProcAddressOrdinal(hctx, uxtheme.BaseAddr, ordinal)
		if got != uxtheme.Exports[name] {
			t.Fatalf("ordinal %d = %#x, want %s at %#x", ordinal, got, name, uxtheme.Exports[name])
		}
	}
	if got := lookupGetProcAddressOrdinal(hctx, uxtheme.BaseAddr, 134); got != 0 {
		t.Fatalf("missing ordinal returned %#x", got)
	}
}
