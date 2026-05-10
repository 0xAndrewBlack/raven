//go:build guest_windows

package main

import "testing"

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
