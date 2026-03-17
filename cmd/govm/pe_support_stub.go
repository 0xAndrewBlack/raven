//go:build !guest_windows

package main

// hasWindowsSupport reports that Windows (PE) guest support is NOT compiled in.
func hasWindowsSupport() bool { return false }

// runPE is a stub for builds without guest_windows; main() guards the call
// behind hasWindowsSupport() so this is never invoked.
func runPE(absPath string, guestArgv []string, sysroot, regFile string, trace bool, enableWayland bool, autoScript string) {
}
