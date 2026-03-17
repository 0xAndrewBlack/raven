//go:build !guest_linux

package main

// hasLinuxSupport reports that Linux (ELF) guest support is NOT compiled in.
func hasLinuxSupport() bool { return false }

// runELF is a stub for builds without guest_linux; main() guards the call
// behind hasLinuxSupport() so this is never invoked.
func runELF(absPath string, guestArgv []string, trace bool, enableWayland bool) {
}
