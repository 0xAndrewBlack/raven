//go:build guest_linux

package main

// hasLinuxSupport reports that Linux (ELF) guest support is compiled in.
func hasLinuxSupport() bool { return true }
