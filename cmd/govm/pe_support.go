//go:build guest_windows

package main

// hasWindowsSupport reports that Windows (PE) guest support is compiled in.
func hasWindowsSupport() bool { return true }
