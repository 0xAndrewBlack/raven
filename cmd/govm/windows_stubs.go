//go:build !guest_windows

package main

import (
	"fmt"
	"os"
)

func runPE(absPath string, guestArgv []string, sysroot, winePrefix, regFile string, trace bool, enableWayland bool, autoScript string) {
	fmt.Fprintf(os.Stderr, "Error: Windows guest support is not compiled into this binary.\n")
	fmt.Fprintf(os.Stderr, "Rebuild with: go build -tags guest_windows\n")
	os.Exit(1)
}

func hasWindowsSupport() bool { return false }
