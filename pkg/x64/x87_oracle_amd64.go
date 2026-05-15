//go:build linux && amd64

package x64

import _ "unsafe"

// hostX87Add executes one host x87 addition and returns the result and status.
// The helper saves and restores the complete host x87 state.
//
//go:linkname hostX87Add hostX87Add
func hostX87Add(a, b float64) (result float64, status uint16)
