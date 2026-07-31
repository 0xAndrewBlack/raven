//go:build linux

package mmu

import "golang.org/x/sys/unix"

func newSharedFile() (int, error) {
	return unix.MemfdCreate("raven-memory", unix.MFD_CLOEXEC)
}
