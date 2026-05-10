package jit

import (
	"golang.org/x/sys/unix"
)

// execBuf is a chunk of host memory that holds generated machine code.
// Code is written while the buffer is RW, then sealed RX before execution
// (W^X). Buffers are never freed individually; the whole arena dies with
// the cache.
type execBuf struct {
	mem  []byte
	used int
}

const execBufSize = 1 << 20

func newExecBuf() (*execBuf, error) {
	mem, err := unix.Mmap(-1, 0, execBufSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, err
	}
	return &execBuf{mem: mem}, nil
}

// place copies code into the buffer and returns its entry address, sealing
// the code as executable. Returns 0 when the buffer is full.
func (b *execBuf) place(code []byte) uintptr {
	aligned := (b.used + 15) &^ 15
	if aligned+len(code) > len(b.mem) {
		return 0
	}
	copy(b.mem[aligned:], code)
	b.used = aligned + len(code)
	return uintptr(nativeSliceAddr(b.mem)) + uintptr(aligned)
}

// seal flips the whole buffer to RX+RW. Linux allows RWX for anonymous
// mappings; keeping it writable lets us append more blocks later. If the
// kernel refuses RWX (hardened setups), fall back to sealing RX only.
func (b *execBuf) seal() error {
	if err := unix.Mprotect(b.mem, unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC); err != nil {
		return unix.Mprotect(b.mem, unix.PROT_READ|unix.PROT_EXEC)
	}
	return nil
}
