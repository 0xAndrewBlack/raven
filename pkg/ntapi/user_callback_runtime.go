//go:build guest_windows

package ntapi

import (
	"encoding/binary"
	"fmt"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

const User32CallbackWindowProc uint32 = 0

const (
	userCallbackRuntimeSize      = uint64(mmu.PageSize)
	userCallbackDispatcherOffset = uint64(0)
	userCallbackWindowProcOffset = uint64(0x100)
	userCallbackTableOffset      = uint64(0x200)
	windowProcCallback32Size     = uint32(32)
	windowProcCallback64Size     = uint32(64)
	windowProcCallback32Result   = uint64(28)
	windowProcCallback64Result   = uint64(56)
)

type UserCallbackRuntime struct {
	Dispatcher    uint64
	CallbackTable uint64
	WindowProc    uint64
}

type WindowProcCallbackArguments struct {
	Proc       uint64
	IsAnsiProc bool
	Wnd        uint64
	Msg        uint32
	WParam     uint64
	LParam     uint64
}

func InstallUserCallbackRuntime(mem *mmu.MMU, state *ProcessState, ntCallbackReturn uint64) (UserCallbackRuntime, error) {
	if mem == nil {
		return UserCallbackRuntime{}, fmt.Errorf("install user callback runtime: nil memory")
	}
	if state == nil || state.PEBAddr == 0 {
		return UserCallbackRuntime{}, fmt.Errorf("install user callback runtime: nil PEB")
	}
	if ntCallbackReturn == 0 {
		return UserCallbackRuntime{}, fmt.Errorf("install user callback runtime: nil NtCallbackReturn")
	}
	if state.Is32 && (state.PEBAddr > uint64(^uint32(0)) || ntCallbackReturn > uint64(^uint32(0))) {
		return UserCallbackRuntime{}, fmt.Errorf("install PE32 user callback runtime: address exceeds 32-bit range")
	}

	base := mem.Mmap(0, userCallbackRuntimeSize, mmu.PermRead|mmu.PermWrite)
	if base == 0 {
		return UserCallbackRuntime{}, fmt.Errorf("install user callback runtime: executable allocation failed")
	}
	installed := false
	defer func() {
		if !installed {
			mem.Munmap(base, userCallbackRuntimeSize)
		}
	}()
	if state.Is32 && base+userCallbackRuntimeSize-1 > uint64(^uint32(0)) {
		return UserCallbackRuntime{}, fmt.Errorf("install user callback runtime: executable allocation failed")
	}

	runtime := UserCallbackRuntime{
		Dispatcher:    base + userCallbackDispatcherOffset,
		CallbackTable: base + userCallbackTableOffset,
		WindowProc:    base + userCallbackWindowProcOffset,
	}
	var (
		dispatcherCode []byte
		windowProcCode []byte
		callbackTable  uint64
		err            error
	)
	if state.Is32 {
		dispatcherCode = buildUserCallbackDispatcher32(uint32(state.PEBAddr), uint32(ntCallbackReturn))
		windowProcCode = buildWindowProcCallback32(uint32(ntCallbackReturn))
		callbackTable, err = readCallbackPointer(mem, state.PEBAddr+Peb32KernelCallbackTable, true)
	} else {
		dispatcherCode = buildUserCallbackDispatcher64(state.PEBAddr, ntCallbackReturn)
		windowProcCode = buildWindowProcCallback64(ntCallbackReturn)
		callbackTable, err = readCallbackPointer(mem, state.PEBAddr+PebKernelCallbackTable, false)
	}
	if err != nil {
		return UserCallbackRuntime{}, fmt.Errorf("install user callback runtime: read callback table: %w", err)
	}
	if err := mem.WriteBytes(runtime.Dispatcher, dispatcherCode); err != nil {
		return UserCallbackRuntime{}, fmt.Errorf("install user callback runtime: write dispatcher: %w", err)
	}
	if err := mem.WriteBytes(runtime.WindowProc, windowProcCode); err != nil {
		return UserCallbackRuntime{}, fmt.Errorf("install user callback runtime: write window proc callback: %w", err)
	}

	if callbackTable == 0 {
		if state.Is32 {
			if err := mem.Write32(runtime.CallbackTable, uint32(runtime.WindowProc)); err != nil {
				return UserCallbackRuntime{}, err
			}
		} else {
			if err := mem.Write64(runtime.CallbackTable, runtime.WindowProc); err != nil {
				return UserCallbackRuntime{}, err
			}
		}
	} else {
		runtime.CallbackTable = callbackTable
	}

	if err := mem.Mprotect(base, userCallbackRuntimeSize, mmu.PermRead|mmu.PermExecute); err != nil {
		return UserCallbackRuntime{}, fmt.Errorf("install user callback runtime: protect code: %w", err)
	}
	if callbackTable == 0 {
		if state.Is32 {
			if err := mem.Write32(state.PEBAddr+Peb32KernelCallbackTable, uint32(runtime.CallbackTable)); err != nil {
				return UserCallbackRuntime{}, err
			}
		} else if err := mem.Write64(state.PEBAddr+PebKernelCallbackTable, runtime.CallbackTable); err != nil {
			return UserCallbackRuntime{}, err
		}
	}
	installed = true
	return runtime, nil
}

func EncodeWindowProcCallbackArguments(is32 bool, args WindowProcCallbackArguments) []byte {
	if is32 {
		buf := make([]byte, windowProcCallback32Size)
		binary.LittleEndian.PutUint32(buf[0:], uint32(args.Proc))
		if args.IsAnsiProc {
			binary.LittleEndian.PutUint32(buf[4:], 1)
		}
		binary.LittleEndian.PutUint32(buf[8:], uint32(args.Wnd))
		binary.LittleEndian.PutUint32(buf[12:], args.Msg)
		binary.LittleEndian.PutUint32(buf[16:], uint32(args.WParam))
		binary.LittleEndian.PutUint32(buf[20:], uint32(args.LParam))
		binary.LittleEndian.PutUint32(buf[24:], uint32(^uint32(0)))
		return buf
	}

	buf := make([]byte, windowProcCallback64Size)
	binary.LittleEndian.PutUint64(buf[0:], args.Proc)
	if args.IsAnsiProc {
		binary.LittleEndian.PutUint32(buf[8:], 1)
	}
	binary.LittleEndian.PutUint64(buf[16:], args.Wnd)
	binary.LittleEndian.PutUint32(buf[24:], args.Msg)
	binary.LittleEndian.PutUint64(buf[32:], args.WParam)
	binary.LittleEndian.PutUint64(buf[40:], args.LParam)
	binary.LittleEndian.PutUint32(buf[48:], uint32(^uint32(0)))
	return buf
}

func ReadWindowProcCallbackResult(mem *mmu.MMU, is32 bool, callbackReturn UserCallbackReturn) (uint64, error) {
	size := windowProcCallback64Size
	offset := windowProcCallback64Result
	if is32 {
		size = windowProcCallback32Size
		offset = windowProcCallback32Result
	}
	if callbackReturn.Address == 0 || callbackReturn.Length < size {
		return 0, fmt.Errorf("window proc callback returned buffer 0x%x length %d", callbackReturn.Address, callbackReturn.Length)
	}
	if is32 {
		value, err := mem.Read32(callbackReturn.Address + offset)
		return uint64(value), err
	}
	return mem.Read64(callbackReturn.Address + offset)
}

func readCallbackPointer(mem *mmu.MMU, address uint64, is32 bool) (uint64, error) {
	if is32 {
		value, err := mem.Read32(address)
		return uint64(value), err
	}
	return mem.Read64(address)
}

func buildUserCallbackDispatcher32(peb, ntCallbackReturn uint32) []byte {
	code := []byte{
		0x8B, 0x54, 0x24, 0x04,
		0xB8,
	}
	code = appendUint32(code, peb)
	code = append(code,
		0x8B, 0x40, byte(Peb32KernelCallbackTable),
		0xFF, 0x74, 0x24, 0x0C,
		0xFF, 0x74, 0x24, 0x0C,
		0xFF, 0x14, 0x90,
		0x50,
		0x6A, 0x00,
		0x6A, 0x00,
		0xB8,
	)
	code = appendUint32(code, ntCallbackReturn)
	return append(code, 0xFF, 0xD0, 0xCC)
}

func buildWindowProcCallback32(ntCallbackReturn uint32) []byte {
	code := []byte{
		0x53,
		0x56,
		0x8B, 0x5C, 0x24, 0x0C,
		0x8B, 0x74, 0x24, 0x10,
		0xFF, 0x73, 0x14,
		0xFF, 0x73, 0x10,
		0xFF, 0x73, 0x0C,
		0xFF, 0x73, 0x08,
		0xFF, 0x13,
		0x89, 0x43, 0x1C,
		0x6A, 0x00,
		0x56,
		0x53,
		0xB8,
	}
	code = appendUint32(code, ntCallbackReturn)
	return append(code, 0xFF, 0xD0, 0xCC)
}

func buildUserCallbackDispatcher64(peb, ntCallbackReturn uint64) []byte {
	code := []byte{
		0x4C, 0x8B, 0x54, 0x24, 0x20,
		0x44, 0x8B, 0x5C, 0x24, 0x28,
		0x8B, 0x44, 0x24, 0x2C,
		0x49, 0xBC,
	}
	code = appendUint64(code, peb)
	code = append(code,
		0x4D, 0x8B, 0x64, 0x24, byte(PebKernelCallbackTable),
		0x49, 0x8B, 0x04, 0xC4,
		0x4C, 0x89, 0xD1,
		0x44, 0x89, 0xDA,
		0x48, 0x83, 0xEC, 0x20,
		0xFF, 0xD0,
		0x48, 0x83, 0xC4, 0x20,
		0x31, 0xC9,
		0x31, 0xD2,
		0x41, 0x89, 0xC0,
		0x48, 0xB8,
	)
	code = appendUint64(code, ntCallbackReturn)
	return append(code, 0xFF, 0xD0, 0xCC)
}

func buildWindowProcCallback64(ntCallbackReturn uint64) []byte {
	code := []byte{
		0x53,
		0x56,
		0x48, 0x89, 0xCB,
		0x89, 0xD6,
		0x48, 0x8B, 0x03,
		0x48, 0x8B, 0x4B, 0x10,
		0x8B, 0x53, 0x18,
		0x4C, 0x8B, 0x43, 0x20,
		0x4C, 0x8B, 0x4B, 0x28,
		0x48, 0x83, 0xEC, 0x28,
		0xFF, 0xD0,
		0x48, 0x89, 0x43, 0x38,
		0x48, 0x89, 0xD9,
		0x89, 0xF2,
		0x45, 0x31, 0xC0,
		0x48, 0xB8,
	}
	code = appendUint64(code, ntCallbackReturn)
	return append(code, 0xFF, 0xD0, 0xCC)
}

func appendUint32(code []byte, value uint32) []byte {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	return append(code, encoded[:]...)
}

func appendUint64(code []byte, value uint64) []byte {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	return append(code, encoded[:]...)
}
