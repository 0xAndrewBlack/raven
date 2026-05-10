//go:build guest_windows

package ntapi

import (
	"encoding/binary"
	"fmt"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

const (
	userCallbackFrame32Size = uint64(0x18)
	userCallbackFrame64Size = uint64(0x58)

	userCallbackFrame64BufferOffset = uint64(0x20)
	userCallbackFrame64LengthOffset = uint64(0x28)
	userCallbackFrame64IndexOffset  = uint64(0x2C)
	userCallbackFrame64RipOffset    = uint64(0x30)
	userCallbackFrame64RspOffset    = uint64(0x48)
)

type UserCallbackFrame struct {
	StackPointer uint64
	Buffer       uint64
	Length       uint32
}

type UserCallbackReturn struct {
	Address uint64
	Length  uint32
	Status  uint32
}

func BuildUserCallbackFrame32(mem *mmu.MMU, oldStack uint64, callbackIndex uint32, input []byte) (UserCallbackFrame, error) {
	var frame UserCallbackFrame
	if oldStack > uint64(^uint32(0)) {
		return frame, fmt.Errorf("PE32 stack pointer 0x%x exceeds 32-bit address space", oldStack)
	}
	inputLength := uint64(len(input))
	if inputLength > uint64(^uint32(0)) {
		return frame, fmt.Errorf("callback input length 0x%x exceeds ULONG", inputLength)
	}
	if inputLength > oldStack {
		return frame, fmt.Errorf("callback input length 0x%x underflows stack pointer 0x%x", inputLength, oldStack)
	}

	frame.Buffer = (oldStack - inputLength) &^ uint64(3)
	if frame.Buffer < userCallbackFrame32Size {
		return UserCallbackFrame{}, fmt.Errorf("callback frame underflows stack at 0x%x", frame.Buffer)
	}
	frame.StackPointer = frame.Buffer - userCallbackFrame32Size
	frame.Length = uint32(inputLength)

	end := frame.Buffer + inputLength
	if err := preflightCallbackStack(mem, frame.StackPointer, end); err != nil {
		return UserCallbackFrame{}, err
	}
	if err := mem.WriteBytes(frame.Buffer, input); err != nil {
		return UserCallbackFrame{}, err
	}

	var header [16]byte
	binary.LittleEndian.PutUint32(header[0x00:], 0)
	binary.LittleEndian.PutUint32(header[0x04:], callbackIndex)
	binary.LittleEndian.PutUint32(header[0x08:], uint32(frame.Buffer))
	binary.LittleEndian.PutUint32(header[0x0C:], frame.Length)
	if err := mem.WriteBytes(frame.StackPointer, header[:]); err != nil {
		return UserCallbackFrame{}, err
	}
	return frame, nil
}

func BuildUserCallbackFrame64(mem *mmu.MMU, oldStack uint64, callbackIndex uint32, input []byte, returnPC uint64) (UserCallbackFrame, error) {
	var frame UserCallbackFrame
	inputLength := uint64(len(input))
	if inputLength > uint64(^uint32(0)) {
		return frame, fmt.Errorf("callback input length 0x%x exceeds ULONG", inputLength)
	}
	if inputLength > oldStack {
		return frame, fmt.Errorf("callback input length 0x%x underflows stack pointer 0x%x", inputLength, oldStack)
	}

	alignedStack := (oldStack - inputLength) &^ uint64(15)
	if alignedStack < 8 {
		return frame, fmt.Errorf("callback arguments underflow stack at 0x%x", alignedStack)
	}
	frame.Buffer = alignedStack - 8
	if frame.Buffer < userCallbackFrame64Size {
		return UserCallbackFrame{}, fmt.Errorf("callback frame underflows stack at 0x%x", frame.Buffer)
	}
	frame.StackPointer = frame.Buffer - userCallbackFrame64Size
	frame.Length = uint32(inputLength)

	end := frame.Buffer + inputLength
	if err := preflightCallbackStack(mem, frame.StackPointer, end); err != nil {
		return UserCallbackFrame{}, err
	}
	if err := mem.WriteBytes(frame.Buffer, input); err != nil {
		return UserCallbackFrame{}, err
	}
	if err := mem.Write64(frame.StackPointer+userCallbackFrame64BufferOffset, frame.Buffer); err != nil {
		return UserCallbackFrame{}, err
	}
	if err := mem.Write32(frame.StackPointer+userCallbackFrame64LengthOffset, frame.Length); err != nil {
		return UserCallbackFrame{}, err
	}
	if err := mem.Write32(frame.StackPointer+userCallbackFrame64IndexOffset, callbackIndex); err != nil {
		return UserCallbackFrame{}, err
	}
	if err := mem.Write64(frame.StackPointer+userCallbackFrame64RipOffset, returnPC); err != nil {
		return UserCallbackFrame{}, err
	}
	if err := mem.Write64(frame.StackPointer+userCallbackFrame64RspOffset, oldStack); err != nil {
		return UserCallbackFrame{}, err
	}
	return frame, nil
}

func ParseUserCallbackReturn32(result, resultLength, callbackStatus uint64) UserCallbackReturn {
	return UserCallbackReturn{
		Address: uint64(uint32(result)),
		Length:  uint32(resultLength),
		Status:  uint32(callbackStatus),
	}
}

func ParseUserCallbackReturn64(result, resultLength, callbackStatus uint64) UserCallbackReturn {
	return UserCallbackReturn{
		Address: result,
		Length:  uint32(resultLength),
		Status:  uint32(callbackStatus),
	}
}

func preflightCallbackStack(mem *mmu.MMU, start, end uint64) error {
	if mem == nil {
		return fmt.Errorf("nil callback memory")
	}
	if end <= start {
		return fmt.Errorf("invalid callback stack range [0x%x, 0x%x)", start, end)
	}
	for address := start; ; {
		if _, _, err := mem.LookupRead(address, mmu.PermWrite); err != nil {
			return fmt.Errorf("callback stack is not writable at 0x%x: %w", address, err)
		}
		pageRemaining := mmu.PageSize - (address & (mmu.PageSize - 1))
		if end-address <= pageRemaining {
			return nil
		}
		address += pageRemaining
	}
}
