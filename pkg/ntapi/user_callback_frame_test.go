//go:build guest_windows

package ntapi

import (
	"bytes"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestBuildUserCallbackFrame32(t *testing.T) {
	mem := mmu.New()
	const base = uint64(0x200000)
	mem.MapRange(base, 2*mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	sentinel := bytes.Repeat([]byte{0xCC}, 2*mmu.PageSize)
	if err := mem.WriteBytes(base, sentinel); err != nil {
		t.Fatal(err)
	}

	oldStack := base + 0x1803
	input := []byte{0x10, 0x20, 0x30, 0x40, 0x50}
	frame, err := BuildUserCallbackFrame32(mem, oldStack, 7, input)
	if err != nil {
		t.Fatal(err)
	}
	wantBuffer := (oldStack - uint64(len(input))) &^ uint64(3)
	if frame.StackPointer != wantBuffer-userCallbackFrame32Size ||
		frame.Buffer != wantBuffer ||
		frame.Length != uint32(len(input)) {
		t.Fatalf("frame = %+v, want stack=0x%x buffer=0x%x length=%d",
			frame, wantBuffer-userCallbackFrame32Size, wantBuffer, len(input))
	}
	assertRead32(t, mem, frame.StackPointer+0x00, 0)
	assertRead32(t, mem, frame.StackPointer+0x04, 7)
	assertRead32(t, mem, frame.StackPointer+0x08, uint32(frame.Buffer))
	assertRead32(t, mem, frame.StackPointer+0x0C, uint32(len(input)))
	assertBytes(t, mem, frame.Buffer, input)
	assertBytes(t, mem, frame.StackPointer+0x10, bytes.Repeat([]byte{0xCC}, 8))
}

func TestBuildUserCallbackFrame64(t *testing.T) {
	mem := mmu.New()
	const base = uint64(0x300000)
	mem.MapRange(base, 2*mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	sentinel := bytes.Repeat([]byte{0xCC}, 2*mmu.PageSize)
	if err := mem.WriteBytes(base, sentinel); err != nil {
		t.Fatal(err)
	}

	oldStack := base + 0x1808
	input := []byte{0xA1, 0xB2, 0xC3, 0xD4, 0xE5}
	const returnPC = uint64(0x7FF612345678)
	frame, err := BuildUserCallbackFrame64(mem, oldStack, 11, input, returnPC)
	if err != nil {
		t.Fatal(err)
	}
	wantBuffer := ((oldStack - uint64(len(input))) &^ uint64(15)) - 8
	if frame.StackPointer != wantBuffer-userCallbackFrame64Size ||
		frame.Buffer != wantBuffer ||
		frame.Length != uint32(len(input)) {
		t.Fatalf("frame = %+v, want stack=0x%x buffer=0x%x length=%d",
			frame, wantBuffer-userCallbackFrame64Size, wantBuffer, len(input))
	}
	if frame.StackPointer&15 != 0 {
		t.Fatalf("stack pointer 0x%x is not 16-byte aligned", frame.StackPointer)
	}
	assertRead64(t, mem, frame.StackPointer+userCallbackFrame64BufferOffset, frame.Buffer)
	assertRead32(t, mem, frame.StackPointer+userCallbackFrame64LengthOffset, uint32(len(input)))
	assertRead32(t, mem, frame.StackPointer+userCallbackFrame64IndexOffset, 11)
	assertRead64(t, mem, frame.StackPointer+userCallbackFrame64RipOffset, returnPC)
	assertRead64(t, mem, frame.StackPointer+userCallbackFrame64RspOffset, oldStack)
	assertBytes(t, mem, frame.Buffer, input)

	assertBytes(t, mem, frame.StackPointer+0x00, bytes.Repeat([]byte{0xCC}, 0x20))
	assertBytes(t, mem, frame.StackPointer+0x38, bytes.Repeat([]byte{0xCC}, 0x10))
	assertBytes(t, mem, frame.StackPointer+0x50, bytes.Repeat([]byte{0xCC}, 8))
}

func TestBuildUserCallbackFramePreflightIsAtomic(t *testing.T) {
	mem := mmu.New()
	const base = uint64(0x400000)
	mem.MapRange(base, 2*mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	sentinel := bytes.Repeat([]byte{0x5A}, mmu.PageSize)
	if err := mem.WriteBytes(base, sentinel); err != nil {
		t.Fatal(err)
	}
	if err := mem.Mprotect(base+mmu.PageSize, mmu.PageSize, mmu.PermRead); err != nil {
		t.Fatal(err)
	}

	oldStack := base + mmu.PageSize + 64
	if _, err := BuildUserCallbackFrame64(mem, oldStack, 1, bytes.Repeat([]byte{0xEE}, 64), 0x1234); err == nil {
		t.Fatal("BuildUserCallbackFrame64 succeeded across a read-only page")
	}
	assertBytes(t, mem, base, sentinel)
}

func TestBuildUserCallbackFrameRejectsInvalidStack(t *testing.T) {
	mem := mmu.New()
	if _, err := BuildUserCallbackFrame32(mem, 1<<32, 0, nil); err == nil {
		t.Fatal("BuildUserCallbackFrame32 accepted a 64-bit stack pointer")
	}
	if _, err := BuildUserCallbackFrame32(mem, 8, 0, []byte{1}); err == nil {
		t.Fatal("BuildUserCallbackFrame32 accepted an underflowing frame")
	}
	if _, err := BuildUserCallbackFrame64(mem, 8, 0, []byte{1}, 0); err == nil {
		t.Fatal("BuildUserCallbackFrame64 accepted an underflowing frame")
	}
}

func TestBuildUserCallbackFrame64AtTopOfAddressSpace(t *testing.T) {
	mem := mmu.New()
	oldStack := ^uint64(0)
	if err := mem.MapPage(oldStack&mmu.PageMask, mmu.PermRead|mmu.PermWrite); err != nil {
		t.Fatal(err)
	}

	frame, err := BuildUserCallbackFrame64(mem, oldStack, 3, []byte{0xA5}, 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	assertBytes(t, mem, frame.Buffer, []byte{0xA5})
}

func TestParseUserCallbackReturn(t *testing.T) {
	got32 := ParseUserCallbackReturn32(
		0xAAAAAAAA12345678,
		0xBBBBBBBB87654321,
		0xCCCCCCCC80000005,
	)
	want32 := UserCallbackReturn{Address: 0x12345678, Length: 0x87654321, Status: 0x80000005}
	if got32 != want32 {
		t.Fatalf("PE32 return = %+v, want %+v", got32, want32)
	}

	got64 := ParseUserCallbackReturn64(
		0x123456789ABCDEF0,
		0xAAAAAAAA11223344,
		0xBBBBBBBBC000000D,
	)
	want64 := UserCallbackReturn{Address: 0x123456789ABCDEF0, Length: 0x11223344, Status: 0xC000000D}
	if got64 != want64 {
		t.Fatalf("PE64 return = %+v, want %+v", got64, want64)
	}
}

func assertRead32(t *testing.T, mem *mmu.MMU, address uint64, want uint32) {
	t.Helper()
	got, err := mem.Read32(address)
	if err != nil || got != want {
		t.Fatalf("Read32(0x%x) = 0x%x, %v; want 0x%x, nil", address, got, err, want)
	}
}

func assertRead64(t *testing.T, mem *mmu.MMU, address uint64, want uint64) {
	t.Helper()
	got, err := mem.Read64(address)
	if err != nil || got != want {
		t.Fatalf("Read64(0x%x) = 0x%x, %v; want 0x%x, nil", address, got, err, want)
	}
}

func assertBytes(t *testing.T, mem *mmu.MMU, address uint64, want []byte) {
	t.Helper()
	got, err := mem.ReadBytes(address, len(want))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("ReadBytes(0x%x, %d) = %x, %v; want %x, nil", address, len(want), got, err, want)
	}
}
