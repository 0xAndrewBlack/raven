//go:build guest_windows

package ntapi

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

type ioCompletionABITestContext struct {
	ctx  *TrapContext
	cpu  *ldrTestCPU
	mem  *mmu.MMU
	base uint64
}

func newIoCompletionABITestContext(t *testing.T, mode32 bool) *ioCompletionABITestContext {
	t.Helper()
	mem := mmu.New()
	mem.Mode32 = mode32
	base := mem.Mmap(0, 0x4000, mmu.PermRead|mmu.PermWrite)
	cpu := &ldrTestCPU{mem: mem, arch: arch.ArchAMD64, sp: base + 0x3000}
	if mode32 {
		cpu.arch = arch.ArchI386
	}
	return &ioCompletionABITestContext{
		ctx:  &TrapContext{CPU: cpu, Mem: mem, Handles: NewHandleTable(), maxArgIdx: -1},
		cpu:  cpu,
		mem:  mem,
		base: base,
	}
}

func (tc *ioCompletionABITestContext) setArgs(t *testing.T, args ...uint64) {
	t.Helper()
	tc.ctx.maxArgIdx = -1
	if tc.mem.Mode32 {
		if err := tc.mem.Write32(tc.cpu.sp, 0); err != nil {
			t.Fatal(err)
		}
		for index, value := range args {
			if err := tc.mem.Write32(tc.cpu.sp+4+uint64(index)*4, uint32(value)); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	for index := range tc.cpu.regs {
		tc.cpu.regs[index] = 0
	}
	registers := []int{regRCX, regRDX, regR8, regR9}
	for index, value := range args {
		if index < len(registers) {
			tc.cpu.regs[registers[index]] = value
			continue
		}
		if err := tc.mem.Write64(tc.cpu.sp+0x28+uint64(index-4)*8, value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNtCreateIoCompletionUsesGuestPointerWidth(t *testing.T) {
	for _, mode32 := range []bool{true, false} {
		name := "pe64"
		if mode32 {
			name = "pe32"
		}
		t.Run(name, func(t *testing.T) {
			tc := newIoCompletionABITestContext(t, mode32)
			output := tc.base + 0x100
			if err := tc.mem.Write64(output, 0xa5a5a5a5a5a5a5a5); err != nil {
				t.Fatal(err)
			}
			if err := tc.mem.Write64(output+8, 0xb6b6b6b6b6b6b6b6); err != nil {
				t.Fatal(err)
			}
			tc.setArgs(t, output)

			if status := handleNtCreateIoCompletion(tc.ctx); status != StatusSuccess {
				t.Fatalf("status = 0x%x", status)
			}
			if mode32 {
				handle, err := tc.mem.Read32(output)
				if err != nil || tc.ctx.Handles.GetIoCompletion(Handle(handle)) == nil {
					t.Fatalf("PE32 handle = 0x%x, %v", handle, err)
				}
				guard, err := tc.mem.Read32(output + 4)
				if err != nil || guard != 0xa5a5a5a5 {
					t.Fatalf("PE32 guard = 0x%x, %v", guard, err)
				}
				return
			}
			handle, err := tc.mem.Read64(output)
			if err != nil || tc.ctx.Handles.GetIoCompletion(Handle(handle)) == nil {
				t.Fatalf("PE64 handle = 0x%x, %v", handle, err)
			}
			guard, err := tc.mem.Read64(output + 8)
			if err != nil || guard != 0xb6b6b6b6b6b6b6b6 {
				t.Fatalf("PE64 guard = 0x%x, %v", guard, err)
			}
		})
	}
}

func TestNtRemoveIoCompletionUsesGuestPointerWidth(t *testing.T) {
	for _, mode32 := range []bool{true, false} {
		name := "pe64"
		if mode32 {
			name = "pe32"
		}
		t.Run(name, func(t *testing.T) {
			tc := newIoCompletionABITestContext(t, mode32)
			port := &IoCompletionPortHandle{}
			handle := tc.ctx.Handles.Alloc(port)
			port.Post(0x1122334455667788, 0x8877665544332211, 0xaabbccdd, 0xc0001234)
			key := tc.base + 0x100
			apc := tc.base + 0x120
			ioStatus := tc.base + 0x140
			timeout := tc.base + 0x180
			for _, address := range []uint64{key, apc} {
				if err := tc.mem.Write64(address, 0xa5a5a5a5a5a5a5a5); err != nil {
					t.Fatal(err)
				}
				if err := tc.mem.Write64(address+8, 0xb6b6b6b6b6b6b6b6); err != nil {
					t.Fatal(err)
				}
			}
			if err := tc.mem.WriteBytes(ioStatus, make([]byte, 24)); err != nil {
				t.Fatal(err)
			}
			if err := tc.mem.Write64(timeout, 0); err != nil {
				t.Fatal(err)
			}
			tc.setArgs(t, uint64(handle), key, apc, ioStatus, timeout)

			if status := handleNtRemoveIoCompletion(tc.ctx); status != StatusSuccess {
				t.Fatalf("status = 0x%x", status)
			}
			assertIoCompletionPointer(t, tc.mem, key, 0x1122334455667788)
			assertIoCompletionPointer(t, tc.mem, apc, 0x8877665544332211)
			if mode32 {
				assertIoCompletionUint32(t, tc.mem, key+4, 0xa5a5a5a5)
				assertIoCompletionUint32(t, tc.mem, apc+4, 0xa5a5a5a5)
			} else {
				assertIoCompletionPointer(t, tc.mem, key+8, 0xb6b6b6b6b6b6b6b6)
				assertIoCompletionPointer(t, tc.mem, apc+8, 0xb6b6b6b6b6b6b6b6)
			}
			status, err := tc.mem.Read32(ioStatus)
			if err != nil || status != 0xc0001234 {
				t.Fatalf("IO status = 0x%x, %v", status, err)
			}
			infoAddress := ioStatus + 8
			if mode32 {
				infoAddress = ioStatus + 4
			}
			assertIoCompletionPointer(t, tc.mem, infoAddress, 0xaabbccdd)
		})
	}
}

func TestNtRemoveIoCompletionExUsesNativeRecordLayout(t *testing.T) {
	for _, mode32 := range []bool{true, false} {
		name := "pe64"
		if mode32 {
			name = "pe32"
		}
		t.Run(name, func(t *testing.T) {
			tc := newIoCompletionABITestContext(t, mode32)
			port := &IoCompletionPortHandle{}
			handle := tc.ctx.Handles.Alloc(port)
			port.Post(0x1122334455667788, 0x8877665544332211, 0xaabbccdd, 0xc0001234)
			port.Post(0x0102030405060708, 0x1020304050607080, 0x12345678, 0x80005678)
			entries := tc.base + 0x200
			removed := tc.base + 0x300
			timeout := tc.base + 0x320
			if err := tc.mem.WriteBytes(entries, make([]byte, 80)); err != nil {
				t.Fatal(err)
			}
			if err := tc.mem.Write64(entries+32, 0xa5a5a5a5a5a5a5a5); err != nil {
				t.Fatal(err)
			}
			if err := tc.mem.Write64(entries+64, 0xa5a5a5a5a5a5a5a5); err != nil {
				t.Fatal(err)
			}
			if err := tc.mem.Write64(timeout, 0); err != nil {
				t.Fatal(err)
			}
			tc.setArgs(t, uint64(handle), entries, 2, removed, timeout, 0)

			if status := handleNtRemoveIoCompletionEx(tc.ctx); status != StatusSuccess {
				t.Fatalf("status = 0x%x", status)
			}
			gotRemoved, err := tc.mem.Read32(removed)
			if err != nil || gotRemoved != 2 {
				t.Fatalf("removed = %d, %v", gotRemoved, err)
			}
			ptrSize := uint64(8)
			if mode32 {
				ptrSize = 4
			}
			entrySize := ptrSize * 4
			assertIoCompletionEntry(t, tc.mem, entries, 0x1122334455667788, 0x8877665544332211, 0xc0001234, 0xaabbccdd)
			assertIoCompletionEntry(t, tc.mem, entries+entrySize, 0x0102030405060708, 0x1020304050607080, 0x80005678, 0x12345678)
			guardAddress := entries + entrySize*2
			wantGuard := uint64(0xa5a5a5a5a5a5a5a5)
			guard, err := tc.mem.Read64(guardAddress)
			if err != nil || guard != wantGuard {
				t.Fatalf("record guard = 0x%x, %v", guard, err)
			}
		})
	}
}

func TestNtRemoveIoCompletionValidatesOutputsBeforeDequeue(t *testing.T) {
	tc := newIoCompletionABITestContext(t, false)
	port := &IoCompletionPortHandle{}
	handle := tc.ctx.Handles.Alloc(port)
	port.Post(1, 2, 3, 4)
	tc.setArgs(t, uint64(handle), 0, tc.base+0x100, tc.base+0x120, 0)

	if status := handleNtRemoveIoCompletion(tc.ctx); status != StatusAccessViolation {
		t.Fatalf("status = 0x%x", status)
	}
	if _, result := port.RemoveEx(0); result != IoCompletionRemoved {
		t.Fatalf("remove result = %d", result)
	}
}

func TestNtRemoveIoCompletionExValidatesOutputsBeforeDequeue(t *testing.T) {
	tc := newIoCompletionABITestContext(t, true)
	port := &IoCompletionPortHandle{}
	handle := tc.ctx.Handles.Alloc(port)
	port.Post(1, 2, 3, 4)
	tc.setArgs(t, uint64(handle), tc.base+0x200, 2, 0, 0, 0)

	if status := handleNtRemoveIoCompletionEx(tc.ctx); status != StatusAccessViolation {
		t.Fatalf("status = 0x%x", status)
	}
	if _, result := port.RemoveEx(0); result != IoCompletionRemoved {
		t.Fatalf("remove result = %d", result)
	}
}

func TestNtCreateIoCompletionRejectsNullOutput(t *testing.T) {
	tc := newIoCompletionABITestContext(t, true)
	tc.setArgs(t, 0)

	if status := handleNtCreateIoCompletion(tc.ctx); status != StatusAccessViolation {
		t.Fatalf("status = 0x%x", status)
	}
}

func assertIoCompletionEntry(
	t *testing.T,
	mem *mmu.MMU,
	address, key, apc uint64,
	status, information uint32,
) {
	t.Helper()
	ptrSize := uint64(8)
	if mem.Mode32 {
		ptrSize = 4
	}
	assertIoCompletionPointer(t, mem, address, key)
	assertIoCompletionPointer(t, mem, address+ptrSize, apc)
	assertIoCompletionPointer(t, mem, address+ptrSize*2, uint64(status))
	assertIoCompletionPointer(t, mem, address+ptrSize*3, uint64(information))
}

func assertIoCompletionPointer(t *testing.T, mem *mmu.MMU, address, want uint64) {
	t.Helper()
	if mem.Mode32 {
		got, err := mem.Read32(address)
		if err != nil || got != uint32(want) {
			t.Fatalf("pointer at 0x%x = 0x%x, %v; want 0x%x", address, got, err, uint32(want))
		}
		return
	}
	got, err := mem.Read64(address)
	if err != nil || got != want {
		t.Fatalf("pointer at 0x%x = 0x%x, %v; want 0x%x", address, got, err, want)
	}
}

func assertIoCompletionUint32(t *testing.T, mem *mmu.MMU, address uint64, want uint32) {
	t.Helper()
	got, err := mem.Read32(address)
	if err != nil || got != want {
		t.Fatalf("uint32 at 0x%x = 0x%x, %v; want 0x%x", address, got, err, want)
	}
}
