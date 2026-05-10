//go:build guest_windows

package ntapi

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestUserCallbackManagerPE32(t *testing.T) {
	mem, cpu := newUserCallbackTestCPU(t, true, 0x500000)
	manager := new(UserCallbackManager)
	before := cpu.Snapshot()

	frame, err := manager.Begin(cpu, mem, 0x401000, 3, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if cpu.GetPC() != 0x401000 || cpu.GetSP() != frame.StackPointer {
		t.Fatalf("callback control state PC=0x%x SP=0x%x, want PC=0x401000 SP=0x%x", cpu.GetPC(), cpu.GetSP(), frame.StackPointer)
	}
	if manager.Depth(cpu) != 1 {
		t.Fatalf("callback depth = %d, want 1", manager.Depth(cpu))
	}

	mutateUserCallbackCPU(cpu, 0x1111)
	got, err := manager.NtCallbackReturn(cpu, 0xAAAAAAAA12345678, 0xBBBBBBBB87654321, 0xCCCCCCCC80000005)
	if err != nil {
		t.Fatal(err)
	}
	want := UserCallbackReturn{Address: 0x12345678, Length: 0x87654321, Status: 0x80000005}
	if got != want {
		t.Fatalf("callback return = %+v, want %+v", got, want)
	}
	if restored := cpu.Snapshot(); restored != before {
		t.Fatalf("PE32 CPU snapshot was not restored")
	}
	if manager.Depth(cpu) != 0 {
		t.Fatalf("callback depth = %d, want 0", manager.Depth(cpu))
	}
}

func TestUserCallbackManagerPE64(t *testing.T) {
	mem, cpu := newUserCallbackTestCPU(t, false, 0x600000)
	manager := new(UserCallbackManager)
	before := cpu.Snapshot()
	returnPC := cpu.GetPC()

	frame, err := manager.Begin(cpu, mem, 0x7FF612340000, 9, []byte{4, 5, 6, 7})
	if err != nil {
		t.Fatal(err)
	}
	assertRead64(t, mem, frame.StackPointer+userCallbackFrame64RipOffset, returnPC)

	mutateUserCallbackCPU(cpu, 0x2222)
	got, err := manager.NtCallbackReturn(cpu, 0x123456789ABCDEF0, 0xAAAAAAAA11223344, 0xBBBBBBBBC000000D)
	if err != nil {
		t.Fatal(err)
	}
	want := UserCallbackReturn{Address: 0x123456789ABCDEF0, Length: 0x11223344, Status: 0xC000000D}
	if got != want {
		t.Fatalf("callback return = %+v, want %+v", got, want)
	}
	if restored := cpu.Snapshot(); restored != before {
		t.Fatalf("PE64 CPU snapshot was not restored")
	}
}

func TestUserCallbackManagerNestedLIFO(t *testing.T) {
	for _, mode32 := range []bool{false, true} {
		t.Run(fmt.Sprintf("mode32=%t", mode32), func(t *testing.T) {
			mem, cpu := newUserCallbackTestCPU(t, mode32, 0x700000)
			manager := new(UserCallbackManager)
			original := cpu.Snapshot()

			outerFrame, err := manager.Begin(cpu, mem, 0x710000, 1, []byte{1})
			if err != nil {
				t.Fatal(err)
			}
			mutateUserCallbackCPU(cpu, 0x3333)
			cpu.Mode32 = mode32
			cpu.SetSP(outerFrame.StackPointer - 0x100)
			outer := cpu.Snapshot()
			if _, err := manager.Begin(cpu, mem, 0x720000, 2, []byte{2}); err != nil {
				t.Fatal(err)
			}
			mutateUserCallbackCPU(cpu, 0x4444)

			innerReturn, err := manager.NtCallbackReturn(cpu, 0xAAAAAAAA00001111, 0xBBBBBBBB00000002, uint64(StatusSuccess))
			if err != nil {
				t.Fatal(err)
			}
			wantInnerAddress := uint64(0xAAAAAAAA00001111)
			if mode32 {
				wantInnerAddress = 0x1111
			}
			if innerReturn != (UserCallbackReturn{Address: wantInnerAddress, Length: 2, Status: StatusSuccess}) {
				t.Fatalf("inner callback return = %+v", innerReturn)
			}
			if restored := cpu.Snapshot(); restored != outer {
				t.Fatalf("inner return did not restore the outer callback state")
			}
			if manager.Depth(cpu) != 1 {
				t.Fatalf("callback depth after inner return = %d, want 1", manager.Depth(cpu))
			}

			outerReturn, err := manager.NtCallbackReturn(cpu, 0xCCCCCCCC00002222, 0xDDDDDDDD00000004, uint64(StatusBufferOverflow))
			if err != nil {
				t.Fatal(err)
			}
			wantOuterAddress := uint64(0xCCCCCCCC00002222)
			if mode32 {
				wantOuterAddress = 0x2222
			}
			if outerReturn != (UserCallbackReturn{Address: wantOuterAddress, Length: 4, Status: StatusBufferOverflow}) {
				t.Fatalf("outer callback return = %+v", outerReturn)
			}
			if restored := cpu.Snapshot(); restored != original {
				t.Fatalf("outer return did not restore the original CPU state")
			}

			first, ok := manager.TakeReturn(cpu)
			if !ok || first != innerReturn {
				t.Fatalf("first queued return = %+v, %t; want inner return", first, ok)
			}
			second, ok := manager.TakeReturn(cpu)
			if !ok || second != outerReturn {
				t.Fatalf("second queued return = %+v, %t; want outer return", second, ok)
			}
		})
	}
}

func TestUserCallbackManagerRejectsWrongCPUAndEmptyStack(t *testing.T) {
	memA, cpuA := newUserCallbackTestCPU(t, false, 0x800000)
	_, cpuB := newUserCallbackTestCPU(t, false, 0x900000)
	manager := new(UserCallbackManager)

	if _, err := manager.NtCallbackReturn(cpuA, 0, 0, 0); !errors.Is(err, ErrNoActiveUserCallback) {
		t.Fatalf("empty return error = %v, want %v", err, ErrNoActiveUserCallback)
	}
	if _, err := manager.Begin(cpuA, memA, 0x810000, 1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.NtCallbackReturn(cpuB, 0, 0, 0); !errors.Is(err, ErrUserCallbackWrongCPU) {
		t.Fatalf("wrong CPU error = %v, want %v", err, ErrUserCallbackWrongCPU)
	}
	if manager.Depth(cpuA) != 1 {
		t.Fatalf("wrong CPU return consumed callback, depth = %d", manager.Depth(cpuA))
	}
}

func TestUserCallbackManagerBeginFailureIsAtomic(t *testing.T) {
	_, cpu := newUserCallbackTestCPU(t, false, 0xA00000)
	manager := new(UserCallbackManager)
	before := cpu.Snapshot()

	if _, err := manager.Begin(cpu, mmu.New(), 0xA10000, 1, []byte{1}); err == nil {
		t.Fatal("Begin succeeded with an unmapped callback stack")
	}
	if got := cpu.Snapshot(); got != before {
		t.Fatal("failed Begin changed CPU state")
	}
	if manager.Depth(cpu) != 0 {
		t.Fatalf("failed Begin left callback depth %d", manager.Depth(cpu))
	}
}

func TestUserCallbackManagerConcurrentCPUs(t *testing.T) {
	manager := new(UserCallbackManager)
	const workers = 16

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			base := uint64(0x1000000 + i*0x10000)
			mem, cpu := newUserCallbackTestCPU(t, i%2 == 0, base)
			before := cpu.Snapshot()
			if _, err := manager.Begin(cpu, mem, base+0x8000, uint32(i), []byte{byte(i)}); err != nil {
				errs <- err
				return
			}
			got, err := manager.NtCallbackReturn(cpu, uint64(i), uint64(i+1), uint64(StatusSuccess))
			if err != nil {
				errs <- err
				return
			}
			wantAddress := uint64(i)
			if cpu.Mode32 {
				wantAddress = uint64(uint32(i))
			}
			if got != (UserCallbackReturn{Address: wantAddress, Length: uint32(i + 1), Status: StatusSuccess}) {
				errs <- fmt.Errorf("worker %d return = %+v", i, got)
				return
			}
			if cpu.Snapshot() != before {
				errs <- fmt.Errorf("worker %d CPU state was not restored", i)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestUserCallbackManagerConcurrentSameCPU(t *testing.T) {
	mem, cpu := newUserCallbackTestCPU(t, false, 0x2000000)
	manager := new(UserCallbackManager)
	const workers = 16

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := manager.Begin(cpu, mem, 0x2100000+uint64(i), uint32(i), []byte{byte(i)}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	if depth := manager.Depth(cpu); depth != workers {
		t.Fatalf("concurrent callback depth = %d, want %d", depth, workers)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := manager.NtCallbackReturn(cpu, uint64(i), uint64(i), uint64(StatusSuccess)); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if depth := manager.Depth(cpu); depth != 0 {
		t.Fatalf("completed callback depth = %d, want 0", depth)
	}
}

func TestDispatcherNtCallbackReturnContract(t *testing.T) {
	for _, mode32 := range []bool{false, true} {
		t.Run(fmt.Sprintf("mode32=%t", mode32), func(t *testing.T) {
			base := uint64(0x3000000)
			mem, cpu := newUserCallbackTestCPU(t, mode32, base)
			d := &Dispatcher{
				handlers:    make(map[uint32]TrapHandler),
				names:       make(map[uint32]string),
				cdeclIDs:    make(map[uint32]bool),
				stdcallArgs: make(map[uint32]int),
				ctx: &TrapContext{
					Mem:   mem,
					State: &ProcessState{Is32: mode32},
				},
			}
			d.ctx.Disp = d
			const syscallID = uint32(0x1234)
			d.register(syscallID, "NtCallbackReturn", d.handleNtCallbackReturn)

			before := cpu.Snapshot()
			if _, err := d.BeginUserCallback(cpu, base+0x8000, 7, []byte{1, 2}); err != nil {
				t.Fatal(err)
			}

			if mode32 {
				sp := cpu.GetSP() - 16
				if err := mem.Write32(sp, 0xDEADBEEF); err != nil {
					t.Fatal(err)
				}
				if err := mem.Write32(sp+4, 0x12345678); err != nil {
					t.Fatal(err)
				}
				if err := mem.Write32(sp+8, 0x11223344); err != nil {
					t.Fatal(err)
				}
				if err := mem.Write32(sp+12, StatusBufferOverflow); err != nil {
					t.Fatal(err)
				}
				cpu.SetSP(sp)
			} else {
				cpu.Regs[x64.RCX] = 0x123456789ABCDEF0
				cpu.Regs[x64.RDX] = 0x11223344
				cpu.Regs[x64.R8] = uint64(StatusBufferOverflow)
			}
			cpu.Regs[x64.RAX] = uint64(syscallID)
			d.Handle(cpu)

			if restored := cpu.Snapshot(); restored != before {
				t.Fatal("dispatcher Handle did not preserve the restored CPU state")
			}
			got, ok := d.TakeUserCallbackReturn(cpu)
			wantAddress := uint64(0x123456789ABCDEF0)
			if mode32 {
				wantAddress = 0x12345678
			}
			want := UserCallbackReturn{Address: wantAddress, Length: 0x11223344, Status: StatusBufferOverflow}
			if !ok || got != want {
				t.Fatalf("dispatcher return = %+v, %t; want %+v, true", got, ok, want)
			}

			emptyCtx := &TrapContext{CPU: cpu, Mem: mem, Disp: d, maxArgIdx: -1}
			if status := d.handleNtCallbackReturn(emptyCtx); status != StatusNoCallbackActive {
				t.Fatalf("empty handler status = 0x%x, want 0x%x", status, StatusNoCallbackActive)
			}
			if emptyCtx.PCRedirected || emptyCtx.ReturnOverridden {
				t.Fatalf("failed handler changed control-flow flags")
			}
		})
	}
}

func newUserCallbackTestCPU(t *testing.T, mode32 bool, base uint64) (*mmu.MMU, *x64.CPU) {
	t.Helper()
	mem := mmu.New()
	mem.MapRange(base, 4*mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	cpu := x64.New(mem)
	cpu.Mode32 = mode32
	cpu.SetSP(base + 3*mmu.PageSize)
	cpu.SetPC(base + 0x1234)
	cpu.Regs[x64.RAX] = base + 1
	cpu.Rflags = 0x246
	cpu.XMM[0] = [2]uint64{base + 2, base + 3}
	cpu.YMM_hi[0] = [2]uint64{base + 4, base + 5}
	cpu.MXCSR = 0x1F80
	return mem, cpu
}

func mutateUserCallbackCPU(cpu *x64.CPU, value uint64) {
	cpu.SetPC(value)
	cpu.SetSP(value + 1)
	cpu.Regs[x64.RAX] = value + 2
	cpu.Rflags = value + 3
	cpu.Mode32 = !cpu.Mode32
	cpu.XMM[0] = [2]uint64{value + 4, value + 5}
	cpu.YMM_hi[0] = [2]uint64{value + 6, value + 7}
	cpu.MXCSR = uint32(value)
}
