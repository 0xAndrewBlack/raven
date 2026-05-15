package jit_test

import (
	"math"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/jit"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func runX87Closure(t *testing.T, code []byte, st [8]float64, top int, cw, sw, tw uint16) (*jit.State, error) {
	t.Helper()
	mem := mmu.New()
	if err := mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteBytes(0x1000, append(code, 0xEB, 0xFE)); err != nil {
		t.Fatal(err)
	}
	cache := jit.NewCacheMode(mem, true)
	block := cache.Compile(0x1000)
	if block == nil {
		t.Fatal("x87 closure block did not compile")
	}
	regs := [16]uint64{}
	rip := uint64(0x1000)
	flags := uint64(2)
	state := &jit.State{
		Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
		FPUST: &st, FPUTop: &top, FPUCW: &cw, FPUSW: &sw, FPUTW: &tw,
	}
	return state, block.Run(state)
}

func TestX87ClosureModelsStackOverflowAndTags(t *testing.T) {
	state, err := runX87Closure(t, []byte{0xD9, 0xC1}, [8]float64{4, 2}, 0, 0x037F, 0x0102, 0)
	if err != nil {
		t.Fatal(err)
	}
	if *state.FPUTop != 7 || !math.IsNaN(state.FPUST[7]) {
		t.Fatalf("overflow result ST=%v top=%d", state.FPUST, *state.FPUTop)
	}
	if (*state.FPUTW>>14)&3 != 2 {
		t.Fatalf("overflow destination tag=%#x, want special", *state.FPUTW)
	}
	if *state.FPUSW != 0x0343 {
		t.Fatalf("overflow status=%#x, want 0x343", *state.FPUSW)
	}
}

func TestX87ClosureModelsConstantsAndPartialRemainder(t *testing.T) {
	state, err := runX87Closure(t, []byte{0xD9, 0xF0}, [8]float64{0.5}, 0, 0x037F, 0, 0xFFFC)
	if err != nil {
		t.Fatal(err)
	}
	if got := state.FPUST[0]; math.Abs(got-(math.Sqrt2-1)) > 1e-15 {
		t.Fatalf("F2XM1=%v, want %v", got, math.Sqrt2-1)
	}

	state, err = runX87Closure(t, []byte{0xD9, 0xF5}, [8]float64{4, 2}, 0, 0x037F, 0, 0xFFF0)
	if err != nil {
		t.Fatal(err)
	}
	if state.FPUST[0] != 0 || (*state.FPUTW&3) != 1 || *state.FPUSW&0x4700 != 0x4000 {
		t.Fatalf("FPREM1 ST=%v tag=%#x status=%#x", state.FPUST, *state.FPUTW, *state.FPUSW)
	}
}

func TestX87ClosureRollsBackUnmaskedStackFault(t *testing.T) {
	initial := [8]float64{4, 2}
	state, err := runX87Closure(t, []byte{0xD9, 0xE8}, initial, 0, 0x037E, 0, 0)
	if err == nil {
		t.Fatal("masked-off invalid exception did not fault")
	}
	if *state.FPUTop != 0 || *state.FPUTW != 0 {
		t.Fatalf("unmasked fault changed stack top=%d tags=%#x", *state.FPUTop, *state.FPUTW)
	}
	if state.FPUST[0] != initial[0] || state.FPUST[1] != initial[1] || *state.FPUSW != 0x2C1 {
		t.Fatalf("unmasked fault state ST=%v status=%#x", state.FPUST, *state.FPUSW)
	}
}
