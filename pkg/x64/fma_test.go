package x64

import (
	"math"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestVFMADD213SDMemory(t *testing.T) {
	mem := mmu.New()
	mem.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermExecute)
	code := []byte{
		0xC4, 0xE2, 0xE9, 0xA9, 0x0D, 0x07, 0x00, 0x00, 0x00,
	}
	if err := mem.WriteBytesRaw(0x1000, code); err != nil {
		t.Fatal(err)
	}
	if err := mem.Write64Raw(0x1010, math.Float64bits(5)); err != nil {
		t.Fatal(err)
	}

	cpu := New(mem)
	cpu.RIP = 0x1000
	cpu.XMM[1] = [2]uint64{math.Float64bits(3), 0x1122334455667788}
	cpu.XMM[2][0] = math.Float64bits(4)
	cpu.YMM_hi[1] = [2]uint64{1, 2}

	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got := math.Float64frombits(cpu.XMM[1][0]); got != 17 {
		t.Fatalf("VFMADD213SD result = %v, want 17", got)
	}
	if got := cpu.XMM[1][1]; got != 0x1122334455667788 {
		t.Fatalf("VFMADD213SD changed upper XMM lane to 0x%x", got)
	}
	if got := cpu.YMM_hi[1]; got != [2]uint64{} {
		t.Fatalf("VFMADD213SD upper YMM = %#x", got)
	}
}

func TestVFMSUB213SDRegister(t *testing.T) {
	mem := mmu.New()
	mem.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermExecute)
	if err := mem.WriteBytesRaw(0x1000, []byte{0xC4, 0xE2, 0xC9, 0xAB, 0xE9}); err != nil {
		t.Fatal(err)
	}

	cpu := New(mem)
	cpu.RIP = 0x1000
	cpu.XMM[1][0] = math.Float64bits(4)
	cpu.XMM[5][0] = math.Float64bits(7)
	cpu.XMM[6][0] = math.Float64bits(3)

	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got := math.Float64frombits(cpu.XMM[5][0]); got != 17 {
		t.Fatalf("VFMSUB213SD result = %v, want 17", got)
	}
}

func TestVFMADD231SDMemory(t *testing.T) {
	mem := mmu.New()
	mem.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermExecute)
	code := []byte{
		0xC4, 0xE2, 0xC9, 0xB9, 0x05, 0x07, 0x00, 0x00, 0x00,
	}
	if err := mem.WriteBytesRaw(0x1000, code); err != nil {
		t.Fatal(err)
	}
	if err := mem.Write64Raw(0x1010, math.Float64bits(5)); err != nil {
		t.Fatal(err)
	}

	cpu := New(mem)
	cpu.RIP = 0x1000
	cpu.XMM[0][0] = math.Float64bits(2)
	cpu.XMM[6][0] = math.Float64bits(3)

	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got := math.Float64frombits(cpu.XMM[0][0]); got != 17 {
		t.Fatalf("VFMADD231SD result = %v, want 17", got)
	}
}

func TestVFMADD213SSPreservesUpperXMMBits(t *testing.T) {
	mem := mmu.New()
	mem.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermExecute)
	if err := mem.WriteBytesRaw(0x1000, []byte{0xC4, 0xE2, 0x69, 0xA9, 0xC1}); err != nil {
		t.Fatal(err)
	}

	cpu := New(mem)
	cpu.RIP = 0x1000
	cpu.XMM[0] = [2]uint64{0xAABBCCDD00000000 | uint64(math.Float32bits(3)), 0x1122334455667788}
	cpu.XMM[1][0] = uint64(math.Float32bits(5))
	cpu.XMM[2][0] = uint64(math.Float32bits(4))

	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got := math.Float32frombits(uint32(cpu.XMM[0][0])); got != 17 {
		t.Fatalf("VFMADD213SS result = %v, want 17", got)
	}
	if got := cpu.XMM[0][0] >> 32; got != 0xAABBCCDD {
		t.Fatalf("VFMADD213SS changed bits 63:32 to 0x%x", got)
	}
	if got := cpu.XMM[0][1]; got != 0x1122334455667788 {
		t.Fatalf("VFMADD213SS changed bits 127:64 to 0x%x", got)
	}
}

func TestVFMADD213SDIgnoresVEXL(t *testing.T) {
	mem := mmu.New()
	mem.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermExecute)
	if err := mem.WriteBytesRaw(0x1000, []byte{0xC4, 0xE2, 0xED, 0xA9, 0xC1}); err != nil {
		t.Fatal(err)
	}

	cpu := New(mem)
	cpu.RIP = 0x1000
	cpu.XMM[0][0] = math.Float64bits(3)
	cpu.XMM[1][0] = math.Float64bits(5)
	cpu.XMM[2][0] = math.Float64bits(4)

	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got := math.Float64frombits(cpu.XMM[0][0]); got != 17 {
		t.Fatalf("VFMADD213SD result = %v, want 17", got)
	}
}

func TestScalarFMAForms(t *testing.T) {
	tests := []struct {
		name      string
		order     byte
		operation byte
		want      float64
	}{
		{name: "add132", order: 0, operation: 0, want: 11},
		{name: "sub132", order: 0, operation: 2, want: 1},
		{name: "nmadd213", order: 1, operation: 4, want: -7},
		{name: "nmsub231", order: 2, operation: 6, want: -17},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := scalarFMA64(test.order, test.operation, 2, 5, 3); got != test.want {
				t.Fatalf("result = %v, want %v", got, test.want)
			}
		})
	}
}
