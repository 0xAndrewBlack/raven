package jit

import (
	"errors"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

type nativeMemoryIntegerResult struct {
	regs     [16]uint64
	flags    uint64
	rip      uint64
	instret  uint64
	fallback bool
	data     uint32
}

func runNativeLeaFixture(t *testing.T, native, mode32 bool, code []byte, regs [16]uint64, flags uint64) nativeMemoryIntegerResult {
	t.Helper()
	mem := mmu.New()
	mem.Mode32 = mode32
	mem.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	program := append(append([]byte(nil), code...), 0xEB, 0xFE)
	for i, opcode := range program {
		if err := mem.Write8(0x3000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}
	cache := NewCacheMode(mem, mode32)
	if native && !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(0x3000)
	if block == nil {
		t.Fatal("LEA fixture did not compile")
	}
	if native && block.native == 0 {
		t.Fatal("native backend rejected LEA fixture")
	}
	rip := uint64(0x3000)
	instret := uint64(0)
	state := &State{
		Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
		Mode32: mode32, Instret: &instret,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	return nativeMemoryIntegerResult{
		regs: regs, flags: flags, rip: rip, instret: instret,
		fallback: state.Fallback,
	}
}

func TestNativeLeaMatchesClosure(t *testing.T) {
	tests := []struct {
		name   string
		mode32 bool
		code   []byte
		regs   [16]uint64
		dst    int
	}{
		{
			name: "PE64 base index scale displacement",
			code: []byte{0x48, 0x8D, 0x44, 0x8B, 0xE0},
			regs: [16]uint64{1: 7, 3: 0x100000000},
			dst:  0,
		},
		{
			name: "PE64 dword destination zero extends",
			code: []byte{0x8D, 0x44, 0x8B, 0xE0},
			regs: [16]uint64{0: ^uint64(0), 1: 7, 3: 0x100000000},
			dst:  0,
		},
		{
			name: "PE64 word destination preserves upper",
			code: []byte{0x66, 0x8D, 0x44, 0x8B, 0xE0},
			regs: [16]uint64{0: 0xAAAAAAAAAAAA5555, 1: 7, 3: 0x100000000},
			dst:  0,
		},
		{
			name: "PE64 RIP relative",
			code: []byte{0x48, 0x8D, 0x05, 0x34, 0x12, 0x00, 0x00},
			regs: [16]uint64{0: ^uint64(0)},
			dst:  0,
		},
		{
			name: "PE64 extended registers",
			code: []byte{0x4F, 0x8D, 0x54, 0xCC, 0x20},
			regs: [16]uint64{9: 3, 12: 0x1000},
			dst:  10,
		},
		{
			name: "PE64 index only",
			code: []byte{0x48, 0x8D, 0x04, 0xCD, 0x78, 0x56, 0x34, 0x12},
			regs: [16]uint64{1: 3},
			dst:  0,
		},
		{
			name:   "PE32 wraps address",
			mode32: true,
			code:   []byte{0x8D, 0x44, 0x8B, 0xE0},
			regs:   [16]uint64{1: 8, 3: 0xFFFFFFF0},
			dst:    0,
		},
		{
			name:   "PE32 absolute displacement",
			mode32: true,
			code:   []byte{0x8D, 0x05, 0x78, 0x56, 0x34, 0x12},
			regs:   [16]uint64{0: ^uint64(0)},
			dst:    0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const flags = uint64(0xA53)
			closure := runNativeLeaFixture(t, false, test.mode32, test.code, test.regs, flags)
			native := runNativeLeaFixture(t, true, test.mode32, test.code, test.regs, flags)
			if native != closure {
				t.Fatalf("native=%+v closure=%+v", native, closure)
			}
			if native.flags != flags || native.instret != 2 || native.fallback {
				t.Fatalf("LEA state=%+v", native)
			}
		})
	}
}

func runNativeALUMemoryFixture(t *testing.T, native bool, code []byte, regs [16]uint64, flags uint64, initial uint32) nativeMemoryIntegerResult {
	return runNativeALUMemoryFixtureAt(t, native, code, regs, flags, initial, 0x10000)
}

func runNativeALUMemoryFixtureAt(t *testing.T, native bool, code []byte, regs [16]uint64, flags uint64, initial uint32, addr uint64) nativeMemoryIntegerResult {
	t.Helper()
	mem := mmu.New()
	if native {
		if err := mem.EnableFlatBacking(); err != nil {
			t.Skipf("flat backing unavailable: %v", err)
		}
	}
	mem.Mode32 = true
	mem.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	mem.MapPage(addr&mmu.PageMask, mmu.PermRead|mmu.PermWrite)
	if (addr+3)&mmu.PageMask != addr&mmu.PageMask {
		mem.MapPage((addr+3)&mmu.PageMask, mmu.PermRead|mmu.PermWrite)
	}
	program := append(append([]byte(nil), code...), 0xEB, 0xFE)
	for i, opcode := range program {
		if err := mem.Write8(0x3000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}
	if err := mem.Write32(addr, initial); err != nil {
		t.Fatal(err)
	}
	regs[3] = addr
	cache := NewCacheMode(mem, true)
	if native && !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(0x3000)
	if block == nil {
		t.Fatal("ALU memory fixture did not compile")
	}
	if native && block.native == 0 {
		t.Fatalf("native backend rejected ALU memory fixture % x", code)
	}
	rip := uint64(0x3000)
	instret := uint64(0)
	state := &State{
		Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
		Mode32: true, Instret: &instret,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	data, err := mem.Read32(addr)
	if err != nil {
		t.Fatal(err)
	}
	return nativeMemoryIntegerResult{
		regs: regs, flags: flags, rip: rip, instret: instret,
		fallback: state.Fallback, data: data,
	}
}

func TestNativePE32ALUMemoryMatchesClosure(t *testing.T) {
	operations := []struct {
		name string
		op   byte
	}{
		{name: "ADD", op: 0},
		{name: "OR", op: 1},
		{name: "ADC", op: 2},
		{name: "SBB", op: 3},
		{name: "AND", op: 4},
		{name: "SUB", op: 5},
		{name: "XOR", op: 6},
		{name: "CMP", op: 7},
	}
	forms := []struct {
		name string
		code func(op byte, byteSize bool) []byte
	}{
		{
			name: "reg memory",
			code: func(op byte, byteSize bool) []byte {
				opcode := byte(0x03) + op*8
				if byteSize {
					opcode--
				}
				return []byte{opcode, 0x03}
			},
		},
		{
			name: "memory reg",
			code: func(op byte, byteSize bool) []byte {
				opcode := byte(0x01) + op*8
				if byteSize {
					opcode--
				}
				return []byte{opcode, 0x03}
			},
		},
		{
			name: "memory immediate",
			code: func(op byte, byteSize bool) []byte {
				opcode := byte(0x83)
				if byteSize {
					opcode = 0x80
				}
				return []byte{opcode, op<<3 | 0x03, 0x05}
			},
		},
	}
	for _, operation := range operations {
		for _, form := range forms {
			for _, byteSize := range []bool{false, true} {
				sizeName := "dword"
				if byteSize {
					sizeName = "byte"
				}
				t.Run(operation.name+"/"+form.name+"/"+sizeName, func(t *testing.T) {
					regs := [16]uint64{0: 0xAAAAAAAA00000011}
					flags := uint64(0xA52)
					if operation.op == byte(aluADC) || operation.op == byte(aluSBB) {
						flags |= flagCF
					}
					code := form.code(operation.op, byteSize)
					closure := runNativeALUMemoryFixture(t, false, code, regs, flags, 0x10203040)
					native := runNativeALUMemoryFixture(t, true, code, regs, flags, 0x10203040)
					if native != closure {
						t.Fatalf("native=%+v closure=%+v code=% x", native, closure, code)
					}
					if native.instret != 2 || native.fallback {
						t.Fatalf("ALU memory state=%+v", native)
					}
				})
			}
		}
	}
}

func TestNativePE32ALUMemoryEdgeValues(t *testing.T) {
	operations := []struct {
		name string
		op   byte
	}{
		{name: "ADD", op: byte(aluADD)},
		{name: "OR", op: byte(aluOR)},
		{name: "ADC", op: byte(aluADC)},
		{name: "SBB", op: byte(aluSBB)},
		{name: "AND", op: byte(aluAND)},
		{name: "SUB", op: byte(aluSUB)},
		{name: "XOR", op: byte(aluXOR)},
		{name: "CMP", op: byte(aluCMP)},
	}
	values := []struct {
		name  string
		a     uint32
		b     uint32
		flags uint64
	}{
		{name: "zero", a: 0, b: 0, flags: 0x202},
		{name: "carry", a: 0xFFFFFFFF, b: 1, flags: 0x202},
		{name: "signed overflow", a: 0x7FFFFFFF, b: 1, flags: 0x202},
		{name: "signed minimum", a: 0x80000000, b: 0xFFFFFFFF, flags: 0x202},
		{name: "borrow input", a: 0, b: 0, flags: 0x203},
		{name: "alternating bits", a: 0xAAAAAAAA, b: 0x55555555, flags: 0xA53},
	}
	for _, operation := range operations {
		for _, value := range values {
			t.Run(operation.name+"/"+value.name, func(t *testing.T) {
				code := []byte{0x03 + operation.op*8, 0x03}
				regs := [16]uint64{0: uint64(value.a)}
				closure := runNativeALUMemoryFixture(t, false, code, regs, value.flags, value.b)
				native := runNativeALUMemoryFixture(t, true, code, regs, value.flags, value.b)
				if native != closure {
					t.Fatalf("native=%+v closure=%+v code=% x", native, closure, code)
				}
			})
		}
	}
}

func TestNativePE32ALUMemoryAddressForms(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		regs [16]uint64
	}{
		{
			name: "SIB with displacement",
			code: []byte{0x03, 0x44, 0x8B, 0xFC},
			regs: [16]uint64{0: 5, 1: 1},
		},
		{
			name: "absolute disp32",
			code: []byte{0x03, 0x05, 0x00, 0x00, 0x01, 0x00},
			regs: [16]uint64{0: 5},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			closure := runNativeALUMemoryFixture(t, false, test.code, test.regs, 0xA53, 7)
			native := runNativeALUMemoryFixture(t, true, test.code, test.regs, 0xA53, 7)
			if native != closure || native.regs[0] != 12 {
				t.Fatalf("native=%+v closure=%+v", native, closure)
			}
		})
	}
}

func TestNativePE32ALUMemoryCrossPageSuccess(t *testing.T) {
	const addr = uint64(0x10FFE)
	code := []byte{0x01, 0x03}
	regs := [16]uint64{0: 0x01020304}
	closure := runNativeALUMemoryFixtureAt(t, false, code, regs, 0xA53, 0x10203040, addr)
	native := runNativeALUMemoryFixtureAt(t, true, code, regs, 0xA53, 0x10203040, addr)
	if native != closure || native.data != 0x11223344 {
		t.Fatalf("native=%+v closure=%+v", native, closure)
	}
}

func TestNativePE32ALUMemoryReadOnlyCompare(t *testing.T) {
	mem := mmu.New()
	if err := mem.EnableFlatBacking(); err != nil {
		t.Skipf("flat backing unavailable: %v", err)
	}
	mem.Mode32 = true
	mem.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	mem.MapPage(0x10000, mmu.PermRead|mmu.PermWrite)
	for i, opcode := range []byte{0x39, 0x03, 0xEB, 0xFE} {
		if err := mem.Write8(0x3000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}
	if err := mem.Write32(0x10000, 7); err != nil {
		t.Fatal(err)
	}
	if err := mem.Mprotect(0x10000, mmu.PageSize, mmu.PermRead|mmu.PermExecute); err != nil {
		t.Fatal(err)
	}
	cache := NewCacheMode(mem, true)
	if !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(0x3000)
	if block == nil || block.native == 0 {
		t.Fatal("native backend rejected read-only CMP")
	}
	regs := [16]uint64{0: 7, 3: 0x10000}
	flags := uint64(0x202)
	rip := uint64(0x3000)
	instret := uint64(0)
	state := &State{
		Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
		Mode32: true, Instret: &instret,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if state.Fallback || instret != 2 || flags&flagZF == 0 {
		t.Fatalf("flags=%#x instret=%d fallback=%v", flags, instret, state.Fallback)
	}
}

func TestNativePE32ALUMemoryFaultSideExits(t *testing.T) {
	tests := []struct {
		name     string
		code     []byte
		addr     uint64
		perms    uint8
		wantData uint32
	}{
		{
			name: "read unmapped",
			code: []byte{0x03, 0x03},
			addr: 0x12000,
		},
		{
			name:     "RMW read only",
			code:     []byte{0x01, 0x03},
			addr:     0x10000,
			perms:    mmu.PermRead,
			wantData: 7,
		},
		{
			name:     "RMW executable",
			code:     []byte{0x01, 0x03},
			addr:     0x10000,
			perms:    mmu.PermRead | mmu.PermWrite | mmu.PermExecute,
			wantData: 7,
		},
		{
			name:  "read crosses unmapped page",
			code:  []byte{0x03, 0x03},
			addr:  0x10FFF,
			perms: mmu.PermRead | mmu.PermWrite,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mem := mmu.New()
			if err := mem.EnableFlatBacking(); err != nil {
				t.Skipf("flat backing unavailable: %v", err)
			}
			mem.Mode32 = true
			mem.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			if test.perms != 0 {
				mem.MapPage(test.addr&mmu.PageMask, mmu.PermRead|mmu.PermWrite)
				if test.wantData != 0 {
					if err := mem.Write32(test.addr, test.wantData); err != nil {
						t.Fatal(err)
					}
				}
				if err := mem.Mprotect(test.addr&mmu.PageMask, mmu.PageSize, test.perms); err != nil {
					t.Fatal(err)
				}
			}
			program := append(append([]byte(nil), test.code...), 0xEB, 0xFE)
			for i, opcode := range program {
				if err := mem.Write8(0x3000+uint64(i), opcode); err != nil {
					t.Fatal(err)
				}
			}
			cache := NewCacheMode(mem, true)
			if !cache.EnableNativeCodegen() {
				t.Skip("native codegen unavailable")
			}
			block := cache.Compile(0x3000)
			if block == nil || block.native == 0 {
				t.Fatal("native backend rejected fault fixture")
			}
			regs := [16]uint64{0: 3, 3: test.addr}
			before := regs
			flags := uint64(0xA53)
			rip := uint64(0x3000)
			instret := uint64(0)
			state := &State{
				Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
				Mode32: true, Instret: &instret,
			}
			if err := block.Run(state); err != nil {
				t.Fatal(err)
			}
			if !state.Fallback || rip != 0x3000 || instret != 0 ||
				regs != before || flags != 0xA53 {
				t.Fatalf("fault state regs=%#v flags=%#x RIP=%#x instret=%d fallback=%v",
					regs, flags, rip, instret, state.Fallback)
			}
			if test.wantData != 0 {
				got, err := mem.Read32(test.addr)
				if err != nil || got != test.wantData {
					t.Fatalf("memory=%#x err=%v, want %#x", got, err, test.wantData)
				}
			}
		})
	}
}

func runNativeStackFixture(t *testing.T, native bool, code []byte, regs [16]uint64, stackValue uint32) nativeMemoryIntegerResult {
	t.Helper()
	mem := mmu.New()
	if native {
		if err := mem.EnableFlatBacking(); err != nil {
			t.Skipf("flat backing unavailable: %v", err)
		}
	}
	mem.Mode32 = true
	mem.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	mem.MapPage(0x20000, mmu.PermRead|mmu.PermWrite)
	for i, opcode := range code {
		if err := mem.Write8(0x3000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}
	if stackValue != 0 {
		if err := mem.Write32(regs[4], stackValue); err != nil {
			t.Fatal(err)
		}
	}
	cache := NewCacheMode(mem, true)
	if native && !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(0x3000)
	if block == nil {
		t.Fatal("stack fixture did not compile")
	}
	if native && block.native == 0 {
		t.Fatalf("native backend rejected stack fixture % x", code)
	}
	flags := uint64(0xA53)
	rip := uint64(0x3000)
	instret := uint64(0)
	state := &State{
		Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
		Mode32: true, Instret: &instret,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	data, err := mem.Read32(0x207FC)
	if err != nil {
		t.Fatal(err)
	}
	return nativeMemoryIntegerResult{
		regs: regs, flags: flags, rip: rip, instret: instret,
		fallback: state.Fallback, data: data,
	}
}

func TestNativePE32StackAndControlFlowMatchClosure(t *testing.T) {
	tests := []struct {
		name       string
		code       []byte
		regs       [16]uint64
		stackValue uint32
	}{
		{
			name: "push pop",
			code: []byte{0x50, 0x59, 0xEB, 0xFE},
			regs: [16]uint64{0: 0x12345678, 4: 0x20800},
		},
		{
			name: "word push pop",
			code: []byte{0x66, 0x50, 0x66, 0x59, 0xEB, 0xFE},
			regs: [16]uint64{
				0: 0x0123456789ABCDEF,
				1: 0xAAAAAAAA55555555,
				4: 0x20800,
			},
		},
		{
			name: "push ESP stores original value",
			code: []byte{0x54, 0x58, 0xEB, 0xFE},
			regs: [16]uint64{4: 0x20800},
		},
		{
			name:       "pop ESP uses popped value",
			code:       []byte{0x5C, 0xEB, 0xFE},
			regs:       [16]uint64{4: 0x20800},
			stackValue: 0x20500,
		},
		{
			name: "call rel32",
			code: []byte{0xE8, 0xFB, 0x00, 0x00, 0x00},
			regs: [16]uint64{4: 0x20800},
		},
		{
			name:       "ret imm16",
			code:       []byte{0xC2, 0x08, 0x00},
			regs:       [16]uint64{4: 0x20800},
			stackValue: 0x12345678,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			closure := runNativeStackFixture(t, false, test.code, test.regs, test.stackValue)
			native := runNativeStackFixture(t, true, test.code, test.regs, test.stackValue)
			if native != closure {
				t.Fatalf("native=%+v closure=%+v", native, closure)
			}
			if native.fallback {
				t.Fatalf("unexpected fallback: %+v", native)
			}
			if test.name == "word push pop" &&
				(native.regs[1] != 0xAAAAAAAA5555CDEF || native.regs[4] != 0x20800) {
				t.Fatalf("word PUSH/POP result=%+v", native)
			}
		})
	}
}

func TestPE32RelativeTargetsWrap(t *testing.T) {
	mem := mmu.New()
	mem.Mode32 = true
	mem.MapPage(0xFFFFF000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	tests := []struct {
		name string
		addr uint64
		code []byte
		kind opKind
	}{
		{name: "CALL rel32", addr: 0xFFFFFFFB, code: []byte{0xE8, 0, 0, 0, 0}, kind: opCall},
		{name: "JMP rel8", addr: 0xFFFFFFFE, code: []byte{0xEB, 0}, kind: opJmp},
		{name: "JMP rel32", addr: 0xFFFFFFFB, code: []byte{0xE9, 0, 0, 0, 0}, kind: opJmp},
		{name: "Jcc rel8", addr: 0xFFFFFFFE, code: []byte{0x74, 0}, kind: opJcc},
		{name: "Jcc rel32", addr: 0xFFFFFFFA, code: []byte{0x0F, 0x84, 0, 0, 0, 0}, kind: opJcc},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for i, opcode := range test.code {
				if err := mem.Write8(test.addr+uint64(i), opcode); err != nil {
					t.Fatal(err)
				}
			}
			d := decoder{mem: mem, pos: test.addr, mode32: true}
			if err := d.decodeOne(); err != nil {
				t.Fatal(err)
			}
			if len(d.insns) != 1 || d.insns[0].kind != test.kind || d.insns[0].target != 0 {
				t.Fatalf("decoded branch = %+v", d.insns)
			}
		})
	}
}

func TestPE32BoundaryBranchesMatchClosureAndNative(t *testing.T) {
	tests := []struct {
		name  string
		addr  uint64
		code  []byte
		flags uint64
		call  bool
	}{
		{
			name: "CALL rel32",
			addr: 0xFFFFFFFB,
			code: []byte{0xE8, 0, 0, 0, 0},
			call: true,
		},
		{
			name: "JMP rel8",
			addr: 0xFFFFFFFE,
			code: []byte{0xEB, 0},
		},
		{
			name:  "Jcc rel32 taken",
			addr:  0xFFFFFFFA,
			code:  []byte{0x0F, 0x84, 0, 0, 0, 0},
			flags: flagZF,
		},
		{
			name: "Jcc rel32 fallthrough",
			addr: 0xFFFFFFFA,
			code: []byte{0x0F, 0x84, 0, 0, 0, 0},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var results [2]nativeMemoryIntegerResult
			for native := range 2 {
				mem := mmu.New()
				if native != 0 {
					if err := mem.EnableFlatBacking(); err != nil {
						t.Skipf("flat backing unavailable: %v", err)
					}
				}
				mem.Mode32 = true
				mem.MapPage(0xFFFFF000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
				mem.MapPage(0x20000, mmu.PermRead|mmu.PermWrite)
				for i, opcode := range test.code {
					if err := mem.Write8(test.addr+uint64(i), opcode); err != nil {
						t.Fatal(err)
					}
				}
				cache := NewCacheMode(mem, true)
				if native != 0 && !cache.EnableNativeCodegen() {
					t.Skip("native codegen unavailable")
				}
				block := cache.Compile(test.addr)
				if block == nil {
					t.Fatal("boundary branch did not compile")
				}
				if native != 0 && block.native == 0 {
					t.Fatal("native backend rejected boundary branch")
				}
				regs := [16]uint64{4: 0x20800}
				flags := uint64(0x202) | test.flags
				rip := test.addr
				instret := uint64(0)
				state := &State{
					Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
					Mode32: true, Instret: &instret,
				}
				if err := block.Run(state); err != nil {
					t.Fatal(err)
				}
				result := nativeMemoryIntegerResult{
					regs: regs, flags: flags, rip: rip, instret: instret,
					fallback: state.Fallback,
				}
				if test.call {
					value, err := mem.Read32(0x207FC)
					if err != nil {
						t.Fatal(err)
					}
					result.data = value
				}
				results[native] = result
			}
			if results[1] != results[0] {
				t.Fatalf("native=%+v closure=%+v", results[1], results[0])
			}
			if results[0].rip != 0 || results[0].instret != 1 || results[0].fallback {
				t.Fatalf("boundary result=%+v", results[0])
			}
			if test.call {
				if results[0].regs[4] != 0x207FC || results[0].data != 0 {
					t.Fatalf("CALL result=%+v", results[0])
				}
			} else if results[0].regs[4] != 0x20800 {
				t.Fatalf("branch changed ESP: %+v", results[0])
			}
		})
	}
}

func TestClosurePE64WordPushPop(t *testing.T) {
	mem := mmu.New()
	mem.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	mem.MapPage(0x20000, mmu.PermRead|mmu.PermWrite)
	for i, opcode := range []byte{0x66, 0x50, 0x66, 0x59, 0xEB, 0xFE} {
		if err := mem.Write8(0x3000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}
	cache := NewCache(mem)
	block := cache.Compile(0x3000)
	if block == nil {
		t.Fatal("word stack fixture did not compile")
	}
	regs := [16]uint64{
		0: 0x0123456789ABCDEF,
		1: 0xAAAAAAAA55555555,
		4: 0x20800,
	}
	flags := uint64(0xA53)
	rip := uint64(0x3000)
	state := &State{Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if regs[1] != 0xAAAAAAAA5555CDEF || regs[4] != 0x20800 {
		t.Fatalf("RCX=%#x RSP=%#x", regs[1], regs[4])
	}
}

func TestClosurePE64WordStackFaultsAreAtomic(t *testing.T) {
	tests := []struct {
		name      string
		code      []byte
		sp        uint64
		faultAddr uint64
	}{
		{
			name:      "PUSH read only",
			code:      []byte{0x66, 0x50, 0xEB, 0xFE},
			sp:        0x20002,
			faultAddr: 0x20000,
		},
		{
			name:      "POP crosses unmapped page",
			code:      []byte{0x66, 0x58, 0xEB, 0xFE},
			sp:        0x20FFF,
			faultAddr: 0x21000,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mem := mmu.New()
			mem.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			mem.MapPage(0x20000, mmu.PermRead|mmu.PermWrite)
			for i, opcode := range test.code {
				if err := mem.Write8(0x3000+uint64(i), opcode); err != nil {
					t.Fatal(err)
				}
			}
			if err := mem.Mprotect(0x20000, mmu.PageSize, mmu.PermRead); err != nil {
				t.Fatal(err)
			}
			cache := NewCache(mem)
			block := cache.Compile(0x3000)
			if block == nil {
				t.Fatal("word stack fault fixture did not compile")
			}
			regs := [16]uint64{0: 0x0123456789ABCDEF, 4: test.sp}
			before := regs
			flags := uint64(0xA53)
			rip := uint64(0x3000)
			instret := uint64(0)
			state := &State{
				Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem, Instret: &instret,
			}
			err := block.Run(state)
			if err == nil {
				t.Fatal("word stack fault unexpectedly succeeded")
			}
			var fault *mmu.Fault
			if !errors.As(err, &fault) || fault.Addr != test.faultAddr {
				t.Fatalf("fault=%v, want address %#x", err, test.faultAddr)
			}
			if regs != before || flags != 0xA53 || rip != 0x3000 || instret != 0 {
				t.Fatalf("regs=%#v flags=%#x RIP=%#x instret=%d", regs, flags, rip, instret)
			}
		})
	}
}

func TestClosurePE32ALUMemoryWriteFaultIsAtomic(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{name: "register source", code: []byte{0x01, 0x03, 0xEB, 0xFE}},
		{name: "immediate source", code: []byte{0x83, 0x03, 0x01, 0xEB, 0xFE}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mem := mmu.New()
			mem.Mode32 = true
			mem.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			mem.MapPage(0x10000, mmu.PermRead|mmu.PermWrite)
			mem.MapPage(0x11000, mmu.PermRead|mmu.PermWrite)
			for i, opcode := range test.code {
				if err := mem.Write8(0x3000+uint64(i), opcode); err != nil {
					t.Fatal(err)
				}
			}
			const addr = 0x10FFE
			const initial = uint32(0x12345678)
			if err := mem.Write32(addr, initial); err != nil {
				t.Fatal(err)
			}
			if err := mem.Mprotect(0x11000, mmu.PageSize, mmu.PermRead); err != nil {
				t.Fatal(err)
			}

			cache := NewCacheMode(mem, true)
			block := cache.Compile(0x3000)
			if block == nil {
				t.Fatal("ALU memory fixture did not compile")
			}
			regs := [16]uint64{0: 1, 3: addr}
			before := regs
			flags := uint64(0xA53)
			rip := uint64(0x3000)
			instret := uint64(0)
			state := &State{
				Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
				Mode32: true, Instret: &instret,
			}
			if err := block.Run(state); err == nil {
				t.Fatal("write across read-only page unexpectedly succeeded")
			}
			got, err := mem.Read32(addr)
			if err != nil {
				t.Fatal(err)
			}
			if got != initial || regs != before || flags != 0xA53 ||
				rip != 0x3000 || instret != 0 {
				t.Fatalf("data=%#x regs=%#v flags=%#x RIP=%#x instret=%d",
					got, regs, flags, rip, instret)
			}
		})
	}
}

func TestNativePE32StackFaultIsAtomic(t *testing.T) {
	mem := mmu.New()
	if err := mem.EnableFlatBacking(); err != nil {
		t.Skipf("flat backing unavailable: %v", err)
	}
	mem.Mode32 = true
	mem.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	mem.MapPage(0x10000, mmu.PermRead)
	for i, opcode := range []byte{0xB8, 0x2A, 0x00, 0x00, 0x00, 0x50} {
		if err := mem.Write8(0x3000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}
	cache := NewCacheMode(mem, true)
	if !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(0x3000)
	if block == nil || block.native == 0 {
		t.Fatal("native backend rejected stack fault fixture")
	}
	regs := [16]uint64{0: 1, 4: 0x10004}
	flags := uint64(0xA53)
	rip := uint64(0x3000)
	instret := uint64(0)
	state := &State{
		Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
		Mode32: true, Instret: &instret,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if !state.Fallback || rip != 0x3005 || instret != 1 ||
		regs[0] != 42 || regs[4] != 0x10004 || flags != 0xA53 {
		t.Fatalf("fault state regs=%#v flags=%#x RIP=%#x instret=%d fallback=%v",
			regs, flags, rip, instret, state.Fallback)
	}
}

func TestNativePE32ControlFlowFaultsAreAtomic(t *testing.T) {
	tests := []struct {
		name     string
		code     []byte
		sp       uint64
		mapAddr  uint64
		mapPerms uint8
	}{
		{
			name: "POP unmapped",
			code: []byte{0x58},
			sp:   0x12000,
		},
		{
			name:     "CALL read only stack",
			code:     []byte{0xE8, 0xFB, 0x00, 0x00, 0x00},
			sp:       0x10004,
			mapAddr:  0x10000,
			mapPerms: mmu.PermRead,
		},
		{
			name:     "RET crosses unmapped page",
			code:     []byte{0xC3},
			sp:       0x10FFF,
			mapAddr:  0x10000,
			mapPerms: mmu.PermRead,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mem := mmu.New()
			if err := mem.EnableFlatBacking(); err != nil {
				t.Skipf("flat backing unavailable: %v", err)
			}
			mem.Mode32 = true
			mem.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			if test.mapAddr != 0 {
				mem.MapPage(test.mapAddr, mmu.PermRead|mmu.PermWrite)
				if err := mem.Mprotect(test.mapAddr, mmu.PageSize, test.mapPerms); err != nil {
					t.Fatal(err)
				}
			}
			for i, opcode := range test.code {
				if err := mem.Write8(0x3000+uint64(i), opcode); err != nil {
					t.Fatal(err)
				}
			}
			cache := NewCacheMode(mem, true)
			if !cache.EnableNativeCodegen() {
				t.Skip("native codegen unavailable")
			}
			block := cache.Compile(0x3000)
			if block == nil || block.native == 0 {
				t.Fatal("native backend rejected control-flow fault fixture")
			}
			regs := [16]uint64{0: 0x12345678, 4: test.sp}
			before := regs
			flags := uint64(0xA53)
			rip := uint64(0x3000)
			instret := uint64(0)
			state := &State{
				Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
				Mode32: true, Instret: &instret,
			}
			if err := block.Run(state); err != nil {
				t.Fatal(err)
			}
			if !state.Fallback || rip != 0x3000 || instret != 0 ||
				regs != before || flags != 0xA53 {
				t.Fatalf("fault state regs=%#v flags=%#x RIP=%#x instret=%d fallback=%v",
					regs, flags, rip, instret, state.Fallback)
			}
		})
	}
}

func BenchmarkNativePE32ALUMemory(b *testing.B) {
	for _, native := range []bool{false, true} {
		name := "Closure"
		if native {
			name = "Native"
		}
		b.Run(name, func(b *testing.B) {
			mem := mmu.New()
			if native {
				if err := mem.EnableFlatBacking(); err != nil {
					b.Skipf("flat backing unavailable: %v", err)
				}
			}
			mem.Mode32 = true
			mem.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			mem.MapPage(0x10000, mmu.PermRead|mmu.PermWrite)
			for i, opcode := range []byte{0x03, 0x03, 0x01, 0x0B, 0x83, 0x03, 0x01, 0xEB, 0xFE} {
				if err := mem.Write8(0x3000+uint64(i), opcode); err != nil {
					b.Fatal(err)
				}
			}
			cache := NewCacheMode(mem, true)
			if native && !cache.EnableNativeCodegen() {
				b.Skip("native codegen unavailable")
			}
			block := cache.Compile(0x3000)
			if block == nil || native && block.native == 0 {
				b.Fatal("memory benchmark did not compile")
			}
			regs := [16]uint64{0: 1, 1: 3, 3: 0x10000}
			flags := uint64(0x202)
			rip := uint64(0x3000)
			state := &State{Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem, Mode32: true}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := block.Run(state); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
