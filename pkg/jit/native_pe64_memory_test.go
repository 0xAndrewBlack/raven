package jit

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

type pe64MemoryMapping struct {
	addr  uint64
	perms uint8
	data  []byte
}

type pe64MemoryResult struct {
	regs     [16]uint64
	flags    uint64
	rip      uint64
	instret  uint64
	fallback bool
	data     [][]byte
}

func runPE64MemoryFixture(t *testing.T, native bool, code []byte, regs [16]uint64, flags uint64, mappings []pe64MemoryMapping) pe64MemoryResult {
	t.Helper()
	mem := mmu.New()
	const codeAddr = uint64(0x3000)
	if err := mem.MapPage(codeAddr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute); err != nil {
		t.Fatal(err)
	}
	program := append(append([]byte(nil), code...), 0xEB, 0xFE)
	if err := mem.WriteBytes(codeAddr, program); err != nil {
		t.Fatal(err)
	}
	for _, mapping := range mappings {
		last := mapping.addr
		if len(mapping.data) > 0 {
			last += uint64(len(mapping.data) - 1)
		}
		firstPage, lastPage := mapping.addr&mmu.PageMask, last&mmu.PageMask
		for page := firstPage; ; page += mmu.PageSize {
			if err := mem.MapPage(page, mapping.perms); err != nil {
				t.Fatal(err)
			}
			if page == lastPage {
				break
			}
		}
		if err := mem.WriteBytesRaw(mapping.addr, mapping.data); err != nil {
			t.Fatal(err)
		}
	}

	cache := NewCacheMode(mem, false)
	if native && !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(codeAddr)
	if block == nil {
		t.Fatal("PE64 memory fixture did not compile")
	}
	if native && block.native == 0 {
		t.Fatalf("native backend rejected PE64 memory fixture % x", code)
	}
	rip := codeAddr
	instret := uint64(0)
	state := &State{
		Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
		Instret: &instret,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	result := pe64MemoryResult{
		regs: regs, flags: flags, rip: rip, instret: instret,
		fallback: state.Fallback,
	}
	for _, mapping := range mappings {
		data, err := mem.ReadBytesRaw(mapping.addr, len(mapping.data))
		if err != nil {
			t.Fatal(err)
		}
		result.data = append(result.data, data)
	}
	return result
}

func comparePE64MemoryFixture(t *testing.T, code []byte, regs [16]uint64, flags uint64, mappings []pe64MemoryMapping) pe64MemoryResult {
	t.Helper()
	closure := runPE64MemoryFixture(t, false, code, regs, flags, mappings)
	native := runPE64MemoryFixture(t, true, code, regs, flags, mappings)
	if native.regs != closure.regs || native.flags != closure.flags ||
		native.rip != closure.rip || native.instret != closure.instret ||
		native.fallback != closure.fallback || len(native.data) != len(closure.data) {
		t.Fatalf("native=%+v closure=%+v", native, closure)
	}
	for i := range native.data {
		if !bytes.Equal(native.data[i], closure.data[i]) {
			t.Fatalf("mapping %d native=% x closure=% x", i, native.data[i], closure.data[i])
		}
	}
	return native
}

func TestNativePE64MovMemoryMatchesClosure(t *testing.T) {
	const (
		lowAddr  = uint64(0x123456789120)
		highAddr = uint64(0xffff923456789120)
	)
	loads := []struct {
		name string
		code []byte
		addr uint64
		regs [16]uint64
		dst  int
		want uint64
	}{
		{
			name: "byte preserves upper",
			code: []byte{0x8A, 0x03},
			addr: lowAddr,
			regs: [16]uint64{0: 0xaabbccddeeff0011},
			dst:  0,
			want: 0xaabbccddeeff0088,
		},
		{
			name: "word preserves upper",
			code: []byte{0x66, 0x8B, 0x03},
			addr: lowAddr,
			regs: [16]uint64{0: 0xaabbccddeeff0011},
			dst:  0,
			want: 0xaabbccddeeff7788,
		},
		{
			name: "dword zero extends",
			code: []byte{0x8B, 0x03},
			addr: lowAddr,
			regs: [16]uint64{0: ^uint64(0)},
			dst:  0,
			want: 0x55667788,
		},
		{
			name: "qword low canonical",
			code: []byte{0x48, 0x8B, 0x03},
			addr: lowAddr,
			dst:  0,
			want: 0x1122334455667788,
		},
		{
			name: "qword high canonical",
			code: []byte{0x48, 0x8B, 0x03},
			addr: highAddr,
			dst:  0,
			want: 0x1122334455667788,
		},
		{
			name: "extended SIB registers",
			code: []byte{0x4F, 0x8B, 0x54, 0xCC, 0x20},
			addr: lowAddr,
			regs: [16]uint64{9: 2},
			dst:  10,
			want: 0x1122334455667788,
		},
	}
	initial := []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}
	for _, test := range loads {
		t.Run(test.name, func(t *testing.T) {
			regs := test.regs
			if test.name == "extended SIB registers" {
				regs[12] = test.addr - regs[9]*8 - 0x20
			} else {
				regs[3] = test.addr
			}
			result := comparePE64MemoryFixture(t, test.code, regs, 0xA53, []pe64MemoryMapping{{
				addr: test.addr, perms: mmu.PermRead | mmu.PermWrite, data: initial,
			}})
			if result.regs[test.dst] != test.want || result.fallback {
				t.Fatalf("register=%#x fallback=%v", result.regs[test.dst], result.fallback)
			}
		})
	}
}

func TestNativePE64MovStoresMatchClosure(t *testing.T) {
	const addr = uint64(0x123456789121)
	tests := []struct {
		name string
		code []byte
		want []byte
	}{
		{name: "byte", code: []byte{0x88, 0x03}, want: []byte{0x88, 0, 0, 0, 0, 0, 0, 0}},
		{name: "word", code: []byte{0x66, 0x89, 0x03}, want: []byte{0x88, 0x77, 0, 0, 0, 0, 0, 0}},
		{name: "dword", code: []byte{0x89, 0x03}, want: []byte{0x88, 0x77, 0x66, 0x55, 0, 0, 0, 0}},
		{name: "qword", code: []byte{0x48, 0x89, 0x03}, want: []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}},
		{name: "immediate byte", code: []byte{0xC6, 0x03, 0xA5}, want: []byte{0xA5, 0, 0, 0, 0, 0, 0, 0}},
		{name: "immediate qword sign extends", code: []byte{0x48, 0xC7, 0x03, 0xFE, 0xFF, 0xFF, 0xFF}, want: []byte{0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			regs := [16]uint64{0: 0x1122334455667788, 3: addr}
			result := comparePE64MemoryFixture(t, test.code, regs, 0xA53, []pe64MemoryMapping{{
				addr: addr, perms: mmu.PermRead | mmu.PermWrite, data: make([]byte, 8),
			}})
			if !bytes.Equal(result.data[0], test.want) || result.fallback {
				t.Fatalf("data=% x fallback=%v", result.data[0], result.fallback)
			}
		})
	}
}

func TestNativePE64ByteRegisterRestrictions(t *testing.T) {
	for _, code := range [][]byte{
		{0x88, 0x23},
		{0x8A, 0x23},
	} {
		mem := mmu.New()
		if err := mem.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute); err != nil {
			t.Fatal(err)
		}
		if err := mem.WriteBytes(0x3000, code); err != nil {
			t.Fatal(err)
		}
		cache := NewCacheMode(mem, false)
		if !cache.EnableNativeCodegen() {
			t.Skip("native codegen unavailable")
		}
		if block := cache.Compile(0x3000); block != nil {
			t.Fatalf("legacy high-byte memory form compiled: % x", code)
		}
	}

	const addr = uint64(0x123456789120)
	t.Run("REX SPL store", func(t *testing.T) {
		regs := [16]uint64{3: addr, 4: 0x1122334455667780}
		result := comparePE64MemoryFixture(t, []byte{0x40, 0x88, 0x23}, regs, 0x202, []pe64MemoryMapping{{
			addr: addr, perms: mmu.PermRead | mmu.PermWrite, data: []byte{0},
		}})
		if result.data[0][0] != 0x80 || result.fallback {
			t.Fatalf("data=% x fallback=%v", result.data[0], result.fallback)
		}
	})
	t.Run("REX SPL load", func(t *testing.T) {
		regs := [16]uint64{3: addr, 4: 0x1122334455667711}
		result := comparePE64MemoryFixture(t, []byte{0x40, 0x8A, 0x23}, regs, 0x202, []pe64MemoryMapping{{
			addr: addr, perms: mmu.PermRead, data: []byte{0x80},
		}})
		if result.regs[4] != 0x1122334455667780 || result.fallback {
			t.Fatalf("RSP=%#x fallback=%v", result.regs[4], result.fallback)
		}
	})
}

func TestNativePE64RIPRelativeAndExtensionsMatchClosure(t *testing.T) {
	const dataAddr = uint64(0x5000)
	tests := []struct {
		name string
		code []byte
		data []byte
		regs [16]uint64
		dst  int
		want uint64
	}{
		{
			name: "RIP relative qword",
			code: []byte{0x48, 0x8B, 0x05, 0xF9, 0x1F, 0x00, 0x00},
			data: []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11},
			want: 0x1122334455667788,
		},
		{
			name: "MOVZX byte to word preserves upper",
			code: []byte{0x66, 0x0F, 0xB6, 0x03},
			data: []byte{0x80, 0x7F},
			regs: [16]uint64{0: 0xaabbccddeeff1122},
			want: 0xaabbccddeeff0080,
		},
		{
			name: "MOVZX word to qword",
			code: []byte{0x48, 0x0F, 0xB7, 0x03},
			data: []byte{0x01, 0x80},
			want: 0x8001,
		},
		{
			name: "MOVSX byte to dword",
			code: []byte{0x0F, 0xBE, 0x03},
			data: []byte{0x80, 0x00},
			want: 0xffffff80,
		},
		{
			name: "MOVSX word to qword",
			code: []byte{0x48, 0x0F, 0xBF, 0x03},
			data: []byte{0x01, 0x80},
			want: 0xffffffffffff8001,
		},
		{
			name: "MOVZX extended destination",
			code: []byte{0x4C, 0x0F, 0xB6, 0x13},
			data: []byte{0xFE, 0x00},
			dst:  10,
			want: 0xFE,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			regs := test.regs
			regs[3] = dataAddr
			result := comparePE64MemoryFixture(t, test.code, regs, 0xA53, []pe64MemoryMapping{{
				addr: dataAddr, perms: mmu.PermRead | mmu.PermWrite, data: test.data,
			}})
			if result.regs[test.dst] != test.want || result.fallback {
				t.Fatalf("register=%#x fallback=%v", result.regs[test.dst], result.fallback)
			}
		})
	}
}

func TestNativePE64ALUMemoryMatchesClosure(t *testing.T) {
	const addr = uint64(0x123456789180)
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
	sizes := []struct {
		name   string
		prefix []byte
		wordOp bool
		size   int
	}{
		{name: "byte", size: 1},
		{name: "word", prefix: []byte{0x66}, wordOp: true, size: 2},
		{name: "dword", wordOp: true, size: 4},
		{name: "qword", prefix: []byte{0x48}, wordOp: true, size: 8},
	}
	forms := []struct {
		name string
		code func(op byte, size int, wordOp bool) []byte
	}{
		{
			name: "reg memory",
			code: func(op byte, _ int, wordOp bool) []byte {
				opcode := byte(0x02) + op*8
				if wordOp {
					opcode++
				}
				return []byte{opcode, 0x03}
			},
		},
		{
			name: "memory reg",
			code: func(op byte, _ int, wordOp bool) []byte {
				opcode := byte(0x00) + op*8
				if wordOp {
					opcode++
				}
				return []byte{opcode, 0x03}
			},
		},
		{
			name: "memory immediate",
			code: func(op byte, size int, _ bool) []byte {
				opcode := byte(0x83)
				if size == 1 {
					opcode = 0x80
				}
				return []byte{opcode, op<<3 | 3, 0x21}
			},
		},
	}

	for _, operation := range operations {
		for _, size := range sizes {
			for _, form := range forms {
				t.Run(operation.name+"/"+size.name+"/"+form.name, func(t *testing.T) {
					code := append([]byte(nil), size.prefix...)
					code = append(code, form.code(operation.op, size.size, size.wordOp)...)
					regs := [16]uint64{
						0: 0x8877665544332211,
						3: addr,
					}
					initial := make([]byte, 8)
					binary.LittleEndian.PutUint64(initial, 0x1020304050607080)
					result := comparePE64MemoryFixture(t, code, regs, flagCF|flagAF|flagDF, []pe64MemoryMapping{{
						addr: addr, perms: mmu.PermRead | mmu.PermWrite, data: initial,
					}})
					if result.fallback {
						t.Fatal("native ALU memory operation fell back")
					}
				})
			}
		}
	}
}

func TestNativePE64HostSensitiveFlagsStayGuestOnly(t *testing.T) {
	const addr = uint64(0x123456789180)
	const flags = uint64(flagCF | flagDF | 1<<8 | 1<<18)
	regs := [16]uint64{0: 7, 3: addr}
	result := comparePE64MemoryFixture(t, []byte{0x48, 0x03, 0x03}, regs, flags, []pe64MemoryMapping{{
		addr: addr, perms: mmu.PermRead, data: []byte{3, 0, 0, 0, 0, 0, 0, 0},
	}})
	if result.regs[0] != 10 || result.flags&(flagDF|1<<8|1<<18) != flags&(flagDF|1<<8|1<<18) ||
		result.fallback {
		t.Fatalf("RAX=%d flags=%#x fallback=%v", result.regs[0], result.flags, result.fallback)
	}
}

func TestNativePE64StackAndControlFlowMatchClosure(t *testing.T) {
	t.Run("push pop qword", func(t *testing.T) {
		const stack = uint64(0x12345678a000)
		regs := [16]uint64{
			0: 0x1122334455667788,
			4: stack + 0x800,
		}
		result := comparePE64MemoryFixture(t, []byte{0x50, 0x59}, regs, 0xA53, []pe64MemoryMapping{{
			addr: stack, perms: mmu.PermRead | mmu.PermWrite, data: make([]byte, mmu.PageSize),
		}})
		if result.regs[1] != regs[0] || result.regs[4] != regs[4] || result.fallback {
			t.Fatalf("RCX=%#x RSP=%#x fallback=%v", result.regs[1], result.regs[4], result.fallback)
		}
	})

	t.Run("push pop word", func(t *testing.T) {
		const stack = uint64(0xffff923456780000)
		regs := [16]uint64{
			0: 0x1122334455667788,
			1: 0xaabbccddeeff0011,
			4: stack + 0x800,
		}
		result := comparePE64MemoryFixture(t, []byte{0x66, 0x50, 0x66, 0x59}, regs, 0xA53, []pe64MemoryMapping{{
			addr: stack, perms: mmu.PermRead | mmu.PermWrite, data: make([]byte, mmu.PageSize),
		}})
		if result.regs[1] != 0xaabbccddeeff7788 || result.regs[4] != regs[4] || result.fallback {
			t.Fatalf("RCX=%#x RSP=%#x fallback=%v", result.regs[1], result.regs[4], result.fallback)
		}
	})

	t.Run("call", func(t *testing.T) {
		const stack = uint64(0x12345678b000)
		regs := [16]uint64{4: stack + 0x800}
		result := comparePE64MemoryFixture(t, []byte{0xE8, 0xFB, 0x0F, 0x00, 0x00}, regs, 0xA53, []pe64MemoryMapping{{
			addr: stack, perms: mmu.PermRead | mmu.PermWrite, data: make([]byte, mmu.PageSize),
		}})
		if result.rip != 0x4000 || result.regs[4] != regs[4]-8 || result.fallback {
			t.Fatalf("RIP=%#x RSP=%#x fallback=%v", result.rip, result.regs[4], result.fallback)
		}
		if got := binary.LittleEndian.Uint64(result.data[0][0x7f8:]); got != 0x3005 {
			t.Fatalf("return address=%#x", got)
		}
	})

	t.Run("ret", func(t *testing.T) {
		const stack = uint64(0x12345678c000)
		data := make([]byte, mmu.PageSize)
		binary.LittleEndian.PutUint64(data[0x800:], 0x5566778899aabbcc)
		regs := [16]uint64{4: stack + 0x800}
		result := comparePE64MemoryFixture(t, []byte{0xC2, 0x20, 0x00}, regs, 0xA53, []pe64MemoryMapping{{
			addr: stack, perms: mmu.PermRead | mmu.PermWrite, data: data,
		}})
		if result.rip != 0x5566778899aabbcc || result.regs[4] != regs[4]+8+0x20 || result.fallback {
			t.Fatalf("RIP=%#x RSP=%#x fallback=%v", result.rip, result.regs[4], result.fallback)
		}
	})
}

func TestNativePE64MappingMutationWhileRunning(t *testing.T) {
	mem := mmu.New()
	const (
		codeAddr = uint64(0x3000)
		dataAddr = uint64(0x12345678d000)
	)
	if err := mem.MapPage(codeAddr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteBytes(codeAddr, []byte{0x48, 0x8B, 0x03, 0xEB, 0xFE}); err != nil {
		t.Fatal(err)
	}
	first := make([]byte, mmu.PageSize)
	second := make([]byte, mmu.PageSize)
	binary.LittleEndian.PutUint64(first, 0x1111111111111111)
	binary.LittleEndian.PutUint64(second, 0x2222222222222222)
	mem.MapHostSlice(dataAddr, first, mmu.PermRead)

	cache := NewCacheMode(mem, false)
	if !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(codeAddr)
	if block == nil || block.native == 0 {
		t.Fatal("native PE64 memory block did not compile")
	}

	var stop atomic.Bool
	var failed atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		regs := [16]uint64{3: dataAddr}
		flags, rip := uint64(0x202), codeAddr
		state := &State{Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem}
		for !stop.Load() {
			rip = codeAddr
			state.Fallback = false
			if err := block.Run(state); err != nil {
				failed.Store(true)
				return
			}
			if state.Fallback {
				continue
			}
			if regs[0] != 0x1111111111111111 && regs[0] != 0x2222222222222222 {
				failed.Store(true)
				return
			}
		}
	}()

	for i := 0; i < 1000; i++ {
		switch i % 4 {
		case 0:
			mem.MapHostSlice(dataAddr, first, mmu.PermRead)
		case 1:
			mem.MapHostSlice(dataAddr, second, mmu.PermRead)
		case 2:
			mem.Munmap(dataAddr, mmu.PageSize)
		case 3:
			mem.MapHostSlice(dataAddr, second, mmu.PermRead|mmu.PermWrite)
		}
	}
	stop.Store(true)
	wg.Wait()
	if failed.Load() {
		t.Fatal("native access observed a torn mapping or host fault")
	}
}

func newPE64NativeFaultFixture(t *testing.T, code []byte, regs [16]uint64, mappings []pe64MemoryMapping) (*Block, *State, *mmu.MMU, *uint64) {
	t.Helper()
	mem := mmu.New()
	const codeAddr = uint64(0x3000)
	if err := mem.MapPage(codeAddr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute); err != nil {
		t.Fatal(err)
	}
	program := append(append([]byte(nil), code...), 0xEB, 0xFE)
	if err := mem.WriteBytes(codeAddr, program); err != nil {
		t.Fatal(err)
	}
	for _, mapping := range mappings {
		last := mapping.addr + uint64(len(mapping.data)-1)
		for page, lastPage := mapping.addr&mmu.PageMask, last&mmu.PageMask; ; page += mmu.PageSize {
			if err := mem.MapPage(page, mapping.perms); err != nil {
				t.Fatal(err)
			}
			if page == lastPage {
				break
			}
		}
		if err := mem.WriteBytesRaw(mapping.addr, mapping.data); err != nil {
			t.Fatal(err)
		}
	}
	cache := NewCacheMode(mem, false)
	if !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(codeAddr)
	if block == nil || block.native == 0 {
		t.Fatalf("native backend rejected fault fixture % x", code)
	}
	flags, rip, instret := uint64(flagCF|flagDF), codeAddr, uint64(0)
	state := &State{
		Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
		Instret: &instret,
	}
	return block, state, mem, &instret
}

func assertPE64NativeFallbackFault(t *testing.T, block *Block, state *State, instret *uint64, want mmu.Fault) {
	t.Helper()
	beforeRegs, beforeFlags := *state.Regs, *state.Rflags
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if !state.Fallback || *state.RIP != 0x3000 || *instret != 0 ||
		*state.Regs != beforeRegs || *state.Rflags != beforeFlags {
		t.Fatalf("fallback=%v RIP=%#x instret=%d regsChanged=%v flags=%#x",
			state.Fallback, *state.RIP, *instret, *state.Regs != beforeRegs, *state.Rflags)
	}
	state.Fallback = false
	err := block.fn(state)
	fault, ok := err.(*mmu.Fault)
	if !ok || *fault != want {
		t.Fatalf("closure fault=%T %v, want %+v", err, err, want)
	}
}

func TestNativePE64MemoryFaultFallbackIsAtomic(t *testing.T) {
	t.Run("unmapped read", func(t *testing.T) {
		const addr = uint64(0x123456789000)
		regs := [16]uint64{0: 0xaabbccddeeff0011, 3: addr}
		block, state, _, instret := newPE64NativeFaultFixture(t, []byte{0x48, 0x8B, 0x03}, regs, nil)
		assertPE64NativeFallbackFault(t, block, state, instret, mmu.Fault{
			Addr: addr, Type: mmu.FaultUnmapped, Perms: mmu.PermRead,
		})
	})

	t.Run("read only write", func(t *testing.T) {
		const addr = uint64(0x123456789000)
		data := bytes.Repeat([]byte{0x5a}, 8)
		regs := [16]uint64{0: 0x1122334455667788, 3: addr}
		block, state, mem, instret := newPE64NativeFaultFixture(t, []byte{0x48, 0x89, 0x03}, regs, []pe64MemoryMapping{{
			addr: addr, perms: mmu.PermRead, data: data,
		}})
		assertPE64NativeFallbackFault(t, block, state, instret, mmu.Fault{
			Addr: addr, Type: mmu.FaultPermission, Perms: mmu.PermRead,
		})
		got, err := mem.ReadBytesRaw(addr, len(data))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("faulting write changed memory: % x, %v", got, err)
		}
	})

	t.Run("write only read", func(t *testing.T) {
		const addr = uint64(0x123456789000)
		regs := [16]uint64{0: 0xaabbccddeeff0011, 3: addr}
		block, state, _, instret := newPE64NativeFaultFixture(t, []byte{0x48, 0x8B, 0x03}, regs, []pe64MemoryMapping{{
			addr: addr, perms: mmu.PermWrite, data: make([]byte, 8),
		}})
		assertPE64NativeFallbackFault(t, block, state, instret, mmu.Fault{
			Addr: addr, Type: mmu.FaultPermission, Perms: mmu.PermWrite,
		})
	})

	t.Run("execute only read", func(t *testing.T) {
		const addr = uint64(0x123456789000)
		regs := [16]uint64{0: 0xaabbccddeeff0011, 3: addr}
		block, state, _, instret := newPE64NativeFaultFixture(t, []byte{0x48, 0x8B, 0x03}, regs, []pe64MemoryMapping{{
			addr: addr, perms: mmu.PermExecute, data: make([]byte, 8),
		}})
		assertPE64NativeFallbackFault(t, block, state, instret, mmu.Fault{
			Addr: addr, Type: mmu.FaultPermission, Perms: mmu.PermExecute,
		})
	})

	t.Run("write only store", func(t *testing.T) {
		const addr = uint64(0x123456789000)
		regs := [16]uint64{0: 0x1122334455667788, 3: addr}
		block, state, mem, instret := newPE64NativeFaultFixture(t, []byte{0x48, 0x89, 0x03}, regs, []pe64MemoryMapping{{
			addr: addr, perms: mmu.PermWrite, data: make([]byte, 8),
		}})
		if err := block.Run(state); err != nil {
			t.Fatal(err)
		}
		got, err := mem.ReadBytesRaw(addr, 8)
		if err != nil {
			t.Fatal(err)
		}
		if state.Fallback || *instret != 2 ||
			!bytes.Equal(got, []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}) {
			t.Fatalf("fallback=%v instret=%d data=% x", state.Fallback, *instret, got)
		}
	})

	t.Run("noncanonical", func(t *testing.T) {
		const addr = uint64(1) << 47
		regs := [16]uint64{0: 0xaabbccddeeff0011, 3: addr}
		block, state, _, instret := newPE64NativeFaultFixture(t, []byte{0x48, 0x8B, 0x03}, regs, nil)
		assertPE64NativeFallbackFault(t, block, state, instret, mmu.Fault{
			Addr: addr, Type: mmu.FaultUnmapped, Perms: mmu.PermRead,
		})
	})

	t.Run("canonical hole crossing", func(t *testing.T) {
		const addr = (uint64(1) << 47) - 1
		regs := [16]uint64{0: 0xaabbccddeeff0011, 3: addr}
		block, state, _, instret := newPE64NativeFaultFixture(t, []byte{0x66, 0x8B, 0x03}, regs, []pe64MemoryMapping{{
			addr: addr, perms: mmu.PermRead, data: []byte{0x5a},
		}})
		assertPE64NativeFallbackFault(t, block, state, instret, mmu.Fault{
			Addr: 1 << 47, Type: mmu.FaultUnmapped, Perms: mmu.PermRead,
		})
	})

	t.Run("uint64 wrap", func(t *testing.T) {
		const addr = ^uint64(0)
		regs := [16]uint64{0: 0xaabbccddeeff0011, 3: addr}
		block, state, _, instret := newPE64NativeFaultFixture(t, []byte{0x66, 0x8B, 0x03}, regs, []pe64MemoryMapping{{
			addr: addr, perms: mmu.PermRead, data: []byte{0x5a},
		}})
		assertPE64NativeFallbackFault(t, block, state, instret, mmu.Fault{
			Addr: ^uint64(0), Type: mmu.FaultUnmapped, Perms: mmu.PermRead,
		})
	})

	t.Run("cross page RMW permission", func(t *testing.T) {
		const page = uint64(0x12345678e000)
		addr := page + mmu.PageSize - 4
		first := bytes.Repeat([]byte{0x11}, 4)
		second := bytes.Repeat([]byte{0x22}, 4)
		regs := [16]uint64{0: 7, 3: addr}
		block, state, mem, instret := newPE64NativeFaultFixture(t, []byte{0x48, 0x01, 0x03}, regs, []pe64MemoryMapping{
			{addr: addr, perms: mmu.PermRead | mmu.PermWrite, data: first},
			{addr: page + mmu.PageSize, perms: mmu.PermRead, data: second},
		})
		assertPE64NativeFallbackFault(t, block, state, instret, mmu.Fault{
			Addr: page + mmu.PageSize, Type: mmu.FaultPermission, Perms: mmu.PermRead,
		})
		gotFirst, _ := mem.ReadBytesRaw(addr, 4)
		gotSecond, _ := mem.ReadBytesRaw(page+mmu.PageSize, 4)
		if !bytes.Equal(gotFirst, first) || !bytes.Equal(gotSecond, second) {
			t.Fatalf("faulting RMW changed memory: % x % x", gotFirst, gotSecond)
		}
	})

	t.Run("cross page MOV permission", func(t *testing.T) {
		const page = uint64(0x12345678f000)
		addr := page + mmu.PageSize - 4
		first := bytes.Repeat([]byte{0x11}, 4)
		second := bytes.Repeat([]byte{0x22}, 4)
		regs := [16]uint64{0: 0x1122334455667788, 3: addr}
		block, state, mem, instret := newPE64NativeFaultFixture(t, []byte{0x48, 0x89, 0x03}, regs, []pe64MemoryMapping{
			{addr: addr, perms: mmu.PermRead | mmu.PermWrite, data: first},
			{addr: page + mmu.PageSize, perms: mmu.PermRead, data: second},
		})
		assertPE64NativeFallbackFault(t, block, state, instret, mmu.Fault{
			Addr: page + mmu.PageSize, Type: mmu.FaultPermission, Perms: mmu.PermRead,
		})
		gotFirst, _ := mem.ReadBytesRaw(addr, 4)
		gotSecond, _ := mem.ReadBytesRaw(page+mmu.PageSize, 4)
		if !bytes.Equal(gotFirst, first) || !bytes.Equal(gotSecond, second) {
			t.Fatalf("faulting MOV changed memory: % x % x", gotFirst, gotSecond)
		}
	})
}

func TestNativePE64CrossPageAccessFallsBackThenClosureSucceeds(t *testing.T) {
	const page = uint64(0x123456790000)

	t.Run("read", func(t *testing.T) {
		addr := page + mmu.PageSize - 4
		data := []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}
		regs := [16]uint64{0: 0xaabbccddeeff0011, 3: addr}
		block, state, _, instret := newPE64NativeFaultFixture(t, []byte{0x48, 0x8B, 0x03}, regs, []pe64MemoryMapping{{
			addr: addr, perms: mmu.PermRead | mmu.PermWrite, data: data,
		}})
		if err := block.Run(state); err != nil {
			t.Fatal(err)
		}
		if !state.Fallback || *state.RIP != 0x3000 || *instret != 0 || state.Regs[0] != regs[0] {
			t.Fatalf("fallback=%v RIP=%#x instret=%d RAX=%#x", state.Fallback, *state.RIP, *instret, state.Regs[0])
		}
		state.Fallback = false
		if err := block.fn(state); err != nil {
			t.Fatal(err)
		}
		if state.Regs[0] != 0x1122334455667788 || state.Fallback {
			t.Fatalf("closure RAX=%#x fallback=%v", state.Regs[0], state.Fallback)
		}
	})

	t.Run("write", func(t *testing.T) {
		addr := page + 2*mmu.PageSize - 4
		data := make([]byte, 8)
		regs := [16]uint64{0: 0x1122334455667788, 3: addr}
		block, state, mem, instret := newPE64NativeFaultFixture(t, []byte{0x48, 0x89, 0x03}, regs, []pe64MemoryMapping{{
			addr: addr, perms: mmu.PermRead | mmu.PermWrite, data: data,
		}})
		if err := block.Run(state); err != nil {
			t.Fatal(err)
		}
		got, _ := mem.ReadBytesRaw(addr, 8)
		if !state.Fallback || *instret != 0 || !bytes.Equal(got, data) {
			t.Fatalf("fallback=%v instret=%d data=% x", state.Fallback, *instret, got)
		}
		state.Fallback = false
		if err := block.fn(state); err != nil {
			t.Fatal(err)
		}
		got, _ = mem.ReadBytesRaw(addr, 8)
		if !bytes.Equal(got, []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}) {
			t.Fatalf("closure data=% x", got)
		}
	})

	t.Run("call", func(t *testing.T) {
		stackPage := page + 4*mmu.PageSize
		sp := stackPage + mmu.PageSize + 4
		regs := [16]uint64{4: sp}
		block, state, mem, instret := newPE64NativeFaultFixture(t, []byte{0xE8, 0xFB, 0x0F, 0x00, 0x00}, regs, []pe64MemoryMapping{{
			addr: stackPage, perms: mmu.PermRead | mmu.PermWrite, data: make([]byte, 2*mmu.PageSize),
		}})
		if err := block.Run(state); err != nil {
			t.Fatal(err)
		}
		if !state.Fallback || *instret != 0 || state.Regs[4] != sp {
			t.Fatalf("fallback=%v instret=%d RSP=%#x", state.Fallback, *instret, state.Regs[4])
		}
		state.Fallback = false
		if err := block.fn(state); err != nil {
			t.Fatal(err)
		}
		data, err := mem.ReadBytesRaw(sp-8, 8)
		if err != nil {
			t.Fatal(err)
		}
		if binary.LittleEndian.Uint64(data) != 0x3005 || state.Regs[4] != sp-8 || *state.RIP != 0x4000 {
			t.Fatalf("return=%#x RSP=%#x RIP=%#x", binary.LittleEndian.Uint64(data), state.Regs[4], *state.RIP)
		}
	})
}

func TestNativePE64RandomizedMemoryDifferential(t *testing.T) {
	const (
		codeAddr = uint64(0x3000)
		dataPage = uint64(0x123456790000)
	)
	type runner struct {
		block *Block
		mem   *mmu.MMU
	}
	newRunner := func(native bool) runner {
		mem := mmu.New()
		if err := mem.MapPage(codeAddr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute); err != nil {
			t.Fatal(err)
		}
		if err := mem.MapPage(dataPage, mmu.PermRead|mmu.PermWrite); err != nil {
			t.Fatal(err)
		}
		if err := mem.WriteBytes(codeAddr, []byte{0x48, 0x03, 0x03, 0xEB, 0xFE}); err != nil {
			t.Fatal(err)
		}
		cache := NewCacheMode(mem, false)
		if native && !cache.EnableNativeCodegen() {
			t.Skip("native codegen unavailable")
		}
		block := cache.Compile(codeAddr)
		if block == nil || native && block.native == 0 {
			t.Fatal("randomized memory block did not compile")
		}
		return runner{block: block, mem: mem}
	}
	closure, native := newRunner(false), newRunner(true)
	rng := rand.New(rand.NewSource(0x50453634))
	const flagMask = uint64(flagCF | flagPF | flagAF | flagZF | flagSF | flagDF | flagOF)
	for i := 0; i < 500; i++ {
		offset := uint64(rng.Intn(mmu.PageSize - 7))
		addr := dataPage + offset
		value := rng.Uint64()
		if err := closure.mem.Write64(addr, value); err != nil {
			t.Fatal(err)
		}
		if err := native.mem.Write64(addr, value); err != nil {
			t.Fatal(err)
		}
		initialRegs := [16]uint64{0: rng.Uint64(), 3: addr}
		initialFlags := rng.Uint64() & flagMask

		run := func(r runner) pe64MemoryResult {
			regs, flags, rip, instret := initialRegs, initialFlags, codeAddr, uint64(0)
			state := &State{Regs: &regs, RIP: &rip, Rflags: &flags, Mem: r.mem, Instret: &instret}
			if err := r.block.Run(state); err != nil {
				t.Fatal(err)
			}
			return pe64MemoryResult{
				regs: regs, flags: flags, rip: rip, instret: instret,
				fallback: state.Fallback,
			}
		}
		want, got := run(closure), run(native)
		if got.regs != want.regs || got.flags != want.flags || got.rip != want.rip ||
			got.instret != want.instret || got.fallback != want.fallback {
			t.Fatalf("iteration %d offset=%#x native=%+v closure=%+v", i, offset, got, want)
		}
	}
}

func TestNativePE64RemapProtectUnmapRedirectsCompiledBlock(t *testing.T) {
	mem := mmu.New()
	const (
		codeAddr = uint64(0x3000)
		dataAddr = uint64(0x123456791000)
	)
	if err := mem.MapPage(codeAddr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteBytes(codeAddr, []byte{0x48, 0x8B, 0x03, 0xEB, 0xFE}); err != nil {
		t.Fatal(err)
	}
	first := make([]byte, mmu.PageSize)
	second := make([]byte, mmu.PageSize)
	binary.LittleEndian.PutUint64(first, 0x1111111111111111)
	binary.LittleEndian.PutUint64(second, 0x2222222222222222)
	mem.MapHostSlice(dataAddr, first, mmu.PermRead)
	cache := NewCacheMode(mem, false)
	if !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(codeAddr)
	if block == nil || block.native == 0 {
		t.Fatal("native remap block did not compile")
	}
	run := func() (uint64, bool) {
		regs := [16]uint64{3: dataAddr}
		flags, rip := uint64(0x202), codeAddr
		state := &State{Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem}
		if err := block.Run(state); err != nil {
			t.Fatal(err)
		}
		return regs[0], state.Fallback
	}
	if value, fallback := run(); value != 0x1111111111111111 || fallback {
		t.Fatalf("first value=%#x fallback=%v", value, fallback)
	}
	mem.MapHostSlice(dataAddr, second, mmu.PermRead)
	if value, fallback := run(); value != 0x2222222222222222 || fallback {
		t.Fatalf("remap value=%#x fallback=%v", value, fallback)
	}
	if err := mem.Mprotect(dataAddr, mmu.PageSize, mmu.PermWrite); err != nil {
		t.Fatal(err)
	}
	if value, fallback := run(); value != 0 || !fallback {
		t.Fatalf("protected value=%#x fallback=%v", value, fallback)
	}
	if err := mem.Mprotect(dataAddr, mmu.PageSize, mmu.PermRead); err != nil {
		t.Fatal(err)
	}
	if value, fallback := run(); value != 0x2222222222222222 || fallback {
		t.Fatalf("restored value=%#x fallback=%v", value, fallback)
	}
	mem.Munmap(dataAddr, mmu.PageSize)
	if value, fallback := run(); value != 0 || !fallback {
		t.Fatalf("unmapped value=%#x fallback=%v", value, fallback)
	}
}

func TestNativePE64ExecutableAndWatchedWritesUseClosure(t *testing.T) {
	const addr = uint64(0x123456792000)
	regs := [16]uint64{0: 0x1122334455667788, 3: addr}
	block, state, mem, instret := newPE64NativeFaultFixture(t, []byte{0x48, 0x89, 0x03}, regs, []pe64MemoryMapping{{
		addr: addr, perms: mmu.PermRead | mmu.PermWrite | mmu.PermExecute, data: make([]byte, 8),
	}})
	entry, _, err := mem.LookupRead(addr, 0)
	if err != nil {
		t.Fatal(err)
	}
	beforeVersion := entry.CodeVersion.Load()
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if !state.Fallback || *instret != 0 || entry.CodeVersion.Load() != beforeVersion {
		t.Fatalf("fallback=%v instret=%d codeVersion=%d", state.Fallback, *instret, entry.CodeVersion.Load())
	}
	state.Fallback = false
	if err := block.fn(state); err != nil {
		t.Fatal(err)
	}
	if entry.CodeVersion.Load() == beforeVersion {
		t.Fatal("closure executable write did not update code generation")
	}

	callbacks := 0
	mem.WatchAddr = addr
	mem.WatchSize = 8
	mem.WatchCB = func(gotAddr, value uint64, size int) {
		if gotAddr == addr && value == regs[0] && size == 8 {
			callbacks++
		}
	}
	*state.RIP = 0x3000
	*instret = 0
	state.Fallback = false
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if callbacks != 1 || state.Fallback || *instret != uint64(block.ninsn) {
		t.Fatalf("callbacks=%d fallback=%v instret=%d", callbacks, state.Fallback, *instret)
	}
}

func TestNativePE64MemoryCodeSize(t *testing.T) {
	mem := mmu.New()
	const codeAddr = uint64(0x3000)
	if err := mem.MapPage(codeAddr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteBytes(codeAddr, []byte{0x48, 0x8B, 0x03, 0xEB, 0xFE}); err != nil {
		t.Fatal(err)
	}
	cache := NewCacheMode(mem, false)
	if !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	before := cache.exec.used
	block := cache.Compile(codeAddr)
	if block == nil || block.native == 0 {
		t.Fatal("native backend rejected PE64 MOV")
	}
	codeSize := cache.exec.used - before
	if codeSize > 512 {
		t.Fatalf("single sparse PE64 MOV emitted %d bytes", codeSize)
	}
	t.Logf("single sparse PE64 MOV code size: %d bytes", codeSize)
}

func BenchmarkNativePE64MemoryBlock(b *testing.B) {
	for _, native := range []bool{false, true} {
		name := "Closure"
		if native {
			name = "Native"
		}
		b.Run(name, func(b *testing.B) {
			mem := mmu.New()
			const (
				codeAddr = uint64(0x3000)
				dataAddr = uint64(0x123456789000)
			)
			mem.MapPage(codeAddr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			mem.MapPage(dataAddr, mmu.PermRead|mmu.PermWrite)
			code := []byte{
				0x48, 0x8B, 0x03,
				0x48, 0x03, 0x43, 0x08,
				0x48, 0x89, 0x43, 0x10,
				0x4C, 0x0F, 0xB6, 0x53, 0x18,
				0x48, 0x0F, 0xBF, 0x4B, 0x1A,
				0xEB, 0xFE,
			}
			if err := mem.WriteBytes(codeAddr, code); err != nil {
				b.Fatal(err)
			}
			data := []byte{
				0x78, 0x56, 0x34, 0x12, 0x10, 0x32, 0x54, 0x76,
				0x11, 0x22, 0x33, 0x44, 0xFE, 0x00, 0x01, 0x80,
				0, 0, 0, 0, 0, 0, 0, 0,
				0xA5, 0, 0x01, 0x80,
			}
			if err := mem.WriteBytesRaw(dataAddr, data); err != nil {
				b.Fatal(err)
			}
			cache := NewCacheMode(mem, false)
			if native && !cache.EnableNativeCodegen() {
				b.Skip("native codegen unavailable")
			}
			block := cache.Compile(codeAddr)
			if block == nil || native && block.native == 0 {
				b.Fatal("PE64 memory benchmark did not compile")
			}
			regs := [16]uint64{3: dataAddr}
			flags, rip := uint64(0x202), codeAddr
			state := &State{Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rip = codeAddr
				if err := block.Run(state); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
