package jit

import (
	"math"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

type mmxRunResult struct {
	fpu      [8]uint64
	top      int
	tag      uint16
	rip      uint64
	instret  uint64
	fallback bool
	memory   uint64
	err      string
}

type mmxRunConfig struct {
	code       []byte
	regs       [16]uint64
	fpu        [8]uint64
	top        int
	tag        uint16
	dataAddr   uint64
	dataPerm   uint8
	nextPerm   uint8
	dataInit   bool
	dataValue  uint64
	readMemory bool
}

func runMMXBlock(t *testing.T, cfg mmxRunConfig, native bool) mmxRunResult {
	t.Helper()

	mem := mmu.New()
	if err := mem.EnableFlatBacking(); err != nil {
		t.Skipf("flat backing unavailable: %v", err)
	}
	mem.Mode32 = true
	mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	for i, opcode := range cfg.code {
		if err := mem.Write8(0x1000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}
	if cfg.dataPerm != 0 {
		mem.MapPage(cfg.dataAddr, cfg.dataPerm)
		if cfg.nextPerm != 0 {
			mem.MapPage(cfg.dataAddr+mmu.PageSize, cfg.nextPerm)
		}
	}
	if cfg.dataInit {
		if err := mem.Write64Raw(cfg.dataAddr, cfg.dataValue); err != nil {
			t.Fatal(err)
		}
	}

	cache := NewCacheMode(mem, true)
	if native && !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(0x1000)
	if block == nil {
		t.Fatal("MMX block did not compile")
	}
	if native && block.native == 0 {
		t.Fatal("native backend rejected MMX block")
	}

	var st [8]float64
	for i, bits := range cfg.fpu {
		st[i] = math.Float64frombits(bits)
	}
	regs := cfg.regs
	rip := uint64(0x1000)
	rflags := uint64(0x202)
	top := cfg.top
	tag := cfg.tag
	instret := uint64(0)
	state := &State{
		Regs:    &regs,
		RIP:     &rip,
		Rflags:  &rflags,
		Mem:     mem,
		Mode32:  true,
		FPUST:   &st,
		FPUTop:  &top,
		FPUTW:   &tag,
		Instret: &instret,
	}
	err := block.Run(state)
	usedFallback := state.Fallback
	if native && state.Fallback {
		state.Fallback = false
		fallback := NewCacheMode(mem, true).Compile(rip)
		if fallback == nil {
			t.Fatalf("closure fallback did not compile at %#x", rip)
		}
		err = fallback.Run(state)
	}

	result := mmxRunResult{
		top:      top,
		tag:      tag,
		rip:      rip,
		instret:  instret,
		fallback: usedFallback,
	}
	for i, value := range st {
		result.fpu[i] = math.Float64bits(value)
	}
	if cfg.readMemory {
		value, readErr := mem.Read64(cfg.dataAddr)
		if readErr != nil {
			t.Fatal(readErr)
		}
		result.memory = value
	}
	if err != nil {
		result.err = err.Error()
	}
	return result
}

func compareMMXRuns(t *testing.T, cfg mmxRunConfig) (mmxRunResult, mmxRunResult) {
	t.Helper()
	closure := runMMXBlock(t, cfg, false)
	native := runMMXBlock(t, cfg, true)
	comparable := native
	comparable.fallback = false
	if comparable != closure {
		t.Fatalf("native result = %+v, closure result = %+v", native, closure)
	}
	return closure, native
}

func TestNativeMMXRegisterMovesAndEMMSMatchClosure(t *testing.T) {
	cfg := mmxRunConfig{
		code: []byte{
			0x0F, 0x6F, 0xC1, // movq mm0, mm1
			0x0F, 0x7F, 0xC2, // movq mm2, mm0
			0x0F, 0x77, // emms
			0xEB, 0xFE,
		},
		fpu: [8]uint64{
			0x0011223344556677,
			0x8899AABBCCDDEEFF,
			0x1020304050607080,
		},
		top: 5,
		tag: 0x1234,
	}
	closure, _ := compareMMXRuns(t, cfg)
	if closure.fpu[0] != cfg.fpu[1] || closure.fpu[2] != cfg.fpu[1] {
		t.Fatalf("MMX registers = %#x %#x", closure.fpu[0], closure.fpu[2])
	}
	if closure.top != 0 || closure.tag != 0xffff {
		t.Fatalf("top=%d tag=%#x", closure.top, closure.tag)
	}
	if closure.instret != 4 {
		t.Fatalf("instret=%d, want 4", closure.instret)
	}
}

func TestNativeMMXGameHotOpcodesMatchClosure(t *testing.T) {
	tests := []struct {
		name string
		cfg  mmxRunConfig
	}{
		{
			name: "movd",
			cfg: mmxRunConfig{
				code: []byte{0x0F, 0x6E, 0xC0, 0xEB, 0xFE},
				regs: [16]uint64{0: 0xFEDCBA9876543210},
				fpu:  [8]uint64{0xAAAAAAAAAAAAAAAA},
				top:  5,
				tag:  0xffff,
			},
		},
		{
			name: "punpcklwd",
			cfg: mmxRunConfig{
				code: []byte{0x0F, 0x61, 0xC1, 0xEB, 0xFE},
				fpu: [8]uint64{
					0x1111222233334444,
					0xAAAABBBBCCCCDDDD,
				},
				top: 3,
				tag: 0xffff,
			},
		},
		{
			name: "packssdw",
			cfg: mmxRunConfig{
				code: []byte{0x0F, 0x6B, 0xC1, 0xEB, 0xFE},
				fpu: [8]uint64{
					0x00008000FFFF7FFF,
					0x7FFFFFFF80000000,
				},
				top: 2,
				tag: 0xffff,
			},
		},
		{
			name: "psllw",
			cfg: mmxRunConfig{
				code: []byte{0x0F, 0x71, 0xF2, 0x04, 0xEB, 0xFE},
				fpu:  [8]uint64{2: 0x80017FFF1234FFFF},
				top:  7,
				tag:  0xffff,
			},
		},
		{
			name: "pmulhw",
			cfg: mmxRunConfig{
				code: []byte{0x0F, 0xE5, 0xC1, 0xEB, 0xFE},
				fpu: [8]uint64{
					0x7FFF8000FFFF1234,
					0x80007FFF0002FEDC,
				},
				top: 1,
				tag: 0xffff,
			},
		},
		{
			name: "paddw",
			cfg: mmxRunConfig{
				code: []byte{0x0F, 0xFD, 0xC1, 0xEB, 0xFE},
				fpu: [8]uint64{
					0xFFFF00017FFF8000,
					0x0002FFFF00018000,
				},
				top: 4,
				tag: 0xffff,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			closure, native := compareMMXRuns(t, test.cfg)
			if native.fallback {
				t.Fatal("hot MMX opcode requested fallback")
			}
			if closure.instret != 2 {
				t.Fatalf("instret=%d, want 2", closure.instret)
			}
		})
	}
}

func TestNativeMMXPackedMemorySourceAndFaultMatchClosure(t *testing.T) {
	valid := mmxRunConfig{
		code:      []byte{0x90, 0x0F, 0xE5, 0x03, 0xEB, 0xFE},
		regs:      [16]uint64{3: 0x2000},
		fpu:       [8]uint64{0x7FFF8000FFFF1234},
		top:       6,
		tag:       0xffff,
		dataAddr:  0x2000,
		dataPerm:  mmu.PermRead | mmu.PermWrite,
		dataInit:  true,
		dataValue: 0x80007FFF0002FEDC,
	}
	closure, native := compareMMXRuns(t, valid)
	if native.fallback {
		t.Fatal("valid packed MMX memory source requested fallback")
	}
	if closure.instret != 3 {
		t.Fatalf("instret=%d, want 3", closure.instret)
	}

	crossPage := valid
	crossPage.regs[3] = 0x20ffc
	crossPage.dataAddr = 0x20ffc
	crossPage.nextPerm = mmu.PermRead | mmu.PermWrite
	closure, native = compareMMXRuns(t, crossPage)
	if native.fallback {
		t.Fatal("cross-page packed MMX source requested fallback")
	}
	if closure.instret != 3 {
		t.Fatalf("cross-page instret=%d, want 3", closure.instret)
	}

	faults := []struct {
		name string
		cfg  mmxRunConfig
	}{
		{
			name: "unmapped",
			cfg: func() mmxRunConfig {
				cfg := valid
				cfg.dataPerm = 0
				cfg.dataInit = false
				return cfg
			}(),
		},
		{
			name: "protected second page",
			cfg: func() mmxRunConfig {
				cfg := crossPage
				cfg.nextPerm = mmu.PermWrite
				return cfg
			}(),
		},
		{
			name: "32-bit wrap",
			cfg: func() mmxRunConfig {
				cfg := valid
				cfg.regs[3] = 0xfffffffc
				cfg.dataAddr = 0xfffffffc
				cfg.dataInit = false
				return cfg
			}(),
		},
	}
	for _, test := range faults {
		t.Run(test.name, func(t *testing.T) {
			test.cfg.fpu[0] = 0x0123456789ABCDEF
			closure := runMMXBlock(t, test.cfg, false)
			native := runMMXBlock(t, test.cfg, true)
			if !native.fallback {
				t.Fatal("packed MMX memory fault did not request closure fallback")
			}
			native.fallback = false
			if native != closure {
				t.Fatalf("native result = %+v, closure result = %+v", native, closure)
			}
			if closure.instret != 1 || closure.fpu[0] != test.cfg.fpu[0] {
				t.Fatalf("fault retired=%d mm0=%#x", closure.instret, closure.fpu[0])
			}
		})
	}
}

func TestNativeMMXLoadUsesWrappedSIBAddress(t *testing.T) {
	cfg := mmxRunConfig{
		code: []byte{
			0x0F, 0x6F, 0x44, 0x8B, 0x30, // movq mm0, [ebx+ecx*4+0x30]
			0xEB, 0xFE,
		},
		regs:      [16]uint64{1: 4, 3: 0xffffffe0},
		fpu:       [8]uint64{0x1111111111111111},
		top:       7,
		tag:       0xffff,
		dataAddr:  0x20,
		dataPerm:  mmu.PermRead | mmu.PermWrite,
		dataInit:  true,
		dataValue: 0xFEDCBA9876543210,
	}
	closure, _ := compareMMXRuns(t, cfg)
	if closure.fpu[0] != cfg.dataValue || closure.top != 0 || closure.tag != 0 {
		t.Fatalf("mm0=%#x top=%d tag=%#x", closure.fpu[0], closure.top, closure.tag)
	}
}

func TestNativeMMXStoreMatchesClosure(t *testing.T) {
	cfg := mmxRunConfig{
		code: []byte{
			0x0F, 0x7F, 0x43, 0x08, // movq [ebx+8], mm0
			0xEB, 0xFE,
		},
		regs:       [16]uint64{3: 0x2000},
		fpu:        [8]uint64{0x0123456789ABCDEF},
		top:        4,
		tag:        0xffff,
		dataAddr:   0x2008,
		dataPerm:   mmu.PermRead | mmu.PermWrite,
		dataInit:   true,
		dataValue:  0xAAAAAAAAAAAAAAAA,
		readMemory: true,
	}
	closure, _ := compareMMXRuns(t, cfg)
	if closure.memory != cfg.fpu[0] || closure.top != 0 || closure.tag != 0 {
		t.Fatalf("memory=%#x top=%d tag=%#x", closure.memory, closure.top, closure.tag)
	}
}

func TestNativeMMXCrossPageAccessMatchesClosure(t *testing.T) {
	tests := []struct {
		name string
		cfg  mmxRunConfig
	}{
		{
			name: "load",
			cfg: mmxRunConfig{
				code:      []byte{0x0F, 0x6F, 0x03, 0xEB, 0xFE},
				regs:      [16]uint64{3: 0x80ffc},
				fpu:       [8]uint64{0x1111222233334444},
				top:       6,
				tag:       0x5555,
				dataAddr:  0x80ffc,
				dataPerm:  mmu.PermRead | mmu.PermWrite,
				nextPerm:  mmu.PermRead | mmu.PermWrite,
				dataInit:  true,
				dataValue: 0x777788889999AAAA,
			},
		},
		{
			name: "store",
			cfg: mmxRunConfig{
				code:       []byte{0x0F, 0x7F, 0x03, 0xEB, 0xFE},
				regs:       [16]uint64{3: 0x90ffc},
				fpu:        [8]uint64{0x1111222233334444},
				top:        6,
				tag:        0x5555,
				dataAddr:   0x90ffc,
				dataPerm:   mmu.PermRead | mmu.PermWrite,
				nextPerm:   mmu.PermRead | mmu.PermWrite,
				dataInit:   true,
				dataValue:  0x777788889999AAAA,
				readMemory: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			closure, native := compareMMXRuns(t, test.cfg)
			if native.fallback {
				t.Fatal("valid cross-page access requested fallback")
			}
			if closure.instret != 2 {
				t.Fatalf("instret=%d, want 2", closure.instret)
			}
		})
	}
}

func TestNativeMMXMemoryFaultsMatchClosure(t *testing.T) {
	tests := []struct {
		name        string
		cfg         mmxRunConfig
		wantError   bool
		wantInstret uint64
	}{
		{
			name: "load unmapped",
			cfg: mmxRunConfig{
				code: []byte{0x90, 0x0F, 0x6F, 0x03, 0xEB, 0xFE},
				regs: [16]uint64{3: 0x50000},
				fpu:  [8]uint64{0x1111222233334444},
				top:  6,
				tag:  0x5555,
			},
			wantError:   true,
			wantInstret: 1,
		},
		{
			name: "load protected",
			cfg: mmxRunConfig{
				code:      []byte{0x90, 0x0F, 0x6F, 0x03, 0xEB, 0xFE},
				regs:      [16]uint64{3: 0x50000},
				fpu:       [8]uint64{0x1111222233334444},
				top:       6,
				tag:       0x5555,
				dataAddr:  0x50000,
				dataPerm:  mmu.PermWrite,
				dataInit:  true,
				dataValue: 0x777788889999AAAA,
			},
			wantError:   true,
			wantInstret: 1,
		},
		{
			name: "store unmapped",
			cfg: mmxRunConfig{
				code: []byte{0x90, 0x0F, 0x7F, 0x03, 0xEB, 0xFE},
				regs: [16]uint64{3: 0x50000},
				fpu:  [8]uint64{0x1111222233334444},
				top:  6,
				tag:  0x5555,
			},
			wantError:   true,
			wantInstret: 1,
		},
		{
			name: "store protected",
			cfg: mmxRunConfig{
				code:       []byte{0x90, 0x0F, 0x7F, 0x03, 0xEB, 0xFE},
				regs:       [16]uint64{3: 0x50000},
				fpu:        [8]uint64{0x1111222233334444},
				top:        6,
				tag:        0x5555,
				dataAddr:   0x50000,
				dataPerm:   mmu.PermRead,
				dataInit:   true,
				dataValue:  0x777788889999AAAA,
				readMemory: true,
			},
			wantError:   true,
			wantInstret: 1,
		},
		{
			name: "load protected second page",
			cfg: mmxRunConfig{
				code:      []byte{0x90, 0x0F, 0x6F, 0x03, 0xEB, 0xFE},
				regs:      [16]uint64{3: 0x50ffc},
				fpu:       [8]uint64{0x1111222233334444},
				top:       6,
				tag:       0x5555,
				dataAddr:  0x50ffc,
				dataPerm:  mmu.PermRead | mmu.PermWrite,
				nextPerm:  mmu.PermWrite,
				dataInit:  true,
				dataValue: 0x777788889999AAAA,
			},
			wantError:   true,
			wantInstret: 1,
		},
		{
			name: "store protected second page",
			cfg: mmxRunConfig{
				code:       []byte{0x90, 0x0F, 0x7F, 0x03, 0xEB, 0xFE},
				regs:       [16]uint64{3: 0x60ffc},
				fpu:        [8]uint64{0x1111222233334444},
				top:        6,
				tag:        0x5555,
				dataAddr:   0x60ffc,
				dataPerm:   mmu.PermRead | mmu.PermWrite,
				nextPerm:   mmu.PermRead,
				dataInit:   true,
				dataValue:  0x777788889999AAAA,
				readMemory: true,
			},
			wantError:   true,
			wantInstret: 1,
		},
		{
			name: "store executable page",
			cfg: mmxRunConfig{
				code:       []byte{0x90, 0x0F, 0x7F, 0x03, 0xEB, 0xFE},
				regs:       [16]uint64{3: 0x70000},
				fpu:        [8]uint64{0x1111222233334444},
				top:        6,
				tag:        0x5555,
				dataAddr:   0x70000,
				dataPerm:   mmu.PermRead | mmu.PermWrite | mmu.PermExecute,
				dataInit:   true,
				dataValue:  0x777788889999AAAA,
				readMemory: true,
			},
			wantInstret: 3,
		},
		{
			name: "load beyond 32-bit address space",
			cfg: mmxRunConfig{
				code:     []byte{0x90, 0x0F, 0x6F, 0x03, 0xEB, 0xFE},
				regs:     [16]uint64{3: 0xfffffffc},
				fpu:      [8]uint64{0x1111222233334444},
				top:      6,
				tag:      0x5555,
				dataAddr: 0xfffffffc,
				dataPerm: mmu.PermRead | mmu.PermWrite,
			},
			wantError:   true,
			wantInstret: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			closure := runMMXBlock(t, test.cfg, false)
			native := runMMXBlock(t, test.cfg, true)
			if !native.fallback {
				t.Fatal("native memory fault did not request closure fallback")
			}
			native.fallback = false
			if native != closure {
				t.Fatalf("native result = %+v, closure result = %+v", native, closure)
			}
			if got := closure.err != ""; got != test.wantError {
				t.Fatalf("has error=%v, want %v: %s", got, test.wantError, closure.err)
			}
			if closure.instret != test.wantInstret {
				t.Fatalf("instret=%d, want %d", closure.instret, test.wantInstret)
			}
			if test.wantError && (closure.top != test.cfg.top || closure.tag != test.cfg.tag) {
				t.Fatalf("fault changed MMX state: top=%d tag=%#x, want top=%d tag=%#x",
					closure.top, closure.tag, test.cfg.top, test.cfg.tag)
			}
		})
	}
}

func TestNativeMMXMemoryWatchUsesClosure(t *testing.T) {
	mem := mmu.New()
	if err := mem.EnableFlatBacking(); err != nil {
		t.Skipf("flat backing unavailable: %v", err)
	}
	mem.Mode32 = true
	mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	mem.MapPage(0x2000, mmu.PermRead|mmu.PermWrite)
	for i, opcode := range []byte{0x0F, 0x7F, 0x03, 0xEB, 0xFE} {
		if err := mem.Write8(0x1000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}
	cache := NewCacheMode(mem, true)
	if !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(0x1000)
	if block == nil || block.native == 0 || !block.nativeMem {
		t.Fatal("native backend rejected MMX memory block")
	}

	watches := 0
	mem.WatchAddr = 0x2000
	mem.WatchSize = 8
	mem.WatchCB = func(addr, value uint64, size int) {
		watches++
		if addr != 0x2000 || value != 0x0123456789ABCDEF || size != 8 {
			t.Fatalf("watch addr=%#x value=%#x size=%d", addr, value, size)
		}
	}
	regs := [16]uint64{3: 0x2000}
	st := [8]float64{math.Float64frombits(0x0123456789ABCDEF)}
	rip := uint64(0x1000)
	rflags := uint64(0x202)
	top := 6
	tag := uint16(0xffff)
	state := &State{
		Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: mem, Mode32: true,
		FPUST: &st, FPUTop: &top, FPUTW: &tag,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if watches != 1 {
		t.Fatalf("watch callbacks=%d, want 1", watches)
	}
	if value, err := mem.Read64(0x2000); err != nil || value != 0x0123456789ABCDEF {
		t.Fatalf("memory=%#x error=%v", value, err)
	}
}

func TestNativeMMXMissingStateUsesClosureSemantics(t *testing.T) {
	mem := mmu.New()
	mem.Mode32 = true
	mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	code := []byte{
		0xB8, 0x2A, 0x00, 0x00, 0x00,
		0x0F, 0x6F, 0xC1,
		0xEB, 0xFE,
	}
	for i, opcode := range code {
		if err := mem.Write8(0x1000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}
	cache := NewCacheMode(mem, true)
	if !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(0x1000)
	if block == nil || block.native == 0 || !block.nativeMMX {
		t.Fatal("native backend rejected MMX block")
	}
	regs := [16]uint64{}
	rip := uint64(0x1000)
	rflags := uint64(0x202)
	state := &State{Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: mem, Mode32: true}
	err := block.Run(state)
	if err == nil || err.Error() != "MMX state is unavailable" {
		t.Fatalf("error=%v", err)
	}
	if regs[0] != 42 || rip != 0x1005 {
		t.Fatalf("eax=%d rip=%#x", regs[0], rip)
	}
}

func BenchmarkBlockRunPE32MMX(b *testing.B) {
	for _, native := range []bool{false, true} {
		name := "Closure"
		if native {
			name = "Native"
		}
		b.Run(name, func(b *testing.B) {
			mem := mmu.New()
			mem.Mode32 = true
			mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			code := make([]byte, 0, 32*3+4)
			for range 16 {
				code = append(code,
					0x0F, 0x6F, 0xC1,
					0x0F, 0x7F, 0xC2,
				)
			}
			code = append(code, 0x0F, 0x77, 0xEB, 0xFE)
			for i, opcode := range code {
				if err := mem.Write8(0x1000+uint64(i), opcode); err != nil {
					b.Fatal(err)
				}
			}
			cache := NewCacheMode(mem, true)
			if native && !cache.EnableNativeCodegen() {
				b.Skip("native codegen unavailable")
			}
			block := cache.Compile(0x1000)
			if block == nil || native && block.native == 0 {
				b.Fatal("MMX benchmark block was not accepted")
			}
			regs := [16]uint64{}
			st := [8]float64{1: math.Float64frombits(0x0123456789ABCDEF)}
			rip := uint64(0x1000)
			rflags := uint64(0x202)
			top := 0
			tag := uint16(0xffff)
			state := &State{
				Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: mem, Mode32: true,
				FPUST: &st, FPUTop: &top, FPUTW: &tag,
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := block.Run(state); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkBlockRunPE32GameMMX(b *testing.B) {
	for _, native := range []bool{false, true} {
		name := "Closure"
		if native {
			name = "Native"
		}
		b.Run(name, func(b *testing.B) {
			mem := mmu.New()
			mem.Mode32 = true
			mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			code := make([]byte, 0, 16*21+4)
			for range 16 {
				code = append(code,
					0x0F, 0x6E, 0xC0,
					0x0F, 0x61, 0xC0,
					0x0F, 0x6B, 0xC1,
					0x0F, 0x71, 0xF0, 0x02,
					0x0F, 0xE5, 0xC1,
					0x0F, 0xFD, 0xC1,
				)
			}
			code = append(code, 0x0F, 0x77, 0xEB, 0xFE)
			for i, opcode := range code {
				if err := mem.Write8(0x1000+uint64(i), opcode); err != nil {
					b.Fatal(err)
				}
			}
			cache := NewCacheMode(mem, true)
			if native && !cache.EnableNativeCodegen() {
				b.Skip("native codegen unavailable")
			}
			block := cache.Compile(0x1000)
			if block == nil || native && block.native == 0 {
				b.Fatal("game MMX benchmark block was not accepted")
			}
			regs := [16]uint64{0: 0x89ABCDEF}
			st := [8]float64{
				math.Float64frombits(0x1111222233334444),
				math.Float64frombits(0xAAAABBBBCCCCDDDD),
			}
			rip := uint64(0x1000)
			rflags := uint64(0x202)
			top := 0
			tag := uint16(0xffff)
			state := &State{
				Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: mem, Mode32: true,
				FPUST: &st, FPUTop: &top, FPUTW: &tag,
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := block.Run(state); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
