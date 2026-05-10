package x64

import (
	"math"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestSnapshotRoundTripAMD64(t *testing.T) {
	testSnapshotRoundTrip(t, false)
}

func TestSnapshotRoundTripI386(t *testing.T) {
	testSnapshotRoundTrip(t, true)
}

func TestSnapshotMutationIsolation(t *testing.T) {
	cpu := New(mmu.New())
	want := initializeSnapshotState(cpu, false)
	snapshot := cpu.Snapshot()

	cpu.Regs[0] = 0
	cpu.XMM[0][0] = 0
	cpu.YMM_hi[15][1] = 0
	cpu.fpuST[7] = 0
	if snapshot != want {
		t.Fatal("CPU mutation changed the snapshot")
	}

	copy := snapshot
	copy.regs[1] = 0
	copy.xmm[1][1] = 0
	copy.ymmHi[14][0] = 0
	copy.fpuST[6] = 0
	if snapshot != want {
		t.Fatal("snapshot copy mutation changed the original")
	}
}

func TestSnapshotPreservesMMXBits(t *testing.T) {
	cpu := New(mmu.New())
	want := [8]uint64{
		0,
		1,
		0x7FF8000000001234,
		0xFFF0000000000000,
		0x8000000000000000,
		0x0123456789ABCDEF,
		0xFEDCBA9876543210,
		0xFFFFFFFFFFFFFFFF,
	}
	for i, bits := range want {
		cpu.fpuST[i] = math.Float64frombits(bits)
	}

	snapshot := cpu.Snapshot()
	cpu.fpuST = [8]float64{}
	cpu.Restore(snapshot)

	for i, wantBits := range want {
		if got := math.Float64bits(cpu.fpuST[i]); got != wantBits {
			t.Fatalf("MMX register %d = 0x%x, want 0x%x", i, got, wantBits)
		}
	}
}

func TestRestorePreservesExecutorState(t *testing.T) {
	mem := mmu.New()
	cpu := New(mem)
	snapshot := initializeSnapshotState(cpu, false)

	cpu.instret = 1234
	cpu.running = true
	cpu.fetchPage = []byte{1, 2, 3}
	cpu.fetchPageBase = 0x5000
	cpu.fetchPageGen = 99
	cpu.unimplWarned = map[uint64]bool{0x1234: true}
	cpu.PreStep = func(*CPU) bool { return true }

	cpu.Restore(snapshot)

	if cpu.instret != 1234 || !cpu.running {
		t.Fatalf("executor counters changed: instret=%d running=%v", cpu.instret, cpu.running)
	}
	if cpu.fetchPage != nil {
		t.Fatal("restore retained a stale fetch page")
	}
	if cpu.fetchPageBase != 0x5000 || cpu.fetchPageGen != 99 {
		t.Fatal("restore rewound fetch cache metadata")
	}
	if !cpu.unimplWarned[0x1234] || cpu.PreStep == nil || cpu.mem != mem {
		t.Fatal("restore changed shared executor state")
	}
}

func testSnapshotRoundTrip(t *testing.T, mode32 bool) {
	t.Helper()
	cpu := New(mmu.New())
	want := initializeSnapshotState(cpu, mode32)
	snapshot := cpu.Snapshot()

	clearSnapshotState(cpu)
	cpu.fetchPage = []byte{1}
	cpu.Restore(snapshot)

	if got := cpu.Snapshot(); got != want {
		t.Fatalf("restored state differs:\n got: %#v\nwant: %#v", got, want)
	}
	if cpu.fetchPage != nil {
		t.Fatal("restore did not invalidate the fetch cache")
	}
}

func initializeSnapshotState(cpu *CPU, mode32 bool) Snapshot {
	for i := range cpu.Regs {
		cpu.Regs[i] = 0x1000000000000000 + uint64(i)
	}
	cpu.RIP = 0x140001234
	cpu.Rflags = 0x8D5
	cpu.fsBase = 0x7FFDE000
	cpu.gsBase = 0xFFFFF78000000000
	cpu.Mode32 = mode32
	cpu.ExpectedReturnPC = 0x7FFFFFF0
	cpu.ExpectedReturnSP = 0x7FFF0000
	for i := range cpu.XMM {
		cpu.XMM[i] = [2]uint64{0x2000 + uint64(i), 0x3000 + uint64(i)}
		cpu.YMM_hi[i] = [2]uint64{0x4000 + uint64(i), 0x5000 + uint64(i)}
	}
	for i := range cpu.fpuST {
		cpu.fpuST[i] = float64(i) + 0.25
	}
	cpu.fpuTop = 5
	cpu.fpuCW = 0x027F
	cpu.fpuSW = 0x4521
	cpu.fpuTW = 0xA55A
	cpu.MXCSR = 0x7F80
	return cpu.Snapshot()
}

func clearSnapshotState(cpu *CPU) {
	cpu.Regs = [16]uint64{}
	cpu.RIP = 0
	cpu.Rflags = 0
	cpu.fsBase = 0
	cpu.gsBase = 0
	cpu.Mode32 = !cpu.Mode32
	cpu.ExpectedReturnPC = 0
	cpu.ExpectedReturnSP = 0
	cpu.XMM = [16][2]uint64{}
	cpu.YMM_hi = [16][2]uint64{}
	cpu.fpuST = [8]float64{}
	cpu.fpuTop = 0
	cpu.fpuCW = 0
	cpu.fpuSW = 0
	cpu.fpuTW = 0
	cpu.MXCSR = 0
}
