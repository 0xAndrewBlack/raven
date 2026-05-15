//go:build linux && amd64

package x64

import (
	"math"
	"math/rand"
	"testing"
)

func TestX87ReferenceHostAddOracle(t *testing.T) {
	got, status := hostX87Add(1.25, 2.5)
	if got != 3.75 {
		t.Fatalf("host result=%v", got)
	}
	if status&0x4500 != 0 {
		t.Fatalf("host status condition bits=%#x", status)
	}
	got, status = hostX87Add(math.Inf(1), math.Inf(-1))
	if !math.IsNaN(got) || status&1 == 0 {
		t.Fatalf("host invalid result=%v status=%#x", got, status)
	}
}

func TestX87ReferenceHostDifferentialAdd(t *testing.T) {
	rng := rand.New(rand.NewSource(0xA77))
	for i := 0; i < 50; i++ {
		a := rng.Float64()*2000 - 1000
		b := rng.Float64()*2000 - 1000
		host, status := hostX87Add(a, b)
		if status&0x3F&^fpuExcPrecision != 0 {
			t.Fatalf("case %d host status=%#x", i, status)
		}
		cpu, _ := newX87ReferenceCPU(t, []byte{0xD8, 0xC1}, 0)
		cpu.fpuSetST0(a)
		cpu.fpuSetSTi(1, b)
		if err := cpu.step(); err != nil {
			t.Fatal(err)
		}
		if cpu.fpuST0() != host || host != a+b {
			t.Fatalf("case %d host=%v interpreter=%v expected=%v", i, host, cpu.fpuST0(), a+b)
		}
	}
}
