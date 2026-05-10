//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestWriteRtlGetNtVersionNumbers(t *testing.T) {
	mem := mmu.New()
	base := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
	config := compatConfig{
		ntVersion:   [2]uint32{10, 2},
		buildNumber: 22631,
	}

	writeRtlGetNtVersionNumbers(mem, base, base+4, base+8, config)

	major, err := mem.Read32(base)
	if err != nil {
		t.Fatal(err)
	}
	minor, err := mem.Read32(base + 4)
	if err != nil {
		t.Fatal(err)
	}
	build, err := mem.Read32(base + 8)
	if err != nil {
		t.Fatal(err)
	}
	if major != 10 || minor != 2 || build != 0xF0005867 {
		t.Fatalf("version = %d.%d build %#x", major, minor, build)
	}

	writeRtlGetNtVersionNumbers(mem, 0, base+4, 0, compatConfig{ntVersion: [2]uint32{6, 3}})
	minor, err = mem.Read32(base + 4)
	if err != nil {
		t.Fatal(err)
	}
	if minor != 3 {
		t.Fatalf("minor version with nullable outputs = %d", minor)
	}
}
