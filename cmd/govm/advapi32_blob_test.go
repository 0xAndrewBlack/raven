//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func TestCryptDataBlobGuestLayouts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		is32       bool
		structSize uint64
	}{
		{name: "PE32", is32: true, structSize: 8},
		{name: "PE64", is32: false, structSize: 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem := mmu.New()
			mem.Mode32 = tc.is32
			const (
				addr     = uint64(0x4000)
				data     = uint64(0x12345678)
				sentinel = uint32(0xa5a5a5a5)
			)
			mem.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			if err := mem.Write32(addr+tc.structSize, sentinel); err != nil {
				t.Fatal(err)
			}
			ctx := &ntapi.TrapContext{Mem: mem, State: &ntapi.ProcessState{Is32: tc.is32}}
			if !writeCryptDataBlob(ctx, addr, 37, data) {
				t.Fatal("writeCryptDataBlob returned false")
			}
			length, pointer, ok := readCryptDataBlob(ctx, addr)
			if !ok || length != 37 || pointer != data {
				t.Fatalf("blob = length %d, pointer %#x, ok %v", length, pointer, ok)
			}
			gotSentinel, err := mem.Read32(addr + tc.structSize)
			if err != nil || gotSentinel != sentinel {
				t.Fatalf("adjacent memory = %#x, err = %v", gotSentinel, err)
			}
		})
	}
}

func TestCopyCryptDataBlob(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		mem := mmu.New()
		mem.Mode32 = is32
		const input = uint64(0x4000)
		const output = uint64(0x5000)
		mem.MapRange(input, mmu.PageSize*2, mmu.PermRead|mmu.PermWrite)
		data := mem.Mmap(0, 4, mmu.PermRead|mmu.PermWrite)
		if err := mem.WriteBytes(data, []byte("test")); err != nil {
			t.Fatal(err)
		}
		ctx := &ntapi.TrapContext{Mem: mem, State: &ntapi.ProcessState{Is32: is32}}
		if !writeCryptDataBlob(ctx, input, 4, data) || !copyCryptDataBlob(ctx, input, output, nil) {
			t.Fatal("DATA_BLOB copy failed")
		}
		length, copiedPtr, ok := readCryptDataBlob(ctx, output)
		copied, err := mem.ReadBytes(copiedPtr, int(length))
		if !ok || err != nil || string(copied) != "test" || copiedPtr == data {
			t.Fatalf("copied blob = %q, pointer %#x, ok %v, err %v", copied, copiedPtr, ok, err)
		}
	}
}

func TestCryptDataBlobRejectsUnmappedMemory(t *testing.T) {
	ctx := &ntapi.TrapContext{Mem: mmu.New(), State: &ntapi.ProcessState{Is32: true}}
	if _, _, ok := readCryptDataBlob(ctx, 0x4000); ok {
		t.Fatal("readCryptDataBlob accepted unmapped memory")
	}
	if writeCryptDataBlob(ctx, 0x4000, 1, 2) {
		t.Fatal("writeCryptDataBlob accepted unmapped memory")
	}
}

func TestCopyCryptDataBlobRejectsMalformedAndOversizedInput(t *testing.T) {
	for _, test := range []struct {
		length  uint32
		pointer uint64
	}{
		{length: 1},
		{length: 64<<20 + 1, pointer: 0x6000},
	} {
		mem := mmu.New()
		mem.Mode32 = true
		const input = uint64(0x4000)
		const output = uint64(0x5000)
		mem.MapRange(input, mmu.PageSize*2, mmu.PermRead|mmu.PermWrite)
		ctx := &ntapi.TrapContext{Mem: mem, State: &ntapi.ProcessState{Is32: true}}
		if !writeCryptDataBlob(ctx, input, test.length, test.pointer) {
			t.Fatal("failed to prepare malformed input")
		}
		if copyCryptDataBlob(ctx, input, output, nil) {
			t.Fatalf("accepted malformed blob length %d", test.length)
		}
	}
}

func TestWriteCryptDataBlobRejectsPartialStructure(t *testing.T) {
	mem := mmu.New()
	mem.Mode32 = true
	const page = uint64(0x4000)
	addr := page + mmu.PageSize - 4
	mem.MapRange(page, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if err := mem.Write32(addr, 0xa5a5a5a5); err != nil {
		t.Fatal(err)
	}
	ctx := &ntapi.TrapContext{Mem: mem, State: &ntapi.ProcessState{Is32: true}}
	if writeCryptDataBlob(ctx, addr, 1, 2) {
		t.Fatal("accepted a partially mapped DATA_BLOB")
	}
	got, err := mem.Read32(addr)
	if err != nil || got != 0xa5a5a5a5 {
		t.Fatalf("length changed to %#x, err = %v", got, err)
	}
}

func TestCopyCryptDataBlobTracksLocalAllocation(t *testing.T) {
	mem := mmu.New()
	mem.Mode32 = true
	const input = uint64(0x4000)
	const output = uint64(0x5000)
	mem.MapRange(input, mmu.PageSize*2, mmu.PermRead|mmu.PermWrite)
	data := mem.Mmap(0, 4, mmu.PermRead|mmu.PermWrite)
	if err := mem.WriteBytes(data, []byte("test")); err != nil {
		t.Fatal(err)
	}
	ctx := &ntapi.TrapContext{Mem: mem, State: &ntapi.ProcessState{Is32: true}}
	hctx := &HandlerCtx{}
	if !writeCryptDataBlob(ctx, input, 4, data) || !copyCryptDataBlob(ctx, input, output, hctx) {
		t.Fatal("DATA_BLOB copy failed")
	}
	_, copiedPtr, ok := readCryptDataBlob(ctx, output)
	if !ok {
		t.Fatal("failed to read copied DATA_BLOB")
	}
	if size, tracked := hctx.localAllocSize(copiedPtr); !tracked || size != 4 {
		t.Fatalf("tracked allocation = %d, %v", size, tracked)
	}
	if size, tracked := hctx.takeLocalAlloc(copiedPtr); !tracked || size != 4 {
		t.Fatalf("released allocation = %d, %v", size, tracked)
	}
	if _, tracked := hctx.localAllocSize(copiedPtr); tracked {
		t.Fatal("released allocation remains tracked")
	}
}
