//go:build guest_windows

package ntapi

import (
	"fmt"
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestAMD64ContextUsesLiteralWindowsOffsets(t *testing.T) {
	mem := mmu.New()
	contextAddress := mem.Mmap(0, 1232, mmu.PermRead|mmu.PermWrite)
	mem.Write32(contextAddress+0x30, 0x10000b)
	mem.Write32(contextAddress+0x34, 0xa1b2c3d4)
	mem.Write32(contextAddress+0x44, 0x246)
	mem.Write64(contextAddress+0x48, 0x1020304050607080)
	mem.Write64(contextAddress+0x78, 0x1111222233334444)
	mem.Write64(contextAddress+0x98, 0x5555666677778888)
	mem.Write64(contextAddress+0xf8, 0x9999aaaabbbbcccc)
	mem.Write64(contextAddress+0x200, 0x610)
	mem.Write64(contextAddress+0x208, 0x618)
	mem.Write64(contextAddress+0x290, 0xf10)
	mem.Write64(contextAddress+0x298, 0xf18)

	context, err := ReadAMD64Context(mem, contextAddress)
	if err != nil {
		t.Fatal(err)
	}
	if context.Rflags != 0x246 ||
		context.Regs[regRAX] != 0x1111222233334444 ||
		context.Regs[regRSP] != 0x5555666677778888 ||
		context.Rip != 0x9999aaaabbbbcccc {
		t.Fatalf("decoded integer context = %#v", context)
	}
	if context.XMM[6] != [2]uint64{0x610, 0x618} ||
		context.XMM[15] != [2]uint64{0xf10, 0xf18} {
		t.Fatalf("decoded XMM6=%#v XMM15=%#v", context.XMM[6], context.XMM[15])
	}

	outputAddress := mem.Mmap(0, 1232, mmu.PermRead|mmu.PermWrite)
	mem.Write32(outputAddress+0x34, 0xa1b2c3d4)
	mem.Write64(outputAddress+0x48, 0x1020304050607080)
	if err := WriteAMD64Context(mem, outputAddress, context); err != nil {
		t.Fatal(err)
	}
	if flags, _ := mem.Read32(outputAddress + 0x30); flags != 0x10000b {
		t.Fatalf("ContextFlags = %#x", flags)
	}
	if eflags, _ := mem.Read32(outputAddress + 0x44); eflags != 0x246 {
		t.Fatalf("EFlags = %#x", eflags)
	}
	if adjacent, _ := mem.Read32(outputAddress + 0x34); adjacent != 0xa1b2c3d4 {
		t.Fatalf("DWORD after ContextFlags = %#x", adjacent)
	}
	if adjacent, _ := mem.Read64(outputAddress + 0x48); adjacent != 0x1020304050607080 {
		t.Fatalf("QWORD after EFlags = %#x", adjacent)
	}
	for offset, want := range map[uint64]uint64{
		0x78:  0x1111222233334444,
		0x98:  0x5555666677778888,
		0xf8:  0x9999aaaabbbbcccc,
		0x200: 0x610,
		0x208: 0x618,
		0x290: 0xf10,
		0x298: 0xf18,
	} {
		if got, _ := mem.Read64(outputAddress + offset); got != want {
			t.Fatalf("CONTEXT +%#x = %#x, want %#x", offset, got, want)
		}
	}
}

func TestLookupFunctionEntryAllowsReentrantTableMutation(t *testing.T) {
	mem := mmu.New()
	const (
		identifier = uint64(0x300000)
		imageBase  = uint64(0x140000000)
		imageSize  = uint64(0x10000)
		callback   = uint64(0x140008000)
		context    = uint64(0x12345678)
	)
	entryAddress := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	mem.Write32(entryAddress, 0x1000)
	mem.Write32(entryAddress+4, 0x1100)
	mem.Write32(entryAddress+8, 0x3000)

	sehFunctionTableMu.Lock()
	oldStatic := staticFunctionTables
	oldDynamic := dynamicFunctionTables
	staticFunctionTables = nil
	dynamicFunctionTables = nil
	sehFunctionTableMu.Unlock()
	t.Cleanup(func() {
		sehFunctionTableMu.Lock()
		staticFunctionTables = oldStatic
		dynamicFunctionTables = oldDynamic
		sehFunctionTableMu.Unlock()
	})

	if !InstallDynamicFunctionTableCallback(identifier, imageBase, imageSize, callback, context) {
		t.Fatal("failed to install callback function table")
	}
	if !AddDynamicFunctionTable(mem, entryAddress, 1, imageBase) {
		t.Fatal("failed to install dynamic function table")
	}

	mutationDone := make(chan bool, 1)
	mutationBlocked := false
	guestCall := func(address uint64, args []uint64) (uint64, error) {
		if address != callback {
			return 0, fmt.Errorf("callback address = %#x", address)
		}
		if len(args) != 2 || args[0] != imageBase+0x1050 || args[1] != context {
			return 0, fmt.Errorf("callback arguments = %#v", args)
		}
		go func() {
			sehFunctionTableMu.Lock()
			mutated := false
			for index := range dynamicFunctionTables {
				if dynamicFunctionTables[index].tableAddr == entryAddress {
					table := &dynamicFunctionTables[index]
					table.baseAddr = 0x150000000
					table.endAddr = 0x150001000
					table.entries[0] = RuntimeFunction{
						BeginAddress: 0x200,
						EndAddress:   0x300,
						UnwindData:   0x400,
						EntryAddr:    entryAddress,
					}
					mutated = true
					break
				}
			}
			sehFunctionTableMu.Unlock()
			mutationDone <- mutated
		}()
		select {
		case mutated := <-mutationDone:
			if !mutated {
				return 0, fmt.Errorf("dynamic table was not replaced")
			}
			return 0, nil
		case <-time.After(time.Second):
			mutationBlocked = true
			return 0, fmt.Errorf("dynamic table mutation blocked by lookup read lock")
		}
	}

	entry, base, address := LookupFunctionEntry(
		mem,
		imageBase+0x1050,
		guestCall,
	)
	if mutationBlocked {
		<-mutationDone
		t.Fatal("dynamic table mutation blocked by lookup read lock")
	}
	if entry == nil || base != imageBase || address != entryAddress {
		t.Fatalf("lookup result entry=%#v base=%#x address=%#x", entry, base, address)
	}
	if entry.BeginAddress != 0x1000 || entry.EndAddress != 0x1100 ||
		entry.UnwindData != 0x3000 {
		t.Fatalf("runtime function = %#v", entry)
	}
}
