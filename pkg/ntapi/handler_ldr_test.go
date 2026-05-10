//go:build guest_windows

package ntapi

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

type ldrTestCPU struct {
	mem     *mmu.MMU
	arch    arch.Arch
	regs    [16]uint64
	pc      uint64
	sp      uint64
	tls     uint64
	result  uint64
	handler arch.SyscallHandler
}

func (c *ldrTestCPU) Run() error                              { return nil }
func (c *ldrTestCPU) Stop()                                   {}
func (c *ldrTestCPU) Resume()                                 {}
func (c *ldrTestCPU) GetPC() uint64                           { return c.pc }
func (c *ldrTestCPU) SetPC(value uint64)                      { c.pc = value }
func (c *ldrTestCPU) GetSP() uint64                           { return c.sp }
func (c *ldrTestCPU) SetSP(value uint64)                      { c.sp = value }
func (c *ldrTestCPU) GetTLS() uint64                          { return c.tls }
func (c *ldrTestCPU) SetTLS(value uint64)                     { c.tls = value }
func (c *ldrTestCPU) SyscallNum() uint64                      { return c.regs[regRAX] }
func (c *ldrTestCPU) SyscallArgs() [6]uint64                  { return [6]uint64{} }
func (c *ldrTestCPU) SetSyscallReturn(value uint64)           { c.result = value }
func (c *ldrTestCPU) SyscallReturnPC() uint64                 { return c.pc }
func (c *ldrTestCPU) GetMem() *mmu.MMU                        { return c.mem }
func (c *ldrTestCPU) GetInstret() uint64                      { return 0 }
func (c *ldrTestCPU) GetArch() arch.Arch                      { return c.arch }
func (c *ldrTestCPU) CloneForThread() arch.CPU                { return c }
func (c *ldrTestCPU) SetSyscallHandler(h arch.SyscallHandler) { c.handler = h }
func (c *ldrTestCPU) ReadReg(index int) uint64                { return c.regs[index] }
func (c *ldrTestCPU) WriteReg(index int, value uint64)        { c.regs[index] = value }

func TestLdrGuestAnsiStringAndPointerLayouts(t *testing.T) {
	for _, mode32 := range []bool{false, true} {
		name := "pe64"
		if mode32 {
			name = "pe32"
		}
		t.Run(name, func(t *testing.T) {
			mem := mmu.New()
			mem.Mode32 = mode32
			base := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
			ansiString := base
			buffer := base + 0x100
			output := base + 0x200
			const exportName = "RtlGetNtVersionNumbers"

			if err := mem.WriteBytes(buffer, []byte(exportName)); err != nil {
				t.Fatal(err)
			}
			if err := mem.Write16(ansiString, uint16(len(exportName))); err != nil {
				t.Fatal(err)
			}
			if mode32 {
				if err := mem.Write32(ansiString+4, uint32(buffer)); err != nil {
					t.Fatal(err)
				}
				if err := mem.Write32(output+4, 0xdeadbeef); err != nil {
					t.Fatal(err)
				}
			} else if err := mem.Write64(ansiString+8, buffer); err != nil {
				t.Fatal(err)
			}

			if got := readGuestAnsiString(mem, ansiString); got != exportName {
				t.Fatalf("ANSI_STRING = %q", got)
			}

			const address = uint64(0x12345678)
			writeGuestPointer(mem, output, address)
			if mode32 {
				got, err := mem.Read32(output)
				if err != nil || got != uint32(address) {
					t.Fatalf("PE32 pointer = 0x%x, %v", got, err)
				}
				guard, err := mem.Read32(output + 4)
				if err != nil || guard != 0xdeadbeef {
					t.Fatalf("PE32 pointer overwrote adjacent memory: 0x%x, %v", guard, err)
				}
				return
			}
			got, err := mem.Read64(output)
			if err != nil || got != address {
				t.Fatalf("PE64 pointer = 0x%x, %v", got, err)
			}
		})
	}
}

func TestLdrGetProcedureAddressAcrossGuestABIs(t *testing.T) {
	for _, mode32 := range []bool{false, true} {
		name := "pe64"
		if mode32 {
			name = "pe32"
		}
		t.Run(name, func(t *testing.T) {
			mem := mmu.New()
			mem.Mode32 = mode32
			base := mem.Mmap(0, 0x2000, mmu.PermRead|mmu.PermWrite)
			ntdll := &SynthPE{
				BaseAddr: base + 0x1000,
				Exports: map[string]uint64{
					"RtlGetNtVersionNumbers": base + 0x1100,
					"wine_get_version":       base + 0x1200,
				},
				ExportOrds: make(map[uint16]uint64),
			}
			dispatcher := &Dispatcher{
				ntdll:            ntdll,
				moduleExports:    make(map[uint64]map[string]uint64),
				moduleOrdExports: make(map[uint64]map[uint16]uint64),
			}
			cpu := &ldrTestCPU{mem: mem, arch: arch.ArchAMD64}
			if mode32 {
				cpu.arch = arch.ArchI386
			}
			ctx := &TrapContext{CPU: cpu, Mem: mem, Disp: dispatcher}
			ansiString := base + 0x100
			nameBuffer := base + 0x200
			output := base + 0x300

			call := func(exportName string) uint32 {
				if err := mem.WriteBytes(nameBuffer, []byte(exportName)); err != nil {
					t.Fatal(err)
				}
				if err := mem.Write16(ansiString, uint16(len(exportName))); err != nil {
					t.Fatal(err)
				}
				if mode32 {
					if err := mem.Write32(ansiString+4, uint32(nameBuffer)); err != nil {
						t.Fatal(err)
					}
					cpu.sp = base + 0x500
					args := []uint32{0, uint32(ntdll.BaseAddr), uint32(ansiString), 0, uint32(output)}
					for index, value := range args {
						if err := mem.Write32(cpu.sp+uint64(index*4), value); err != nil {
							t.Fatal(err)
						}
					}
				} else {
					if err := mem.Write64(ansiString+8, nameBuffer); err != nil {
						t.Fatal(err)
					}
					cpu.regs[regRCX] = ntdll.BaseAddr
					cpu.regs[regRDX] = ansiString
					cpu.regs[regR8] = 0
					cpu.regs[regR9] = output
				}
				return handleLdrGetProcedureAddress(ctx)
			}

			if status := call("RtlGetNtVersionNumbers"); status != StatusSuccess {
				t.Fatalf("native lookup status = 0x%x", status)
			}
			var resolved uint64
			if mode32 {
				value, err := mem.Read32(output)
				if err != nil {
					t.Fatal(err)
				}
				resolved = uint64(value)
			} else {
				value, err := mem.Read64(output)
				if err != nil {
					t.Fatal(err)
				}
				resolved = value
			}
			if resolved != ntdll.Exports["RtlGetNtVersionNumbers"] {
				t.Fatalf("native lookup address = 0x%x", resolved)
			}

			writeGuestPointer(mem, output, 0x1234)
			if status := call("wine_get_version"); status != 0xC0000139 {
				t.Fatalf("hidden lookup status = 0x%x", status)
			}
			if mode32 {
				value, _ := mem.Read32(output)
				resolved = uint64(value)
			} else {
				resolved, _ = mem.Read64(output)
			}
			if resolved != 0 {
				t.Fatalf("hidden lookup output = 0x%x", resolved)
			}
		})
	}
}

func TestFindModuleByNameAcrossGuestABIs(t *testing.T) {
	modules := []ModuleInfo{
		{Name: "app.exe", FullPath: `C:\app.exe`, BaseAddr: 0x400000, ImageSize: 0x10000, Entry: 0x401000},
		{Name: "kernel32.dll", FullPath: `C:\Windows\System32\kernel32.dll`, BaseAddr: 0x76000000, ImageSize: 0x20000, Entry: 0x76001000},
	}
	for _, mode32 := range []bool{false, true} {
		name := "pe64"
		if mode32 {
			name = "pe32"
		}
		t.Run(name, func(t *testing.T) {
			mem := mmu.New()
			mem.Mode32 = mode32
			state, err := InitProcess(mem, &ProcessInit{
				ImageBase:   modules[0].BaseAddr,
				ImageSize:   modules[0].ImageSize,
				EntryPoint:  modules[0].Entry,
				CommandLine: `C:\app.exe`,
				ImagePath:   `C:\app.exe`,
				CurrentDir:  `C:\`,
				ProcessId:   1,
				ThreadId:    1,
				StackBase:   0x70000000,
				StackLimit:  0x6fff0000,
				Is32:        mode32,
			}, modules)
			if err != nil {
				t.Fatal(err)
			}
			ctx := &TrapContext{Mem: mem, State: state}
			if got := findModuleByName(ctx, "kernel32.dll"); got != modules[1].BaseAddr {
				t.Fatalf("module base = 0x%x", got)
			}
			if got := findModuleByName(ctx, "missing.dll"); got != 0 {
				t.Fatalf("missing module base = 0x%x", got)
			}
		})
	}
}

func TestLdrGetDllHandleExAcrossGuestABIs(t *testing.T) {
	modules := []ModuleInfo{
		{Name: "app.exe", FullPath: `C:\app.exe`, BaseAddr: 0x400000, ImageSize: 0x10000, Entry: 0x401000},
		{Name: "kernel32.dll", FullPath: `C:\Windows\System32\kernel32.dll`, BaseAddr: 0x76000000, ImageSize: 0x20000, Entry: 0x76001000},
	}
	for _, mode32 := range []bool{false, true} {
		name := "pe64"
		if mode32 {
			name = "pe32"
		}
		t.Run(name, func(t *testing.T) {
			mem := mmu.New()
			mem.Mode32 = mode32
			state, err := InitProcess(mem, &ProcessInit{
				ImageBase: modules[0].BaseAddr, ImageSize: modules[0].ImageSize, EntryPoint: modules[0].Entry,
				CommandLine: `C:\app.exe`, ImagePath: `C:\app.exe`, CurrentDir: `C:\`,
				ProcessId: 1, ThreadId: 1, StackBase: 0x70000000, StackLimit: 0x6fff0000, Is32: mode32,
			}, modules)
			if err != nil {
				t.Fatal(err)
			}
			base := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
			unicodeString := base
			buffer := base + 0x100
			output := base + 0x200
			stack := base + 0x400
			const moduleName = "kernel32.dll"
			writeGuestUTF16(mem, buffer, moduleName)
			if err := mem.Write16(unicodeString, uint16(len(moduleName)*2)); err != nil {
				t.Fatal(err)
			}
			if mode32 {
				if err := mem.Write32(unicodeString+4, uint32(buffer)); err != nil {
					t.Fatal(err)
				}
				if err := mem.Write32(output+4, 0xdeadbeef); err != nil {
					t.Fatal(err)
				}
			} else if err := mem.Write64(unicodeString+8, buffer); err != nil {
				t.Fatal(err)
			}

			cpu := &ldrTestCPU{mem: mem, arch: arch.ArchAMD64, sp: stack}
			if mode32 {
				cpu.arch = arch.ArchI386
				args := []uint32{0, 0, 0, 0, uint32(unicodeString), uint32(output)}
				for index, value := range args {
					if err := mem.Write32(stack+uint64(index*4), value); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				cpu.regs[regRCX] = 0
				cpu.regs[regRDX] = 0
				cpu.regs[regR8] = 0
				cpu.regs[regR9] = unicodeString
				if err := mem.Write64(stack+0x28, output); err != nil {
					t.Fatal(err)
				}
			}
			ctx := &TrapContext{CPU: cpu, Mem: mem, State: state}
			if status := handleLdrGetDllHandleEx(ctx); status != StatusSuccess {
				t.Fatalf("lookup status = 0x%x", status)
			}
			if mode32 {
				value, _ := mem.Read32(output)
				if uint64(value) != modules[1].BaseAddr {
					t.Fatalf("PE32 module base = 0x%x", value)
				}
				guard, _ := mem.Read32(output + 4)
				if guard != 0xdeadbeef {
					t.Fatalf("PE32 output overwrote adjacent memory: 0x%x", guard)
				}
			} else {
				value, _ := mem.Read64(output)
				if value != modules[1].BaseAddr {
					t.Fatalf("PE64 module base = 0x%x", value)
				}
			}
		})
	}
}

func TestLdrGetDllPathAcrossGuestABIs(t *testing.T) {
	for _, mode32 := range []bool{false, true} {
		name := "pe64"
		if mode32 {
			name = "pe32"
		}
		t.Run(name, func(t *testing.T) {
			mem := mmu.New()
			mem.Mode32 = mode32
			base := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
			flagsStorage := base + 0x100
			dllPathOutput := base + 0x200
			searchOutput := base + 0x300
			stack := base + 0x400
			writeGuestPointer(mem, flagsStorage, 0x1111)
			writeGuestPointer(mem, dllPathOutput, 0x2222)
			writeGuestPointer(mem, searchOutput, 0x3333)

			cpu := &ldrTestCPU{mem: mem, arch: arch.ArchAMD64, sp: stack}
			if mode32 {
				cpu.arch = arch.ArchI386
				args := []uint32{0, 0, uint32(flagsStorage), uint32(dllPathOutput), uint32(searchOutput)}
				for index, value := range args {
					if err := mem.Write32(stack+uint64(index*4), value); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				cpu.regs[regRCX] = 0
				cpu.regs[regRDX] = flagsStorage
				cpu.regs[regR8] = dllPathOutput
				cpu.regs[regR9] = searchOutput
			}
			ctx := &TrapContext{CPU: cpu, Mem: mem}
			if status := handleLdrGetDllPath(ctx); status != StatusSuccess {
				t.Fatalf("status = 0x%x", status)
			}
			readPointer := func(addr uint64) uint64 {
				if mode32 {
					value, _ := mem.Read32(addr)
					return uint64(value)
				}
				value, _ := mem.Read64(addr)
				return value
			}
			if got := readPointer(flagsStorage); got != 0x1111 {
				t.Fatalf("flags storage was modified: 0x%x", got)
			}
			if got := readPointer(dllPathOutput); got != 0 {
				t.Fatalf("DLL path output = 0x%x", got)
			}
			if got := readPointer(searchOutput); got != 0 {
				t.Fatalf("search path output = 0x%x", got)
			}
		})
	}
}
