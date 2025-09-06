package loader

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mirkobrombin/go-vm/pkg/arch"
	"github.com/mirkobrombin/go-vm/pkg/mmu"
)

// PEModule represents a loaded PE image in guest memory.
type PEModule struct {
	Name       string   // DLL name or exe basename (lowercase)
	Path       string   // host filesystem path
	BaseAddr   uint64   // actual base address in guest MMU
	ImageSize  uint64   // size of the mapped image
	EntryPoint uint64   // AddressOfEntryPoint (RVA + BaseAddr)
	Exports    map[string]uint64 // export name → guest address
	ExportOrds map[uint16]uint64 // export ordinal → guest address
	Forwards   map[string]string // export name → "DLL.Function" forward
	Imports    []PEImportEntry   // unresolved imports
	Is64       bool
	IsDLL      bool     // true if IMAGE_FILE_DLL flag is set
	TLSDataAddr uint64  // guest address of allocated TLS template data (0 if none)
	TLSDataSize uint64  // size of TLS initial data
	TLSIndexAddr uint64 // guest address of the TLS index slot
}

// PEImportEntry describes a single import that needs resolution.
type PEImportEntry struct {
	DLLName  string
	FuncName string   // empty if by ordinal
	Ordinal  uint16   // valid only if FuncName == ""
	IATSlot  uint64   // guest address of the IAT slot to patch
}

// PELoadResult extends LoadResult with PE-specific data.
type PELoadResult struct {
	LoadResult
	MainModule *PEModule
}

// PE image base relocation types.
const (
	imageRelBasedAbsolute       = 0
	imageRelBasedHigh           = 1
	imageRelBasedLow            = 2
	imageRelBasedHighLow        = 3
	imageRelBasedHighAdj        = 4
	imageRelBasedDir64          = 10
)

// PE section characteristics.
const (
	imageScnMemExecute = 0x20000000
	imageScnMemRead    = 0x40000000
	imageScnMemWrite   = 0x80000000
	imageScnCntCode    = 0x00000020
)

// LoadPE parses a PE/COFF executable and maps it into the given MMU.
// It returns the load result and the module descriptor for import resolution.
func LoadPE(path string, mem *mmu.MMU, argv []string, envp []string) (*PELoadResult, error) {
	mod, err := MapPEFile(path, mem, 0)
	if err != nil {
		return nil, fmt.Errorf("pe load: %w", err)
	}

	// Set up a minimal Windows-style stack (8 MiB, top at 0x7FFE0000).
	stackTop := uint64(0x7FFE0000)
	stackSize := uint64(8 * 1024 * 1024)
	stackBottom := stackTop - stackSize
	mem.MapRange(stackBottom, stackSize, mmu.PermRead|mmu.PermWrite)

	// Initialize the stack with a return address of 0 (process exit sentinel).
	sp := stackTop - 8
	write64(mem, sp, 0)

	// Windows x64 calling convention: 32 bytes shadow space + alignment.
	sp -= 32
	sp &= ^uint64(0xF) // 16-byte align

	// Set brk after the image
	brkAddr := (mod.BaseAddr + mod.ImageSize + mmu.PageSize - 1) & mmu.PageMask
	mem.SetBrk(brkAddr)

	return &PELoadResult{
		LoadResult: LoadResult{
			EntryPoint: mod.EntryPoint,
			StackPtr:   sp,
			BrkAddr:    brkAddr,
			TLSAddr:    0, // TEB is set up separately by P1
			Arch:       arch.ArchAMD64,
		},
		MainModule: mod,
	}, nil
}

// MapPEFile loads a PE file into guest memory at the given base address
// (0 means use the PE's preferred ImageBase). Returns the module descriptor.
func MapPEFile(path string, mem *mmu.MMU, forceBase uint64) (*PEModule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	pf, err := pe.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("pe parse %s: %w", path, err)
	}
	defer pf.Close()

	mod := &PEModule{
		Name:       strings.ToLower(filepath.Base(path)),
		Path:       path,
		Exports:    make(map[string]uint64),
		ExportOrds: make(map[uint16]uint64),
		Forwards:   make(map[string]string),
	}

	var imageBase, sizeOfImage, entryRVA uint64
	var relocDirRVA, relocDirSize uint32
	var tlsDirRVA, tlsDirSize uint32

	// Check DLL flag in COFF header characteristics
	mod.IsDLL = pf.Characteristics&0x2000 != 0 // IMAGE_FILE_DLL

	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		mod.Is64 = true
		imageBase = oh.ImageBase
		sizeOfImage = uint64(oh.SizeOfImage)
		entryRVA = uint64(oh.AddressOfEntryPoint)
		if len(oh.DataDirectory) > 5 {
			relocDirRVA = oh.DataDirectory[5].VirtualAddress
			relocDirSize = oh.DataDirectory[5].Size
		}
		if len(oh.DataDirectory) > 9 {
			tlsDirRVA = oh.DataDirectory[9].VirtualAddress
			tlsDirSize = oh.DataDirectory[9].Size
		}
	case *pe.OptionalHeader32:
		mod.Is64 = false
		imageBase = uint64(oh.ImageBase)
		sizeOfImage = uint64(oh.SizeOfImage)
		entryRVA = uint64(oh.AddressOfEntryPoint)
		if len(oh.DataDirectory) > 5 {
			relocDirRVA = oh.DataDirectory[5].VirtualAddress
			relocDirSize = oh.DataDirectory[5].Size
		}
		if len(oh.DataDirectory) > 9 {
			tlsDirRVA = oh.DataDirectory[9].VirtualAddress
			tlsDirSize = oh.DataDirectory[9].Size
		}
	default:
		return nil, fmt.Errorf("no optional header in %s", path)
	}

	base := imageBase
	if forceBase != 0 {
		base = forceBase
	}

	// Check if preferred base is available; if not, pick a free region.
	needReloc := false
	if mem.IsMapped(base) || mem.IsMapped(base+sizeOfImage-1) {
		// Find free space
		base = mem.Mmap(0, sizeOfImage, mmu.PermRead|mmu.PermWrite)
		needReloc = true
	} else {
		mem.MapRange(base, sizeOfImage, mmu.PermRead|mmu.PermWrite)
	}

	mod.BaseAddr = base
	mod.ImageSize = sizeOfImage
	mod.EntryPoint = base + entryRVA

	// Map PE headers (first page(s))
	if len(pf.Sections) == 0 {
		return nil, fmt.Errorf("PE has no sections in %s", path)
	}
	headerData := make([]byte, pf.Sections[0].Offset)
	f.Seek(0, io.SeekStart)
	io.ReadFull(f, headerData)
	mem.WriteBytes(base, headerData)

	// Map each section
	for _, sec := range pf.Sections {
		rva := uint64(sec.VirtualAddress)
		vsize := uint64(sec.VirtualSize)
		rawSize := uint64(sec.Size)

		if vsize == 0 {
			vsize = rawSize
		}

		// Determine permissions
		ch := sec.Characteristics
		var perms uint8
		if ch&imageScnMemRead != 0 {
			perms |= mmu.PermRead
		}
		if ch&imageScnMemWrite != 0 {
			perms |= mmu.PermWrite
		}
		if ch&imageScnMemExecute != 0 {
			perms |= mmu.PermExecute
		}
		if perms == 0 {
			perms = mmu.PermRead // default
		}

		// Read raw data
		if rawSize > 0 {
			data := make([]byte, rawSize)
			f.Seek(int64(sec.Offset), io.SeekStart)
			n, _ := io.ReadFull(f, data)
			if uint64(n) < rawSize {
				data = data[:n]
			}
			mem.WriteBytes(base+rva, data)
		}

		// Set proper permissions on the section pages
		alignedStart := (base + rva) & mmu.PageMask
		alignedEnd := (base + rva + vsize + mmu.PageSize - 1) & mmu.PageMask
		mem.Mprotect(alignedStart, alignedEnd-alignedStart, perms)
	}

	// Apply base relocations if the image was relocated
	if needReloc && relocDirRVA != 0 && relocDirSize > 0 {
		delta := int64(base) - int64(imageBase)
		if err := applyRelocations(mem, base, uint64(relocDirRVA), uint64(relocDirSize), delta, mod.Is64); err != nil {
			return nil, fmt.Errorf("relocations: %w", err)
		}
	}

	// Parse exports
	parseExports(pf, f, mod)

	// Parse imports
	parseImports(pf, f, mod)

	// Parse TLS Directory
	if tlsDirRVA != 0 && tlsDirSize > 0 {
		parseTLSDirectory(mem, base, pf, f, tlsDirRVA, mod)
	}

	return mod, nil
}

// applyRelocations processes the .reloc section and patches addresses.
func applyRelocations(mem *mmu.MMU, base, relocRVA, relocSize uint64, delta int64, is64 bool) error {
	addr := base + relocRVA
	end := addr + relocSize

	for addr < end {
		pageRVA, err := mem.Read32(addr)
		if err != nil {
			break
		}
		blockSize, err := mem.Read32(addr + 4)
		if err != nil {
			break
		}
		if blockSize < 8 {
			break
		}

		numEntries := (blockSize - 8) / 2
		for i := uint32(0); i < numEntries; i++ {
			entry, err := mem.Read16(addr + 8 + uint64(i)*2)
			if err != nil {
				break
			}

			relocType := entry >> 12
			offset := uint64(entry & 0x0FFF)
			target := base + uint64(pageRVA) + offset

			// Temporarily allow writes for relocation patching
			switch relocType {
			case imageRelBasedAbsolute:
				// padding, skip
			case imageRelBasedHighLow:
				val, err := mem.Read32(target)
				if err != nil {
					continue
				}
				newVal := uint32(int64(val) + delta)
				mem.Write32(target, newVal)
			case imageRelBasedDir64:
				val, err := mem.Read64(target)
				if err != nil {
					continue
				}
				newVal := uint64(int64(val) + delta)
				mem.Write64(target, newVal)
			case imageRelBasedHigh:
				val, err := mem.Read16(target)
				if err != nil {
					continue
				}
				newVal := uint16(int64(val) + (delta >> 16))
				mem.Write16(target, newVal)
			case imageRelBasedLow:
				val, err := mem.Read16(target)
				if err != nil {
					continue
				}
				newVal := uint16(int64(val) + delta)
				mem.Write16(target, newVal)
			}
		}

		addr += uint64(blockSize)
	}

	return nil
}

// parseExports extracts the export table from a PE.
func parseExports(pf *pe.File, f *os.File, mod *PEModule) {
	var exportDirRVA, exportDirSize uint32
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 0 {
			exportDirRVA = oh.DataDirectory[0].VirtualAddress
			exportDirSize = oh.DataDirectory[0].Size
		}
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 0 {
			exportDirRVA = oh.DataDirectory[0].VirtualAddress
			exportDirSize = oh.DataDirectory[0].Size
		}
	}

	if exportDirRVA == 0 {
		return
	}

	// Read export directory from the raw file by finding which section contains the RVA.
	secData, secRVA := sectionDataForRVA(pf, f, exportDirRVA)
	if secData == nil {
		return
	}

	off := exportDirRVA - secRVA
	if int(off)+40 > len(secData) {
		return
	}

	ordBase := binary.LittleEndian.Uint32(secData[off+16:])
	numFuncs := binary.LittleEndian.Uint32(secData[off+20:])
	numNames := binary.LittleEndian.Uint32(secData[off+24:])
	funcRVA := binary.LittleEndian.Uint32(secData[off+28:])
	nameRVA := binary.LittleEndian.Uint32(secData[off+32:])
	ordRVA := binary.LittleEndian.Uint32(secData[off+36:])

	// Read function RVA table
	funcTable := readRVAArray(secData, secRVA, funcRVA, numFuncs)
	nameTable := readRVAArray(secData, secRVA, nameRVA, numNames)
	ordTable := readOrdArray(secData, secRVA, ordRVA, numNames)

	exportEnd := exportDirRVA + exportDirSize

	for i := uint32(0); i < numNames; i++ {
		nameOff := nameTable[i] - secRVA
		if int(nameOff) >= len(secData) {
			continue
		}
		name := readCString(secData, nameOff)
		ordIdx := ordTable[i]
		if uint32(ordIdx) >= numFuncs {
			continue
		}
		funcAddr := funcTable[ordIdx]

		// Check if this is a forwarder (RVA points within the export directory)
		if funcAddr >= exportDirRVA && funcAddr < exportEnd {
			fwdOff := funcAddr - secRVA
			if int(fwdOff) < len(secData) {
				fwdStr := readCString(secData, fwdOff)
				mod.Forwards[name] = fwdStr
			}
		} else {
			mod.Exports[name] = mod.BaseAddr + uint64(funcAddr)
			mod.ExportOrds[uint16(uint32(ordIdx)+ordBase)] = mod.BaseAddr + uint64(funcAddr)
		}
	}
}

// parseImports extracts the import table from a PE.
func parseImports(pf *pe.File, f *os.File, mod *PEModule) {
	var importDirRVA uint32
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 1 {
			importDirRVA = oh.DataDirectory[1].VirtualAddress
		}
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 1 {
			importDirRVA = oh.DataDirectory[1].VirtualAddress
		}
	}

	if importDirRVA == 0 {
		return
	}

	secData, secRVA := sectionDataForRVA(pf, f, importDirRVA)
	if secData == nil {
		return
	}

	// Walk import descriptors (20 bytes each, terminated by an all-zero entry)
	off := importDirRVA - secRVA
	for {
		if int(off)+20 > len(secData) {
			break
		}
		iltRVA := binary.LittleEndian.Uint32(secData[off:])
		nameRVA := binary.LittleEndian.Uint32(secData[off+12:])
		iatRVA := binary.LittleEndian.Uint32(secData[off+16:])

		if iltRVA == 0 && nameRVA == 0 {
			break
		}

		dllName := ""
		nameOff := nameRVA - secRVA
		if int(nameOff) < len(secData) {
			dllName = readCString(secData, nameOff)
		}

		// Walk the ILT (or IAT if ILT is 0) to find individual imports
		lookupRVA := iltRVA
		if lookupRVA == 0 {
			lookupRVA = iatRVA
		}

		entrySize := uint32(8) // 64-bit
		if !mod.Is64 {
			entrySize = 4
		}

		lookupOff := lookupRVA - secRVA
		iatAddr := uint64(iatRVA) + mod.BaseAddr
		for {
			if int(lookupOff)+int(entrySize) > len(secData) {
				break
			}

			var thunk uint64
			if mod.Is64 {
				thunk = binary.LittleEndian.Uint64(secData[lookupOff:])
			} else {
				thunk = uint64(binary.LittleEndian.Uint32(secData[lookupOff:]))
			}
			if thunk == 0 {
				break
			}

			imp := PEImportEntry{
				DLLName: dllName,
				IATSlot: iatAddr,
			}

			ordinalFlag := uint64(1) << 63
			if !mod.Is64 {
				ordinalFlag = 1 << 31
			}

			if thunk&ordinalFlag != 0 {
				imp.Ordinal = uint16(thunk & 0xFFFF)
			} else {
				hintRVA := uint32(thunk & 0x7FFFFFFF)
				hintOff := hintRVA - secRVA
				if int(hintOff)+2 < len(secData) {
					imp.FuncName = readCString(secData, hintOff+2)
				}
			}

			mod.Imports = append(mod.Imports, imp)
			lookupOff += entrySize
			iatAddr += uint64(entrySize)
		}

		off += 20
	}
}

// ResolveImports patches IAT slots using the given loaded modules.
func ResolveImports(mem *mmu.MMU, mod *PEModule, modules map[string]*PEModule) error {
	for _, imp := range mod.Imports {
		dllKey := strings.ToLower(imp.DLLName)
		target, ok := modules[dllKey]
		if !ok {
			// Try without .dll extension
			dllKey = strings.TrimSuffix(dllKey, ".dll")
			target, ok = modules[dllKey]
		}
		if !ok {
			continue // unresolved - leave stub (will trap if called)
		}

		var addr uint64
		if imp.FuncName != "" {
			addr = target.Exports[imp.FuncName]
			// Check forwarder
			if addr == 0 {
				if fwd, ok := target.Forwards[imp.FuncName]; ok {
					addr = resolveForward(fwd, modules)
				}
			}
		} else {
			addr = target.ExportOrds[imp.Ordinal]
		}

		if addr != 0 {
			if mod.Is64 {
				mem.Write64(imp.IATSlot, addr)
			} else {
				mem.Write32(imp.IATSlot, uint32(addr))
			}
		}
	}
	return nil
}

// resolveForward handles forwarded exports like "ntdll.RtlAllocateHeap".
func resolveForward(fwd string, modules map[string]*PEModule) uint64 {
	parts := strings.SplitN(fwd, ".", 2)
	if len(parts) != 2 {
		return 0
	}
	dllKey := strings.ToLower(parts[0])
	if !strings.HasSuffix(dllKey, ".dll") {
		dllKey += ".dll"
	}
	target, ok := modules[dllKey]
	if !ok {
		return 0
	}
	return target.Exports[parts[1]]
}

// parseTLSDirectory reads the IMAGE_TLS_DIRECTORY and allocates TLS storage.
//
// IMAGE_TLS_DIRECTORY64 layout:
//
//	+0x00 StartAddressOfRawData  (VA)
//	+0x08 EndAddressOfRawData    (VA)
//	+0x10 AddressOfIndex         (VA) - pointer to TLS index slot
//	+0x18 AddressOfCallBacks     (VA) - pointer to null-terminated callback array
//	+0x20 SizeOfZeroFill         (DWORD)
//	+0x24 Characteristics        (DWORD)
func parseTLSDirectory(mem *mmu.MMU, base uint64, pf *pe.File, f *os.File, tlsRVA uint32, mod *PEModule) {
	if mod.Is64 {
		// Read from guest memory (already mapped)
		tlsAddr := base + uint64(tlsRVA)
		startVA, err := mem.Read64(tlsAddr + 0x00)
		if err != nil {
			return
		}
		endVA, err := mem.Read64(tlsAddr + 0x08)
		if err != nil {
			return
		}
		indexVA, err := mem.Read64(tlsAddr + 0x10)
		if err != nil {
			return
		}
		zeroFill, _ := mem.Read32(tlsAddr + 0x20)

		rawSize := uint64(0)
		if endVA > startVA {
			rawSize = endVA - startVA
		}
		totalSize := rawSize + uint64(zeroFill)
		if totalSize == 0 {
			totalSize = 64 // minimum TLS area
		}

		// Allocate TLS template data
		tlsData := mem.Mmap(0, totalSize, mmu.PermRead|mmu.PermWrite)
		mod.TLSDataAddr = tlsData
		mod.TLSDataSize = totalSize

		// Copy initial TLS data from the image
		if rawSize > 0 && startVA != 0 {
			data, err := mem.ReadBytes(startVA, int(rawSize))
			if err == nil {
				mem.WriteBytes(tlsData, data)
			}
		}

		// Write TLS index (0 for the main module)
		if indexVA != 0 {
			mod.TLSIndexAddr = indexVA
			mem.Write32(indexVA, 0)
		}
	} else {
		// 32-bit TLS directory (smaller pointers)
		tlsAddr := base + uint64(tlsRVA)
		startVA32, err := mem.Read32(tlsAddr + 0x00)
		if err != nil {
			return
		}
		endVA32, err := mem.Read32(tlsAddr + 0x04)
		if err != nil {
			return
		}
		indexVA32, err := mem.Read32(tlsAddr + 0x08)
		if err != nil {
			return
		}
		zeroFill, _ := mem.Read32(tlsAddr + 0x10)

		rawSize := uint64(0)
		if endVA32 > startVA32 {
			rawSize = uint64(endVA32 - startVA32)
		}
		totalSize := rawSize + uint64(zeroFill)
		if totalSize == 0 {
			totalSize = 64
		}

		tlsData := mem.Mmap(0, totalSize, mmu.PermRead|mmu.PermWrite)
		mod.TLSDataAddr = tlsData
		mod.TLSDataSize = totalSize

		if rawSize > 0 && startVA32 != 0 {
			data, err := mem.ReadBytes(uint64(startVA32), int(rawSize))
			if err == nil {
				mem.WriteBytes(tlsData, data)
			}
		}

		if indexVA32 != 0 {
			mod.TLSIndexAddr = uint64(indexVA32)
			mem.Write32(uint64(indexVA32), 0)
		}
	}
}

// --- Helpers ---

func sectionDataForRVA(pf *pe.File, f *os.File, rva uint32) ([]byte, uint32) {
	for _, sec := range pf.Sections {
		start := sec.VirtualAddress
		end := start + sec.VirtualSize
		if sec.VirtualSize == 0 {
			end = start + sec.Size
		}
		if rva >= start && rva < end {
			data, err := sec.Data()
			if err != nil {
				return nil, 0
			}
			return data, start
		}
	}
	return nil, 0
}

func readRVAArray(secData []byte, secRVA, rva, count uint32) []uint32 {
	off := rva - secRVA
	result := make([]uint32, count)
	for i := uint32(0); i < count; i++ {
		idx := off + i*4
		if int(idx)+4 > len(secData) {
			break
		}
		result[i] = binary.LittleEndian.Uint32(secData[idx:])
	}
	return result
}

func readOrdArray(secData []byte, secRVA, rva, count uint32) []uint16 {
	off := rva - secRVA
	result := make([]uint16, count)
	for i := uint32(0); i < count; i++ {
		idx := off + i*2
		if int(idx)+2 > len(secData) {
			break
		}
		result[i] = binary.LittleEndian.Uint16(secData[idx:])
	}
	return result
}

func readCString(data []byte, offset uint32) string {
	end := offset
	for end < uint32(len(data)) && data[end] != 0 {
		end++
	}
	return string(data[offset:end])
}

func write64(mem *mmu.MMU, addr, val uint64) {
	mem.Write64(addr, val)
}
