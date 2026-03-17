//go:build guest_windows

package loader

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
)

// PEModule represents a loaded PE image in guest memory.
type PEModule struct {
	Name             string            // DLL name or exe basename (lowercase)
	Path             string            // host filesystem path
	BaseAddr         uint64            // actual base address in guest MMU
	ImageSize        uint64            // size of the mapped image
	EntryPoint       uint64            // AddressOfEntryPoint (RVA + BaseAddr)
	Exports          map[string]uint64 // export name → guest address
	ExportOrds       map[uint16]uint64 // export ordinal → guest address
	Forwards         map[string]string // export name → "DLL.Function" forward
	ForwardOrds      map[uint16]string // export ordinal → "DLL.Function" forward
	Imports          []PEImportEntry   // unresolved imports
	Is64             bool
	IsDLL            bool     // true if IMAGE_FILE_DLL flag is set
	TLSDataAddr      uint64   // guest address of allocated TLS template data (0 if none)
	TLSDataSize      uint64   // size of TLS initial data
	TLSIndexAddr     uint64   // guest address of the TLS index slot
	TLSCallbacks     []uint64 // guest addresses of TLS callback functions
	ExceptionDirRVA  uint32   // RVA of .pdata (exception directory)
	ExceptionDirSize uint32   // size of .pdata
	ResourceDirRVA   uint32   // RVA of .rsrc (resource directory)
	ResourceDirSize  uint32   // size of .rsrc
	BoundImports     []BoundImportEntry
	DelayImports     []PEImportEntry // delay-loaded imports (resolved lazily or at load)
}

// BoundImportEntry captures one bound import descriptor from the PE image.
type BoundImportEntry struct {
	DLLName               string
	TimeDateStamp         uint32
	OffsetModuleName      uint16
	NumberOfForwarderRefs uint16
}

// PEImportEntry describes a single import that needs resolution.
type PEImportEntry struct {
	DLLName  string
	FuncName string // empty if by ordinal
	Ordinal  uint16 // valid only if FuncName == ""
	IATSlot  uint64 // guest address of the IAT slot to patch
}

// PELoadResult extends LoadResult with PE-specific data.
type PELoadResult struct {
	LoadResult
	MainModule *PEModule
}

// PE image base relocation types.
const (
	imageRelBasedAbsolute = 0
	imageRelBasedHigh     = 1
	imageRelBasedLow      = 2
	imageRelBasedHighLow  = 3
	imageRelBasedHighAdj  = 4
	imageRelBasedDir64    = 10
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
	// Reserve the Windows-style stack (64 MiB, below KUSER_SHARED_DATA at
	// 0x7FFE0000) BEFORE mapping the main module. A system DLL run as the main
	// image (e.g. -call-export gdi32.dll, preferred ImageBase ~0x7c370000) has a
	// preferred base inside this stack range; mapping the stack first lets
	// MapPEFile's collision check relocate the image to a free region, instead
	// of the stack mapping later overwriting the DLL's code pages as RW
	// (non-executable) and faulting on the first instruction fetch.
	stackTop := uint64(0x7FFD0000)
	stackSize := uint64(64 * 1024 * 1024)
	stackBottom := stackTop - stackSize
	mem.MapRange(stackBottom, stackSize, mmu.PermRead|mmu.PermWrite)

	mod, err := MapPEFile(path, mem, 0)
	if err != nil {
		return nil, fmt.Errorf("pe load: %w", err)
	}

	// Simulate a CALL to the entry point.
	sp := stackTop // 16-byte aligned
	if mod.Is64 {
		// x64: allocate 32-byte shadow space, push 8-byte return address.
		sp -= 32            // shadow space (32 bytes for 4 register args)
		sp -= 8             // CALL pushes return address
		write64(mem, sp, 0) // exit sentinel (ret to 0 → process exit)
	} else {
		// x86 (PE32): no shadow space, push 4-byte return address.
		sp -= 4
		mem.Write32(sp, 0) // exit sentinel
	}

	// Set brk after the image
	brkAddr := (mod.BaseAddr + mod.ImageSize + mmu.PageSize - 1) & mmu.PageMask
	mem.SetBrk(brkAddr)

	resultArch := arch.ArchAMD64
	if !mod.Is64 {
		resultArch = arch.ArchI386
	}

	return &PELoadResult{
		LoadResult: LoadResult{
			EntryPoint: mod.EntryPoint,
			StackPtr:   sp,
			BrkAddr:    brkAddr,
			TLSAddr:    0, // TEB is set up separately by P1
			Arch:       resultArch,
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
		Name:        strings.ToLower(filepath.Base(path)),
		Path:        path,
		Exports:     make(map[string]uint64),
		ExportOrds:  make(map[uint16]uint64),
		Forwards:    make(map[string]string),
		ForwardOrds: make(map[uint16]string),
	}

	var imageBase, sizeOfImage, entryRVA uint64
	var relocDirRVA, relocDirSize uint32
	var tlsDirRVA, tlsDirSize uint32
	var boundImportRVA, boundImportSize uint32
	var excDirRVA, excDirSize uint32
	var resDirRVA, resDirSize uint32
	var delayImportRVA uint32

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
		if len(oh.DataDirectory) > 11 {
			boundImportRVA = oh.DataDirectory[11].VirtualAddress
			boundImportSize = oh.DataDirectory[11].Size
		}
		if len(oh.DataDirectory) > 3 {
			excDirRVA = oh.DataDirectory[3].VirtualAddress
			excDirSize = oh.DataDirectory[3].Size
		}
		if len(oh.DataDirectory) > 2 {
			resDirRVA = oh.DataDirectory[2].VirtualAddress
			resDirSize = oh.DataDirectory[2].Size
		}
		if len(oh.DataDirectory) > 13 {
			delayImportRVA = oh.DataDirectory[13].VirtualAddress
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
		if len(oh.DataDirectory) > 11 {
			boundImportRVA = oh.DataDirectory[11].VirtualAddress
			boundImportSize = oh.DataDirectory[11].Size
		}
		if len(oh.DataDirectory) > 3 {
			excDirRVA = oh.DataDirectory[3].VirtualAddress
			excDirSize = oh.DataDirectory[3].Size
		}
		if len(oh.DataDirectory) > 2 {
			resDirRVA = oh.DataDirectory[2].VirtualAddress
			resDirSize = oh.DataDirectory[2].Size
		}
		if len(oh.DataDirectory) > 13 {
			delayImportRVA = oh.DataDirectory[13].VirtualAddress
		}
	default:
		return nil, fmt.Errorf("no optional header in %s", path)
	}

	base := imageBase
	if forceBase != 0 {
		base = forceBase
	}

	// Check if preferred base is available; if not, pick a free region.
	// Also needs relocation if forceBase overrides the preferred base.
	needReloc := base != imageBase
	if !needReloc && (mem.IsMapped(base) || mem.IsMapped(base+sizeOfImage-1)) {
		// Preferred base is occupied - pick a free region.
		base = mem.Mmap(0, sizeOfImage, mmu.PermRead|mmu.PermWrite)
		needReloc = true
	} else if !needReloc {
		mem.MapRange(base, sizeOfImage, mmu.PermRead|mmu.PermWrite)
	}

	mod.BaseAddr = base
	mod.ImageSize = sizeOfImage
	mod.EntryPoint = base + entryRVA
	mod.ExceptionDirRVA = excDirRVA
	mod.ExceptionDirSize = excDirSize
	mod.ResourceDirRVA = resDirRVA
	mod.ResourceDirSize = resDirSize

	// Map PE headers (first page(s))
	if len(pf.Sections) == 0 {
		return nil, fmt.Errorf("PE has no sections in %s", path)
	}
	headerData := make([]byte, pf.Sections[0].Offset)
	f.Seek(0, io.SeekStart)
	io.ReadFull(f, headerData)
	mem.WriteBytes(base, headerData)

	// For DLLs, add execute permission to the PE header pages (DEP-off).
	if mod.IsDLL && len(headerData) > 0 {
		hdrSize := (uint64(len(headerData)) + mmu.PageSize - 1) & mmu.PageMask
		mem.Mprotect(base, hdrSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	}

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
		// Windows PE binaries expect DEP disabled - add execute to all sections
		// that have code or are DLLs. This allows dynamic thunks and function
		// pointer tables to work correctly.
		if mod.IsDLL || sec.Name == ".text" || (ch&imageScnCntCode) != 0 {
			perms |= mmu.PermExecute
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
	if boundImportRVA != 0 && boundImportSize > 0 {
		parseBoundImports(pf, f, mod, boundImportRVA, boundImportSize)
	}

	// Parse delay-load imports (directory index 13)
	if delayImportRVA != 0 {
		parseDelayImports(pf, f, mod, delayImportRVA)
	}

	return mod, nil
}

// MapPEBytes loads a PE image from an in-memory byte slice into the MMU.
// It writes the bytes to a temporary host file and delegates to MapPEFile,
// overriding the module name with the provided name.
func MapPEBytes(name string, data []byte, mem *mmu.MMU, forceBase uint64) (*PEModule, error) {
	tmp, err := os.CreateTemp("", "govm-dll-*.pe")
	if err != nil {
		return nil, fmt.Errorf("MapPEBytes tmpfile: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("MapPEBytes write: %w", err)
	}
	tmp.Close()
	defer os.Remove(tmpPath)

	mod, err := MapPEFile(tmpPath, mem, forceBase)
	if err != nil {
		return nil, err
	}
	mod.Name = strings.ToLower(name)
	return mod, nil
}


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
				mem.Write32Raw(target, newVal)
			case imageRelBasedDir64:
				val, err := mem.Read64(target)
				if err != nil {
					continue
				}
				newVal := uint64(int64(val) + delta)
				mem.Write64Raw(target, newVal)
			case imageRelBasedHigh:
				val, err := mem.Read16(target)
				if err != nil {
					continue
				}
				newVal := uint16(int64(val) + (delta >> 16))
				b := []byte{byte(newVal), byte(newVal >> 8)}
				mem.WriteBytesRaw(target, b)
			case imageRelBasedLow:
				val, err := mem.Read16(target)
				if err != nil {
					continue
				}
				newVal := uint16(int64(val) + delta)
				b := []byte{byte(newVal), byte(newVal >> 8)}
				mem.WriteBytesRaw(target, b)
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

	// Build a set of ordinal indices that have names (from the name table)
	namedOrdIdx := make(map[uint16]bool, numNames)
	for i := uint32(0); i < numNames; i++ {
		nameOff := nameTable[i] - secRVA
		if int(nameOff) >= len(secData) {
			continue
		}
		name := readCString(secData, nameOff)
		ordIdx := ordTable[i]
		namedOrdIdx[ordIdx] = true
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
				mod.ForwardOrds[uint16(uint32(ordIdx)+ordBase)] = fwdStr
			}
		} else {
			mod.Exports[name] = mod.BaseAddr + uint64(funcAddr)
			mod.ExportOrds[uint16(uint32(ordIdx)+ordBase)] = mod.BaseAddr + uint64(funcAddr)
		}
	}

	// Also iterate ordinal-only exports (no name in name table)
	for ordIdx := uint32(0); ordIdx < numFuncs; ordIdx++ {
		if namedOrdIdx[uint16(ordIdx)] {
			continue // already processed via name table
		}
		funcAddr := funcTable[ordIdx]
		if funcAddr == 0 {
			continue
		}
		ord := uint16(ordIdx + ordBase)
		if funcAddr >= exportDirRVA && funcAddr < exportEnd {
			fwdOff := funcAddr - secRVA
			if int(fwdOff) < len(secData) {
				fwdStr := readCString(secData, fwdOff)
				mod.ForwardOrds[ord] = fwdStr
			}
		} else {
			mod.ExportOrds[ord] = mod.BaseAddr + uint64(funcAddr)
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

// parseDelayImports reads the delay-load import directory (index 13).
// Each ImgDelayDescr is 32 bytes:
//
//	+0x00 grAttrs      DWORD  (1 = RVA-based addresses)
//	+0x04 rvaDLLName   DWORD  (RVA of DLL name string)
//	+0x08 rvaHmod      DWORD  (RVA of module handle storage)
//	+0x0C rvaIAT       DWORD  (RVA of delay-load IAT)
//	+0x10 rvaINT       DWORD  (RVA of delay-load INT / name table)
//	+0x14 rvaBoundIAT  DWORD
//	+0x18 rvaUnloadIAT DWORD
//	+0x1C dwTimeStamp  DWORD
func parseDelayImports(pf *pe.File, f *os.File, mod *PEModule, dirRVA uint32) {
	secData, secRVA := sectionDataForRVA(pf, f, dirRVA)
	if secData == nil {
		return
	}

	off := dirRVA - secRVA
	for {
		if int(off)+32 > len(secData) {
			break
		}

		attrs := binary.LittleEndian.Uint32(secData[off:])
		nameRVA := binary.LittleEndian.Uint32(secData[off+4:])
		iatRVA := binary.LittleEndian.Uint32(secData[off+0x0C:])
		intRVA := binary.LittleEndian.Uint32(secData[off+0x10:])

		// Terminator: all-zero descriptor
		if nameRVA == 0 && iatRVA == 0 {
			break
		}

		// grAttrs == 1 means addresses are RVAs; 0 means VAs (old-style).
		// We only support the modern RVA-based format.
		isRVA := attrs&1 != 0
		_ = isRVA // future: handle VA-based if needed

		// Read DLL name
		dllName := ""
		nameOff := nameRVA - secRVA
		if int(nameOff) < len(secData) {
			dllName = readCString(secData, nameOff)
		}
		if dllName == "" {
			off += 32
			continue
		}

		// Walk the INT (Import Name Table) to enumerate imported functions.
		// Simultaneously walk IAT offsets so we know which slot to patch.
		lookupRVA := intRVA
		if lookupRVA == 0 {
			lookupRVA = iatRVA
		}

		// May be in a different section
		intSec, intSecRVA := sectionDataForRVA(pf, f, lookupRVA)
		if intSec == nil {
			intSec = secData
			intSecRVA = secRVA
		}

		entrySize := uint32(8)
		if !mod.Is64 {
			entrySize = 4
		}

		lookupOff := lookupRVA - intSecRVA
		iatAddr := uint64(iatRVA) + mod.BaseAddr
		for {
			if int(lookupOff)+int(entrySize) > len(intSec) {
				break
			}

			var thunk uint64
			if mod.Is64 {
				thunk = binary.LittleEndian.Uint64(intSec[lookupOff:])
			} else {
				thunk = uint64(binary.LittleEndian.Uint32(intSec[lookupOff:]))
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
				// Hint/Name entry may be in yet another section
				hintSec, hintSecRVA := sectionDataForRVA(pf, f, hintRVA)
				if hintSec == nil {
					hintSec = secData
					hintSecRVA = secRVA
				}
				hintOff := hintRVA - hintSecRVA
				if int(hintOff)+2 < len(hintSec) {
					imp.FuncName = readCString(hintSec, hintOff+2)
				}
			}

			mod.DelayImports = append(mod.DelayImports, imp)
			lookupOff += entrySize
			iatAddr += uint64(entrySize)
		}

		ravelog.Logf("[pe] delay-import: %s (%d entries)\n", dllName, len(mod.DelayImports))
		off += 32
	}
}
func ResolveImports(mem *mmu.MMU, mod *PEModule, modules map[string]*PEModule) error {
	resolved := 0
	unresolved := 0
	for _, imp := range mod.Imports {
		dllKey := strings.ToLower(imp.DLLName)
		target, ok := modules[dllKey]
		if !ok {
			// Try without .dll extension
			dllKey = strings.TrimSuffix(dllKey, ".dll")
			target, ok = modules[dllKey]
		}
		if !ok {
			ravelog.Logf("[resolve] DLL NOT FOUND: %s (for %s)\n", imp.DLLName, mod.Name)
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
			if addr == 0 {
				if fwd, ok := target.ForwardOrds[imp.Ordinal]; ok {
					addr = resolveForward(fwd, modules)
				}
			}
		}

		if addr != 0 {
			if mod.Is64 {
				mem.Write64Raw(imp.IATSlot, addr)
			} else {
				mem.Write32Raw(imp.IATSlot, uint32(addr))
			}
			resolved++
		} else {
			ravelog.Logf("[resolve] UNRESOLVED: %s!%s (ord=%d) for %s IAT=0x%x\n",
				imp.DLLName, imp.FuncName, imp.Ordinal, mod.Name, imp.IATSlot)
			// Write a sentinel address outside crash-recovery range (> 0x10000)
			// to prevent silent recovery; will cause a clear "unmapped" fault.
			const unresolvedSentinel = 0xDEAD_DEAD_0001_0000
			if mod.Is64 {
				mem.Write64Raw(imp.IATSlot, unresolvedSentinel)
			} else {
				mem.Write32Raw(imp.IATSlot, 0xDEAD0000)
			}
			unresolved++
		}
	}
	ravelog.Logf("[resolve] %s: %d imports, %d resolved, %d unresolved, exports=%d\n",
		mod.Name, len(mod.Imports), resolved, unresolved, len(modules))

	// Also resolve delay-load imports. These are eagerly resolved at load time
	// (same as regular imports) since the emulator handles all DLLs synthetically.
	delayRes := 0
	delayUnres := 0
	for _, imp := range mod.DelayImports {
		dllKey := strings.ToLower(imp.DLLName)
		target, ok := modules[dllKey]
		if !ok {
			dllKey = strings.TrimSuffix(dllKey, ".dll")
			target, ok = modules[dllKey]
		}
		if !ok {
			ravelog.Logf("[resolve-delay] DLL NOT FOUND: %s (for %s)\n", imp.DLLName, mod.Name)
			delayUnres++
			continue
		}

		var addr uint64
		if imp.FuncName != "" {
			addr = target.Exports[imp.FuncName]
			if addr == 0 {
				if fwd, ok := target.Forwards[imp.FuncName]; ok {
					addr = resolveForward(fwd, modules)
				}
			}
		} else {
			addr = target.ExportOrds[imp.Ordinal]
			if addr == 0 {
				if fwd, ok := target.ForwardOrds[imp.Ordinal]; ok {
					addr = resolveForward(fwd, modules)
				}
			}
		}

		if addr != 0 {
			if mod.Is64 {
				mem.Write64Raw(imp.IATSlot, addr)
			} else {
				mem.Write32Raw(imp.IATSlot, uint32(addr))
			}
			delayRes++
		} else {
			ravelog.Logf("[resolve-delay] UNRESOLVED: %s!%s (ord=%d) for %s IAT=0x%x\n",
				imp.DLLName, imp.FuncName, imp.Ordinal, mod.Name, imp.IATSlot)
			delayUnres++
		}
	}
	if len(mod.DelayImports) > 0 {
		ravelog.Logf("[resolve] %s: %d delay-imports, %d resolved, %d unresolved\n",
			mod.Name, len(mod.DelayImports), delayRes, delayUnres)
	}

	return nil
}

// resolveForward handles forwarded exports like "ntdll.RtlAllocateHeap".
// Supports recursive forwarding chains and ordinal-based forwards (e.g., "shlwapi.#24").
func resolveForward(fwd string, modules map[string]*PEModule) uint64 {
	return resolveForwardDepth(fwd, modules, 0)
}

func resolveForwardDepth(fwd string, modules map[string]*PEModule, depth int) uint64 {
	if depth > 8 {
		return 0 // prevent infinite loops
	}
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
	funcName := parts[1]

	// Handle ordinal-based forwards like "#24"
	if len(funcName) > 0 && funcName[0] == '#' {
		var ord uint16
		for _, c := range funcName[1:] {
			ord = ord*10 + uint16(c-'0')
		}
		if addr, ok := target.ExportOrds[ord]; ok {
			return addr
		}
		if chainFwd, ok := target.ForwardOrds[ord]; ok {
			return resolveForwardDepth(chainFwd, modules, depth+1)
		}
		return 0
	}

	// Named export
	if addr, ok := target.Exports[funcName]; ok {
		return addr
	}
	// Check if the target itself forwards this name
	if chainFwd, ok := target.Forwards[funcName]; ok {
		return resolveForwardDepth(chainFwd, modules, depth+1)
	}
	return 0
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

		// Read TLS callbacks (AddressOfCallBacks at offset 0x18)
		callbacksVA, _ := mem.Read64(tlsAddr + 0x18)
		if callbacksVA != 0 {
			for i := uint64(0); ; i++ {
				cb, err := mem.Read64(callbacksVA + i*8)
				if err != nil || cb == 0 {
					break
				}
				mod.TLSCallbacks = append(mod.TLSCallbacks, cb)
			}
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
		// Read TLS callbacks for 32-bit (AddressOfCallBacks at offset 0x0C)
		callbacksVA32, _ := mem.Read32(tlsAddr + 0x0C)
		if callbacksVA32 != 0 {
			for i := uint64(0); ; i++ {
				cb, err := mem.Read32(uint64(callbacksVA32) + i*4)
				if err != nil || cb == 0 {
					break
				}
				mod.TLSCallbacks = append(mod.TLSCallbacks, uint64(cb))
			}
		}
	}
}

func parseBoundImports(pf *pe.File, f *os.File, mod *PEModule, boundRVA, boundSize uint32) {
	secData, secRVA := sectionDataForRVA(pf, f, boundRVA)
	if secData == nil {
		return
	}
	baseOff := boundRVA - secRVA
	if int(baseOff) >= len(secData) {
		return
	}
	endOff := baseOff + boundSize
	if endOff > uint32(len(secData)) {
		endOff = uint32(len(secData))
	}

	off := baseOff
	for off+8 <= endOff {
		timeDateStamp := binary.LittleEndian.Uint32(secData[off:])
		if timeDateStamp == 0 {
			break
		}
		offsetModuleName := binary.LittleEndian.Uint16(secData[off+4:])
		numForwarderRefs := binary.LittleEndian.Uint16(secData[off+6:])

		nameOff := baseOff + uint32(offsetModuleName)
		if nameOff >= uint32(len(secData)) {
			break
		}
		dllName := readCString(secData, nameOff)
		if dllName != "" {
			mod.BoundImports = append(mod.BoundImports, BoundImportEntry{
				DLLName:               dllName,
				TimeDateStamp:         timeDateStamp,
				OffsetModuleName:      offsetModuleName,
				NumberOfForwarderRefs: numForwarderRefs,
			})
		}

		skip := uint32(8) + uint32(numForwarderRefs)*8
		if off+skip > endOff {
			break
		}
		off += skip
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
