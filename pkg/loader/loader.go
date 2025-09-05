package loader

import (
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/mirkobrombin/go-vm/pkg/arch"
	"github.com/mirkobrombin/go-vm/pkg/mmu"
)

const (
	DefaultStackSize = 8 * 1024 * 1024    // 8 MiB
	StackTop         = uint64(0x7FFF0000)  // top of guest stack
)

// LoadResult holds the state produced by loading an ELF.
type LoadResult struct {
	EntryPoint uint64
	StackPtr   uint64
	BrkAddr    uint64
	TLSAddr    uint64    // Thread-Local Storage base (0 if none)
	Arch       arch.Arch // detected architecture
}

// LoadELF parses an ELF file and maps it into the given MMU.
func LoadELF(path string, mem *mmu.MMU, argv []string, envp []string) (*LoadResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	ef, err := elf.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("elf parse: %w", err)
	}
	defer ef.Close()

	var guestArch arch.Arch
	switch ef.Machine {
	case elf.EM_RISCV:
		guestArch = arch.ArchRISCV64
	case elf.EM_X86_64:
		guestArch = arch.ArchAMD64
	default:
		return nil, fmt.Errorf("unsupported machine: %v (RISC-V and x86_64 supported)", ef.Machine)
	}
	if ef.Class != elf.ELFCLASS64 {
		return nil, fmt.Errorf("only 64-bit ELFs supported")
	}

	var maxAddr uint64
	var phdrAddr uint64
	var tlsVaddr, tlsFilesz, tlsMemsz, tlsAlign uint64

	for _, phdr := range ef.Progs {
		switch phdr.Type {
		case elf.PT_LOAD:
			// Map PT_LOAD segment
			vaddr := phdr.Vaddr
			memsz := phdr.Memsz
			filesz := phdr.Filesz

			alignedStart := vaddr & mmu.PageMask
			alignedEnd := (vaddr + memsz + mmu.PageSize - 1) & mmu.PageMask
			alignedSize := alignedEnd - alignedStart

			var perms uint8
			if phdr.Flags&elf.PF_R != 0 {
				perms |= mmu.PermRead
			}
			if phdr.Flags&elf.PF_W != 0 {
				perms |= mmu.PermWrite
			}
			if phdr.Flags&elf.PF_X != 0 {
				perms |= mmu.PermExecute
			}

			// Map with write permission temporarily for loading
			mem.MapRange(alignedStart, alignedSize, perms|mmu.PermWrite)

			if filesz > 0 {
				data := make([]byte, filesz)
				if _, err := f.Seek(int64(phdr.Off), io.SeekStart); err != nil {
					return nil, fmt.Errorf("seek: %w", err)
				}
				if _, err := io.ReadFull(f, data); err != nil {
					return nil, fmt.Errorf("read segment: %w", err)
				}
				if err := mem.WriteBytes(vaddr, data); err != nil {
					return nil, fmt.Errorf("write segment @ 0x%x: %w", vaddr, err)
				}
			}

			// Restore original permissions
			mem.MapRange(alignedStart, alignedSize, perms)

			end := vaddr + memsz
			if end > maxAddr {
				maxAddr = end
			}

			if phdr.Off == 0 {
				phdrAddr = vaddr + 64
			}

		case elf.PT_TLS:
			tlsVaddr = phdr.Vaddr
			tlsFilesz = phdr.Filesz
			tlsMemsz = phdr.Memsz
			tlsAlign = phdr.Align
			if tlsAlign == 0 {
				tlsAlign = 8
			}
		}
	}

	// Align brk to page boundary
	brkAddr := (maxAddr + mmu.PageSize - 1) & mmu.PageMask
	mem.SetBrk(brkAddr)

	// Allocate TLS area if PT_TLS was found
	var tlsBase uint64
	if tlsMemsz > 0 {
		// TLS layout: allocate tlsMemsz + alignment + TCB space.
		// RISC-V: TP points to beginning of TLS block.
		// x86_64: FS base points to end of TLS block (TCB at TP+0).
		tlsSize := (tlsMemsz + tlsAlign - 1) & ^(tlsAlign - 1)
		tlsBase = mem.Mmap(0, tlsSize+256, mmu.PermRead|mmu.PermWrite) // +256 for TCB
		// Copy initialized TLS data from the image
		if tlsFilesz > 0 {
			tlsData := make([]byte, tlsFilesz)
			f.Seek(0, io.SeekStart)
			// Re-read: find PT_TLS offset
			for _, phdr := range ef.Progs {
				if phdr.Type == elf.PT_TLS {
					f.Seek(int64(phdr.Off), io.SeekStart)
					io.ReadFull(f, tlsData)
					break
				}
			}
			mem.WriteBytes(tlsBase, tlsData)
		}
		_ = tlsVaddr // not needed beyond this point
	}

	// Set up the guest stack
	stackBottom := StackTop - DefaultStackSize
	mem.MapRange(stackBottom, DefaultStackSize, mmu.PermRead|mmu.PermWrite)

	// Generate 16 random bytes for AT_RANDOM
	randomAddr := StackTop - DefaultStackSize + 16
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	mem.MapRange(randomAddr&mmu.PageMask, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	mem.WriteBytes(randomAddr, randomBytes)

	auxvData := auxvInfo{
		entry:    ef.Entry,
		phdr:     phdrAddr,
		phent:    56,
		phnum:    uint64(len(ef.Progs)),
		pageSize: mmu.PageSize,
		random:   randomAddr,
	}

	sp, err := initStack(mem, StackTop, argv, envp, auxvData, guestArch)
	if err != nil {
		return nil, fmt.Errorf("init stack: %w", err)
	}

	return &LoadResult{
		EntryPoint: ef.Entry,
		StackPtr:   sp,
		BrkAddr:    brkAddr,
		TLSAddr:    tlsBase,
		Arch:       guestArch,
	}, nil
}

type auxvInfo struct {
	entry    uint64
	phdr     uint64
	phent    uint64
	phnum    uint64
	pageSize uint64
	random   uint64
}

// initStack writes argc, argv pointers, envp pointers, and auxv to the stack.
func initStack(mem *mmu.MMU, stackTop uint64, argv []string, envp []string, aux auxvInfo, guestArch arch.Arch) (uint64, error) {
	strArea := stackTop - 4096
	cursor := strArea
	argvPtrs := make([]uint64, len(argv))
	for i, s := range argv {
		argvPtrs[i] = cursor
		if err := mem.WriteBytes(cursor, append([]byte(s), 0)); err != nil {
			return 0, err
		}
		cursor += uint64(len(s)) + 1
	}
	envpPtrs := make([]uint64, len(envp))
	for i, s := range envp {
		envpPtrs[i] = cursor
		if err := mem.WriteBytes(cursor, append([]byte(s), 0)); err != nil {
			return 0, err
		}
		cursor += uint64(len(s)) + 1
	}

	// Platform string
	var platform string
	if guestArch == arch.ArchAMD64 {
		platform = "x86_64"
	} else {
		platform = "riscv"
	}
	platformStr := cursor
	if err := mem.WriteBytes(cursor, append([]byte(platform), 0)); err != nil {
		return 0, err
	}
	cursor += uint64(len(platform)) + 1

	type auxEntry struct{ tag, val uint64 }
	auxv := []auxEntry{
		{3, aux.phdr},       // AT_PHDR
		{4, aux.phent},      // AT_PHENT
		{5, aux.phnum},      // AT_PHNUM
		{6, aux.pageSize},   // AT_PAGESZ
		{7, 0},              // AT_BASE (no interpreter)
		{8, 0},              // AT_FLAGS
		{9, aux.entry},      // AT_ENTRY
		{11, 1000},          // AT_UID
		{12, 1000},          // AT_EUID
		{13, 1000},          // AT_GID
		{14, 1000},          // AT_EGID
		{15, platformStr},   // AT_PLATFORM
		{16, 0},             // AT_HWCAP
		{17, 100},           // AT_CLKTCK
		{23, 0},             // AT_SECURE
		{25, aux.random},    // AT_RANDOM
		{26, 0},             // AT_HWCAP2
		{0, 0},              // AT_NULL
	}

	nWords := 1 + // argc
		len(argv) + 1 + // argv ptrs + NULL
		len(envp) + 1 + // envp ptrs + NULL
		len(auxv)*2

	sp := strArea - uint64(nWords*8)
	sp &= ^uint64(0xF) // 16-byte align

	pos := sp
	write64 := func(v uint64) error {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, v)
		err := mem.WriteBytes(pos, buf)
		pos += 8
		return err
	}

	if err := write64(uint64(len(argv))); err != nil {
		return 0, err
	}
	for _, p := range argvPtrs {
		if err := write64(p); err != nil {
			return 0, err
		}
	}
	if err := write64(0); err != nil {
		return 0, err
	}
	for _, p := range envpPtrs {
		if err := write64(p); err != nil {
			return 0, err
		}
	}
	if err := write64(0); err != nil {
		return 0, err
	}
	for _, a := range auxv {
		if err := write64(a.tag); err != nil {
			return 0, err
		}
		if err := write64(a.val); err != nil {
			return 0, err
		}
	}

	return sp, nil
}
