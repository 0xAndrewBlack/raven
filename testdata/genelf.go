// Command genelf produces minimal static RISC-V 64-bit ELF test binaries.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	if err := generateHello("testdata/hello.rv64"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("wrote testdata/hello.rv64")

	if err := generateExit42("testdata/exit42.rv64"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("wrote testdata/exit42.rv64")
}

// --- ELF64 structures (little-endian, RISC-V) ---

const (
	ehdrSize = 64
	phdrSize = 56
)

func elfHeader(entry, phoff uint64, phnum int) []byte {
	buf := make([]byte, ehdrSize)

	// e_ident
	buf[0] = 0x7F
	buf[1] = 'E'
	buf[2] = 'L'
	buf[3] = 'F'
	buf[4] = 2  // ELFCLASS64
	buf[5] = 1  // ELFDATA2LSB
	buf[6] = 1  // EV_CURRENT
	buf[7] = 0  // ELFOSABI_NONE
	// pad 8 bytes

	binary.LittleEndian.PutUint16(buf[16:], 2)     // e_type = ET_EXEC
	binary.LittleEndian.PutUint16(buf[18:], 243)    // e_machine = EM_RISCV
	binary.LittleEndian.PutUint32(buf[20:], 1)      // e_version
	binary.LittleEndian.PutUint64(buf[24:], entry)   // e_entry
	binary.LittleEndian.PutUint64(buf[32:], phoff)   // e_phoff
	binary.LittleEndian.PutUint64(buf[40:], 0)       // e_shoff
	binary.LittleEndian.PutUint32(buf[48:], 0)       // e_flags
	binary.LittleEndian.PutUint16(buf[52:], ehdrSize) // e_ehsize
	binary.LittleEndian.PutUint16(buf[54:], phdrSize) // e_phentsize
	binary.LittleEndian.PutUint16(buf[56:], uint16(phnum)) // e_phnum
	binary.LittleEndian.PutUint16(buf[58:], 0)       // e_shentsize
	binary.LittleEndian.PutUint16(buf[60:], 0)       // e_shnum
	binary.LittleEndian.PutUint16(buf[62:], 0)       // e_shstrndx

	return buf
}

func progHeader(ptype uint32, flags uint32, offset, vaddr, filesz, memsz uint64) []byte {
	buf := make([]byte, phdrSize)
	binary.LittleEndian.PutUint32(buf[0:], ptype)    // p_type
	binary.LittleEndian.PutUint32(buf[4:], flags)    // p_flags
	binary.LittleEndian.PutUint64(buf[8:], offset)   // p_offset
	binary.LittleEndian.PutUint64(buf[16:], vaddr)   // p_vaddr
	binary.LittleEndian.PutUint64(buf[24:], vaddr)   // p_paddr
	binary.LittleEndian.PutUint64(buf[32:], filesz)  // p_filesz
	binary.LittleEndian.PutUint64(buf[40:], memsz)   // p_memsz
	binary.LittleEndian.PutUint64(buf[48:], 0x1000)  // p_align
	return buf
}

func u32le(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// ----- hello world binary -----
// Writes "Hello, Tech VM!\n" to stdout via write(1, msg, 16) then exit(0).
//
// RISC-V assembly:
//   _start:
//     li   a7, 64         # SYS_write
//     li   a0, 1          # fd = stdout
//     la   a1, msg        # buf (PC-relative via auipc+addi)
//     li   a2, 16         # count
//     ecall
//     li   a7, 93         # SYS_exit
//     li   a0, 0          # code = 0
//     ecall
//   msg:
//     .ascii "Hello, Tech VM!\n"

func generateHello(path string) error {
	const baseAddr = 0x10000
	const textOff = ehdrSize + phdrSize // code starts right after headers

	msg := []byte("Hello, Tech VM!\n")

	// Calculate message offset from _start
	// Instructions: 7 instructions × 4 bytes = 28 bytes
	// msg is at textOff + 28 relative to file, vaddr = baseAddr + textOff + 28
	nInstr := 7
	codeSize := nInstr * 4
	msgVaddr := baseAddr + uint64(textOff) + uint64(codeSize)
	entryVaddr := baseAddr + uint64(textOff)

	// auipc a1, delta_hi  ; addi a1, a1, delta_lo
	// delta = msgVaddr - PC_of_auipc  = codeSize - (2*4) ... relative to auipc at instruction #2
	// auipc is instruction index 2 (0-based), so PC_auipc = entryVaddr + 8
	delta := int64(msgVaddr) - int64(entryVaddr+8)
	deltaHi := ((delta + 0x800) >> 12) & 0xFFFFF
	deltaLo := delta - (deltaHi << 12)
	// Correct: deltaLo might need sign-extension adjustment
	if deltaLo < 0 {
		deltaLo = delta & 0xFFF
		if deltaLo >= 0x800 {
			deltaLo -= 0x1000
		}
	}

	code := [][]byte{
		u32le(0x04000893), // li a7, 64        (addi a7, x0, 64)
		u32le(0x00100513), // li a0, 1         (addi a0, x0, 1)
		u32le(encAUIPC(11, uint32(deltaHi))),        // auipc a1, deltaHi
		u32le(encADDI(11, 11, int32(deltaLo))),      // addi  a1, a1, deltaLo
		u32le(0x01000613), // li a2, 16        (addi a2, x0, 16)
		u32le(0x00000073), // ecall
		// now exit(0)
		// We re-use a7 for exit. But let's be explicit:
	}

	// After write ecall, add exit sequence
	codeExit := [][]byte{
		u32le(0x05D00893), // li a7, 93        (addi a7, x0, 93)
		u32le(0x00000513), // li a0, 0         (addi a0, x0, 0)
		u32le(0x00000073), // ecall
	}

	// Recalculate with 10 instructions total
	nInstr = len(code) + len(codeExit)
	codeSize = nInstr * 4
	msgVaddr = baseAddr + uint64(textOff) + uint64(codeSize)

	// Recalc delta for auipc (instruction index 2)
	delta = int64(msgVaddr) - int64(entryVaddr+8)
	deltaHi = ((delta + 0x800) >> 12) & 0xFFFFF
	deltaLo = delta - (deltaHi << 12)

	// Rebuild code with correct offsets
	var allCode []byte
	instrs := []uint32{
		0x04000893,                          // addi a7, x0, 64
		0x00100513,                          // addi a0, x0, 1
		encAUIPC(11, uint32(deltaHi)),       // auipc a1, deltaHi
		encADDI(11, 11, int32(deltaLo)),     // addi a1, a1, deltaLo
		uint32(len(msg))<<20 | 0x00000613,   // addi a2, x0, len(msg)  -- but encode properly
		0x00000073,                          // ecall
		0x05D00893,                          // addi a7, x0, 93
		0x00000513,                          // addi a0, x0, 0
		0x00000073,                          // ecall
	}

	// Fix a2 encoding: addi a2, x0, imm  = imm[11:0] | rs1(x0=0) | funct3(000) | rd(a2=x12) | opcode(0010011)
	// = (len(msg) << 20) | (0 << 15) | (0 << 12) | (12 << 7) | 0x13
	instrs[4] = (uint32(len(msg)) << 20) | (12 << 7) | 0x13

	for _, ins := range instrs {
		allCode = append(allCode, u32le(ins)...)
	}
	allCode = append(allCode, msg...)

	totalSegSize := uint64(len(allCode)) + uint64(textOff)
	phdr := progHeader(1, 5|2, 0, baseAddr, totalSegSize, totalSegSize) // PT_LOAD, PF_R|PF_W|PF_X
	ehdr := elfHeader(entryVaddr, ehdrSize, 1)

	var file []byte
	file = append(file, ehdr...)
	file = append(file, phdr...)
	file = append(file, allCode...)

	return os.WriteFile(path, file, 0755)
}

// ----- exit(42) binary -----
// Simply does exit(42) to test return code.

func generateExit42(path string) error {
	const baseAddr = 0x10000
	const textOff = ehdrSize + phdrSize
	entryVaddr := baseAddr + uint64(textOff)

	instrs := []uint32{
		0x05D00893, // addi a7, x0, 93    (SYS_exit)
		0x02A00513, // addi a0, x0, 42    (exit code)
		0x00000073, // ecall
	}

	var code []byte
	for _, ins := range instrs {
		code = append(code, u32le(ins)...)
	}

	totalSeg := uint64(textOff) + uint64(len(code))
	phdr := progHeader(1, 5|2, 0, baseAddr, totalSeg, totalSeg)
	ehdr := elfHeader(entryVaddr, ehdrSize, 1)

	var file []byte
	file = append(file, ehdr...)
	file = append(file, phdr...)
	file = append(file, code...)

	return os.WriteFile(path, file, 0755)
}

// encAUIPC encodes: auipc rd, imm20
// Format: imm[31:12] | rd | 0010111
func encAUIPC(rd int, imm20 uint32) uint32 {
	return (imm20 << 12) | (uint32(rd) << 7) | 0x17
}

// encADDI encodes: addi rd, rs1, imm12
// Format: imm[11:0] | rs1 | 000 | rd | 0010011
func encADDI(rd, rs1 int, imm12 int32) uint32 {
	return (uint32(imm12&0xFFF) << 20) | (uint32(rs1) << 15) | (uint32(rd) << 7) | 0x13
}
