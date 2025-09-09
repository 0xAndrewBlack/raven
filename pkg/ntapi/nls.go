package ntapi

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/mirkobrombin/go-vm/pkg/mmu"
)

// buildNlsCodePageData generates a minimal NLS code page table in the Windows
// binary format consumed by RtlInitCodePageTable. This is used when no sysroot
// .nls files are available.
//
// NLS file layout (USHORTs):
//
//	[0]     header size (13 for SBCS)
//	[1]     code page number
//	[2]     max char size (1=SBCS, 2=DBCS)
//	[3]     default char (typically '?')
//	[4]     unicode default char
//	[5]     trans default char
//	[6..11] lead byte pairs (all zero for SBCS)
//	[12]    unknown (0)
//	[13..268] MultiByte→WideChar table (256 entries)
//	[269]   glyph table size (256)
//	[270..525] glyph table (256 entries)
//	[526]   DBCS ranges end marker (0 = no DBCS)
//	[527..65536+527] WideChar→MultiByte table (65536 entries)
func buildNlsCodePageData(codePage uint16) []byte {
	const (
		headerWords = 13
		mbTableSize = 256
		glyphSize   = 256
		wc2mbSize   = 65536
	)

	totalWords := headerWords + 1 + mbTableSize + 1 + glyphSize + 1 + wc2mbSize
	data := make([]byte, totalWords*2)
	put16 := func(offset int, val uint16) {
		binary.LittleEndian.PutUint16(data[offset*2:], val)
	}

	// Header
	put16(0, headerWords) // header size
	put16(1, codePage)    // code page
	put16(2, 1)           // SBCS
	put16(3, '?')         // default char
	put16(4, '?')         // unicode default char
	put16(5, '?')         // trans default char
	// [6..11] = lead bytes = all zero (SBCS)
	// [12] = unknown = 0

	// MultiByte → WideChar table (identity for 0-255)
	mbBase := headerWords
	for i := 0; i < mbTableSize; i++ {
		put16(mbBase+1+i, cp1252ToUnicode(codePage, byte(i)))
	}

	// Glyph table
	glyphBase := mbBase + 1 + mbTableSize
	put16(glyphBase, glyphSize)
	for i := 0; i < glyphSize; i++ {
		put16(glyphBase+1+i, cp1252ToUnicode(codePage, byte(i)))
	}

	// DBCS ranges end marker (0 = no DBCS)
	dbcsEnd := glyphBase + 1 + glyphSize
	put16(dbcsEnd, 0)

	// WideChar → MultiByte table (reverse mapping)
	wc2mbBase := dbcsEnd + 1
	// Initialize all to default char '?'
	for i := 0; i < wc2mbSize; i++ {
		put16(wc2mbBase+i, '?')
	}
	// Fill reverse mapping
	for b := 0; b < 256; b++ {
		u := cp1252ToUnicode(codePage, byte(b))
		put16(wc2mbBase+int(u), uint16(b))
	}

	return data
}

// cp1252ToUnicode maps a byte to its Unicode codepoint for CP1252.
func cp1252ToUnicode(codePage uint16, b byte) uint16 {
	if b < 0x80 || b >= 0xA0 {
		return uint16(b) // identity for ASCII and 0xA0-0xFF
	}
	// CP1252 0x80-0x9F special mappings
	cp1252_80_9f := [32]uint16{
		0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
		0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
		0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
		0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
	}
	if codePage == 437 {
		cp437_80_9f := [32]uint16{
			0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7,
			0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
			0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
			0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
		}
		return cp437_80_9f[b-0x80]
	}
	return cp1252_80_9f[b-0x80]
}

// buildUnicodeCaseTable generates a minimal Unicode case mapping table.
func buildUnicodeCaseTable() []byte {
	const tableSize = 65536
	data := make([]byte, tableSize*2)
	put16 := func(offset int, val uint16) {
		binary.LittleEndian.PutUint16(data[offset*2:], val)
	}
	for i := 0; i < tableSize; i++ {
		val := uint16(i)
		if i >= 'a' && i <= 'z' {
			val = uint16(i - 0x20)
		}
		if i >= 0xE0 && i <= 0xFE && i != 0xF7 {
			val = uint16(i - 0x20)
		}
		put16(i, val)
	}
	return data
}

// InitNlsData pre-populates PEB NLS fields with valid code page data.
// This must be called after InitProcess but before DllMain execution.
func InitNlsData(mem *mmu.MMU, pebAddr uint64, sysRoot string) {
	var ansiData, oemData []byte

	// Try loading from sysroot first
	if sysRoot != "" {
		path := fmt.Sprintf("%s/c_1252.nls", sysRoot)
		if d, err := os.ReadFile(path); err == nil {
			ansiData = d
		}
		path = fmt.Sprintf("%s/c_437.nls", sysRoot)
		if d, err := os.ReadFile(path); err == nil {
			oemData = d
		}
	}

	// Fall back to synthetic tables
	if ansiData == nil {
		ansiData = buildNlsCodePageData(1252)
	}
	if oemData == nil {
		oemData = buildNlsCodePageData(437)
	}

	caseData := buildUnicodeCaseTable()

	// Map ANSI code page data
	ansiSize := (uint64(len(ansiData)) + mmu.PageSize - 1) & mmu.PageMask
	ansiAddr := mem.Mmap(0, ansiSize, mmu.PermRead|mmu.PermWrite)
	mem.WriteBytes(ansiAddr, ansiData)
	mem.Write64(pebAddr+PebAnsiCodePageData, ansiAddr)

	// Map OEM code page data
	oemSize := (uint64(len(oemData)) + mmu.PageSize - 1) & mmu.PageMask
	oemAddr := mem.Mmap(0, oemSize, mmu.PermRead|mmu.PermWrite)
	mem.WriteBytes(oemAddr, oemData)
	mem.Write64(pebAddr+PebOemCodePageData, oemAddr)

	// Map Unicode case table data
	caseSize := (uint64(len(caseData)) + mmu.PageSize - 1) & mmu.PageMask
	caseAddr := mem.Mmap(0, caseSize, mmu.PermRead|mmu.PermWrite)
	mem.WriteBytes(caseAddr, caseData)
	mem.Write64(pebAddr+PebUnicodeCaseTableData, caseAddr)
}

// BuildSortKeyData generates a minimal but valid sort key NLS section matching
// the format Wine's kernelbase load_sortdefault_nls() expects:
//
//	Header: { sortkeys_off, casemaps_off, ctypes_off, sortids_off } (4 × UINT32)
//	Sort keys: 65536 × UINT32 weights (indexed by Unicode codepoint)
//	Casemap: 65536 × UINT16
//	Ctypes: WORD count + WORD idx_offset + 2*256 WORD values + 256 BYTE index
//	Sort IDs: version + guid_count(1) + sortguid(40 bytes) +
//	           exp_count(0) + compr_count(1) + sort_compression(24 bytes) +
//	           compr_data padding + jamo padding
func BuildSortKeyData() []byte {
	const (
		headerSize   = 16
		numChars     = 65536
		sortKeysSize = numChars * 4
		casemapSize  = numChars * 2
		ctypeWords   = 2 + 256*3
		ctypeIdxSize = 256
		ctypeSize    = ctypeWords*2 + ctypeIdxSize
		sortGuidSize = 40
		sortCompSize = 24
	)

	sortKeysOff := uint32(headerSize)
	casemapOff := sortKeysOff + sortKeysSize
	ctypeOff := casemapOff + casemapSize
	sortidsOff := ctypeOff + uint32(ctypeSize)
	sortidsSize := uint32(4 + 4 + sortGuidSize + 4 + 4 + sortCompSize + 64 + 64)
	totalSize := sortidsOff + sortidsSize

	data := make([]byte, totalSize)
	le := binary.LittleEndian

	// Header
	le.PutUint32(data[0:], sortKeysOff)
	le.PutUint32(data[4:], casemapOff)
	le.PutUint32(data[8:], ctypeOff)
	le.PutUint32(data[12:], sortidsOff)

	// Sort keys: give each ASCII char a basic weight
	keys := data[sortKeysOff:]
	for i := 0; i < numChars; i++ {
		off := i * 4
		switch {
		case i >= 'A' && i <= 'Z':
			keys[off] = byte(2 + i - 'A')
			keys[off+1] = 14   // SCRIPT_LATIN
			keys[off+2] = 2    // diacritic
			keys[off+3] = 0x12 // CASE_UPPER | CASE_FULLSIZE
		case i >= 'a' && i <= 'z':
			keys[off] = byte(2 + i - 'a')
			keys[off+1] = 14
			keys[off+2] = 2
			keys[off+3] = 0x02 // CASE_FULLSIZE
		case i >= '0' && i <= '9':
			keys[off] = byte(2 + i - '0')
			keys[off+1] = 13 // SCRIPT_DIGIT
			keys[off+2] = 2
			keys[off+3] = 2
		case i == ' ':
			keys[off] = 7
			keys[off+1] = 6 // SCRIPT_PUNCTUATION
			keys[off+2] = 2
			keys[off+3] = 2
		case i > 0 && i < 128:
			keys[off] = byte(i)
			keys[off+1] = 6
			keys[off+2] = 2
			keys[off+3] = 2
		}
	}

	// Casemap: identity
	cm := data[casemapOff:]
	for i := 0; i < numChars; i++ {
		le.PutUint16(cm[i*2:], uint16(i))
	}

	// Ctypes section
	ct := data[ctypeOff:]
	le.PutUint16(ct[0:], uint16(256*3))
	ctypeIdxOff := uint16(ctypeWords * 2)
	le.PutUint16(ct[2:], ctypeIdxOff)
	for i := 0; i < 256; i++ {
		var c1 uint16
		switch {
		case i >= 'A' && i <= 'Z':
			c1 = 0x0101
		case i >= 'a' && i <= 'z':
			c1 = 0x0102
		case i >= '0' && i <= '9':
			c1 = 0x0004
		case i == ' ' || i == '\t' || i == '\n' || i == '\r':
			c1 = 0x0048
		case i < 0x20:
			c1 = 0x0020
		default:
			c1 = 0x0010
		}
		le.PutUint16(ct[4+i*2:], c1)
	}
	idx := ct[ctypeIdxOff:]
	for i := 0; i < 256 && int(ctypeIdxOff)+i < len(ct); i++ {
		idx[i] = byte(i)
	}

	// Sort IDs section
	sid := data[sortidsOff:]
	le.PutUint32(sid[0:], 1) // version
	le.PutUint32(sid[4:], 1) // guid_count = 1
	// sortguid[0]: flags/offsets all zero (default sort)
	guid := sid[8:]
	le.PutUint32(guid[0:], 0x00000001) // GUID data1

	expOff := 8 + sortGuidSize
	le.PutUint32(sid[expOff:], 0) // exp_count = 0

	comprOff := expOff + 4
	le.PutUint32(sid[comprOff:], 1) // compr_count = 1 (must be ≥1)
	// sort_compression[0] all zeroed - minimal entry

	// After compression: compr_data + multiple weights count
	mwOff := comprOff + 4 + sortCompSize
	le.PutUint32(sid[mwOff:], 0) // multiple weights count = 0
	// jamo table follows - zeroed

	return data
}
