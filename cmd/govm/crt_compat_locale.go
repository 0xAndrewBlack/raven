//go:build guest_windows

package main

import (
	"encoding/binary"
	"math"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

// These are the CRT DLLs in the checked-in Wine corpus that export this
// family. vcruntime DLLs do not export the public ctype/multibyte surface.
var crtLocaleModules = append([]string(nil), crtStringModules...)

type crtLocaleSemantic struct {
	name      string
	id        string
	signature string
	handler   ntapi.TrapHandler
}

var crtLocaleSemantics = []crtLocaleSemantic{
	{name: "isalpha", id: "crt.locale.isalpha.v1", signature: "cdecl(long)", handler: crtIsalpha},
	{name: "isdigit", id: "crt.locale.isdigit.v1", signature: "cdecl(long)", handler: crtIsdigit},
	{name: "isalnum", id: "crt.locale.isalnum.v1", signature: "cdecl(long)", handler: crtIsalnum},
	{name: "isspace", id: "crt.locale.isspace.v1", signature: "cdecl(long)", handler: crtIsspace},
	{name: "ispunct", id: "crt.locale.ispunct.v1", signature: "cdecl(long)", handler: crtIspunct},
	{name: "isprint", id: "crt.locale.isprint.v1", signature: "cdecl(long)", handler: crtIsprint},
	{name: "isgraph", id: "crt.locale.isgraph.v1", signature: "cdecl(long)", handler: crtIsgraph},
	{name: "iscntrl", id: "crt.locale.iscntrl.v1", signature: "cdecl(long)", handler: crtIscntrl},
	{name: "isupper", id: "crt.locale.isupper.v1", signature: "cdecl(long)", handler: crtIsupper},
	{name: "islower", id: "crt.locale.islower.v1", signature: "cdecl(long)", handler: crtIslower},
	{name: "toupper", id: "crt.locale.toupper.v1", signature: "cdecl(long)", handler: crtToupper},
	{name: "tolower", id: "crt.locale.tolower.v1", signature: "cdecl(long)", handler: crtTolower},
	{name: "_toupper", id: "crt.locale.underscore.toupper.v1", signature: "cdecl(long)", handler: crtToupper},
	{name: "_tolower", id: "crt.locale.underscore.tolower.v1", signature: "cdecl(long)", handler: crtTolower},
	{name: "_isctype", id: "crt.locale.underscore.isctype.v1", signature: "cdecl(long long)", handler: crtIsctype},
	{name: "mblen", id: "crt.locale.mblen.codepage.v2", signature: "cdecl(ptr long)", handler: crtMblen},
	{name: "mbtowc", id: "crt.locale.mbtowc.codepage.v2", signature: "cdecl(ptr str long)", handler: crtMbtowc},
	{name: "wctomb", id: "crt.locale.wctomb.codepage.v2", signature: "cdecl(ptr long)", handler: crtWctomb},
	{name: "mbstowcs", id: "crt.locale.mbstowcs.codepage.v2", signature: "cdecl(ptr str long)", handler: crtMbstowcs},
	{name: "wcstombs", id: "crt.locale.wcstombs.codepage.v2", signature: "cdecl(ptr ptr long)", handler: crtWcstombs},
	{name: "setlocale", id: "crt.locale.setlocale.windows.v2", signature: "cdecl(long str)", handler: crtSetlocale},
	{name: "_setmbcp", id: "crt.locale.setmbcp.codepage.v2", signature: "cdecl(long)", handler: crtSetmbcp},
}

func init() {
	registerCRTProvider(registerCRTLocaleDefinitions)
	for _, semantic := range crtLocaleSemantics {
		registerCRTLocaleContractCases(semantic)
	}
}

func registerCRTLocaleDefinitions(registry *crtSemanticRegistry) {
	for _, semantic := range crtLocaleSemantics {
		registry.Define(crtSemanticDefinition{
			ExportName:       semantic.name,
			ImplementationID: semantic.id,
			Signature:        semantic.signature,
			ContractCaseID:   semantic.id + ".contract",
			AllowedModules:   append([]string(nil), crtLocaleModules...),
			AllowedArch:      []string{"i386", "win64"},
			Handler:          semantic.handler,
		})
	}
}

const (
	crtCTypeUpper   uint32 = 0x0001
	crtCTypeLower   uint32 = 0x0002
	crtCTypeDigit   uint32 = 0x0004
	crtCTypeSpace   uint32 = 0x0008
	crtCTypePunct   uint32 = 0x0010
	crtCTypeControl uint32 = 0x0020
	crtCTypeBlank   uint32 = 0x0040
	crtCTypeHex     uint32 = 0x0080
	crtCTypeAlpha   uint32 = 0x0100
)

func crtCTypeClass(value byte) uint32 {
	var class uint32
	switch {
	case value >= 'A' && value <= 'Z':
		class |= crtCTypeUpper | crtCTypeAlpha
	case value >= 'a' && value <= 'z':
		class |= crtCTypeLower | crtCTypeAlpha
	case value >= '0' && value <= '9':
		class |= crtCTypeDigit
	}
	if value >= '0' && value <= '9' || value >= 'A' && value <= 'F' || value >= 'a' && value <= 'f' {
		class |= crtCTypeHex
	}
	if value == ' ' || value == '\t' {
		class |= crtCTypeBlank
	}
	if value == ' ' || value >= '\t' && value <= '\r' {
		class |= crtCTypeSpace
	}
	if value < 0x20 || value == 0x7f {
		class |= crtCTypeControl
	}
	if value >= 0x20 && value <= 0x7e {
		class |= crtCTypePrint
		if class&(crtCTypeAlpha|crtCTypeDigit) == 0 {
			class |= crtCTypePunct
		}
	}
	return class
}

const crtCTypePrint uint32 = 0x0200

func crtCTypeInput(value uint64) (byte, bool, bool) {
	if value == math.MaxUint64 || uint32(value) == math.MaxUint32 {
		return 0, false, true
	}
	if value <= 0xff {
		return byte(value), true, false
	}
	return 0, false, false
}

func crtCTypeBoolean(ctx *ntapi.TrapContext, mask uint32) uint32 {
	value, valid, eof := crtCTypeInput(ctx.Arg(0))
	if !valid || eof {
		ctx.SetReturn(0)
		return 0
	}
	if crtCTypeClass(value)&mask != 0 {
		ctx.SetReturn(1)
	} else {
		ctx.SetReturn(0)
	}
	return 0
}

func crtIsalpha(ctx *ntapi.TrapContext) uint32 { return crtCTypeBoolean(ctx, crtCTypeAlpha) }
func crtIsdigit(ctx *ntapi.TrapContext) uint32 { return crtCTypeBoolean(ctx, crtCTypeDigit) }
func crtIsalnum(ctx *ntapi.TrapContext) uint32 {
	return crtCTypeBoolean(ctx, crtCTypeAlpha|crtCTypeDigit)
}
func crtIsspace(ctx *ntapi.TrapContext) uint32 { return crtCTypeBoolean(ctx, crtCTypeSpace) }
func crtIspunct(ctx *ntapi.TrapContext) uint32 { return crtCTypeBoolean(ctx, crtCTypePunct) }
func crtIsprint(ctx *ntapi.TrapContext) uint32 { return crtCTypeBoolean(ctx, crtCTypePrint) }
func crtIsgraph(ctx *ntapi.TrapContext) uint32 {
	value, valid, eof := crtCTypeInput(ctx.Arg(0))
	if !valid || eof {
		ctx.SetReturn(0)
		return 0
	}
	if value >= 0x21 && value <= 0x7e {
		ctx.SetReturn(1)
	} else {
		ctx.SetReturn(0)
	}
	return 0
}
func crtIscntrl(ctx *ntapi.TrapContext) uint32 { return crtCTypeBoolean(ctx, crtCTypeControl) }
func crtIsupper(ctx *ntapi.TrapContext) uint32 { return crtCTypeBoolean(ctx, crtCTypeUpper) }
func crtIslower(ctx *ntapi.TrapContext) uint32 { return crtCTypeBoolean(ctx, crtCTypeLower) }

func crtCaseConvert(ctx *ntapi.TrapContext, upper bool) uint32 {
	input := ctx.Arg(0)
	value, valid, eof := crtCTypeInput(input)
	if eof {
		ctx.SetReturn(uint64(uint32(math.MaxUint32)))
		return 0
	}
	if !valid {
		ctx.SetReturn(uint64(uint32(input)))
		return 0
	}
	if upper && value >= 'a' && value <= 'z' {
		value -= 'a' - 'A'
	}
	if !upper && value >= 'A' && value <= 'Z' {
		value += 'a' - 'A'
	}
	ctx.SetReturn(uint64(value))
	return 0
}

func crtToupper(ctx *ntapi.TrapContext) uint32 { return crtCaseConvert(ctx, true) }
func crtTolower(ctx *ntapi.TrapContext) uint32 { return crtCaseConvert(ctx, false) }

func crtIsctype(ctx *ntapi.TrapContext) uint32 {
	value, valid, eof := crtCTypeInput(ctx.Arg(0))
	if !valid || eof {
		ctx.SetReturn(0)
		return 0
	}
	ctx.SetReturn(uint64(crtCTypeClass(value) & uint32(ctx.Arg(1))))
	return 0
}

type crtLocaleRuntimeKey struct {
	state *ntapi.ProcessState
	mem   *mmu.MMU
}

type crtLocaleRuntime struct {
	mu              sync.Mutex
	name            string
	codePage        uint32
	localeAddresses map[string]uint64
}

var crtLocaleRuntimes = struct {
	sync.Mutex
	values map[crtLocaleRuntimeKey]*crtLocaleRuntime
}{values: make(map[crtLocaleRuntimeKey]*crtLocaleRuntime)}

func crtLocaleRuntimeFor(ctx *ntapi.TrapContext) *crtLocaleRuntime {
	key := crtLocaleRuntimeKey{mem: ctx.Mem}
	if ctx.State != nil {
		key.state = ctx.State
	}
	crtLocaleRuntimes.Lock()
	defer crtLocaleRuntimes.Unlock()
	if runtime := crtLocaleRuntimes.values[key]; runtime != nil {
		return runtime
	}
	runtime := &crtLocaleRuntime{
		name:            "C",
		codePage:        20127,
		localeAddresses: make(map[string]uint64),
	}
	crtLocaleRuntimes.values[key] = runtime
	return runtime
}

func crtLocaleAddress(ctx *ntapi.TrapContext, runtime *crtLocaleRuntime, name string) (uint64, bool) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if address := runtime.localeAddresses[name]; address != 0 {
		return address, true
	}
	address := ctx.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if address == 0 {
		return 0, false
	}
	data := append([]byte(name), 0)
	if err := ctx.Mem.WriteBytes(address, data); err != nil {
		return 0, false
	}
	runtime.localeAddresses[name] = address
	return address, true
}

func crtSetlocale(ctx *ntapi.TrapContext) uint32 {
	category := ctx.Arg(0)
	if category > 5 {
		ctx.SetReturn(0)
		return 0
	}
	runtime := crtLocaleRuntimeFor(ctx)
	if localeAddress := ctx.Arg(1); localeAddress != 0 {
		value, ok := crtReadNarrowString(ctx.Mem, localeAddress)
		if !ok {
			return crtMemoryAccessFailure(ctx)
		}
		name, codePage, supported := crtResolveLocaleName(string(value))
		if !supported {
			ctx.SetReturn(0)
			return 0
		}
		runtime.mu.Lock()
		runtime.name = name
		runtime.codePage = codePage
		runtime.mu.Unlock()
	}
	runtime.mu.Lock()
	name := runtime.name
	runtime.mu.Unlock()
	address, ok := crtLocaleAddress(ctx, runtime, name)
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(address)
	return 0
}

func crtResolveLocaleName(value string) (string, uint32, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "c", "posix":
		return "C", 20127, true
	case "":
		return "English_United States.1252", 1252, true
	case ".1252", "en-us", "en_us", "english", "english_united states", "english_united states.1252":
		return "English_United States.1252", 1252, true
	case "fr-fr", "fr_fr", "french", "french_france", "french_france.1252":
		return "French_France.1252", 1252, true
	case "de-de", "de_de", "german", "german_germany", "german_germany.1252":
		return "German_Germany.1252", 1252, true
	case ".utf8", ".utf-8", "c.utf8", "c.utf-8", "utf8", "utf-8", "en-us.utf8", "en_us.utf-8", "english_united states.65001":
		return "English_United States.65001", 65001, true
	default:
		return "", 0, false
	}
}

func crtSetmbcp(ctx *ntapi.TrapContext) uint32 {
	codePage := uint32(ctx.Arg(0))
	switch codePage {
	case 0:
		codePage = 20127
	case 1252, 65001:
	default:
		crtWriteErrno(ctx, 22)
		ctx.SetReturn(uint64(uint32(math.MaxUint32)))
		return 0
	}
	runtime := crtLocaleRuntimeFor(ctx)
	runtime.mu.Lock()
	runtime.codePage = codePage
	runtime.mu.Unlock()
	ctx.SetReturn(0)
	return 0
}

type crtUTF8DecodeResult uint8

const (
	crtUTF8Valid crtUTF8DecodeResult = iota
	crtUTF8Invalid
	crtUTF8Incomplete
	crtUTF8MemoryFault
)

func crtDecodeUTF8(mem *mmu.MMU, address, limit uint64) (rune, int, crtUTF8DecodeResult) {
	if limit == 0 {
		return 0, 0, crtUTF8Incomplete
	}
	first, err := mem.Read8(address)
	if err != nil {
		return 0, 0, crtUTF8MemoryFault
	}
	if first == 0 {
		return 0, 1, crtUTF8Valid
	}
	width := 0
	switch {
	case first < 0x80:
		width = 1
	case first >= 0xc2 && first <= 0xdf:
		width = 2
	case first >= 0xe0 && first <= 0xef:
		width = 3
	case first >= 0xf0 && first <= 0xf4:
		width = 4
	default:
		return 0, 0, crtUTF8Invalid
	}
	if limit < uint64(width) {
		return 0, 0, crtUTF8Incomplete
	}
	var data [4]byte
	data[0] = first
	for index := 1; index < width; index++ {
		value, err := mem.Read8(address + uint64(index))
		if err != nil {
			return 0, 0, crtUTF8MemoryFault
		}
		data[index] = value
	}
	if !utf8.Valid(data[:width]) {
		return 0, 0, crtUTF8Invalid
	}
	value, size := utf8.DecodeRune(data[:width])
	if size != width || value == utf8.RuneError && width == 1 || value >= 0xd800 && value <= 0xdfff {
		return 0, 0, crtUTF8Invalid
	}
	return value, width, crtUTF8Valid
}

var crtCP1252High = [32]rune{
	0x20ac, 0x0081, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021,
	0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008d, 0x017d, 0x008f,
	0x0090, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
	0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x009d, 0x017e, 0x0178,
}

func crtLocaleCodePage(ctx *ntapi.TrapContext) uint32 {
	runtime := crtLocaleRuntimeFor(ctx)
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.codePage
}

func crtDecodeMultibyte(ctx *ntapi.TrapContext, address, limit uint64) (rune, int, crtUTF8DecodeResult) {
	if crtLocaleCodePage(ctx) == 65001 {
		return crtDecodeUTF8(ctx.Mem, address, limit)
	}
	if limit == 0 {
		return 0, 0, crtUTF8Incomplete
	}
	value, err := ctx.Mem.Read8(address)
	if err != nil {
		return 0, 0, crtUTF8MemoryFault
	}
	switch crtLocaleCodePage(ctx) {
	case 20127:
		if value > 0x7f {
			return 0, 0, crtUTF8Invalid
		}
		return rune(value), 1, crtUTF8Valid
	case 1252:
		if value >= 0x80 && value <= 0x9f {
			return crtCP1252High[value-0x80], 1, crtUTF8Valid
		}
		return rune(value), 1, crtUTF8Valid
	default:
		return 0, 0, crtUTF8Invalid
	}
}

func crtEncodeMultibyte(codePage uint32, value rune) ([]byte, bool) {
	switch codePage {
	case 20127:
		if value < 0 || value > 0x7f {
			return nil, false
		}
		return []byte{byte(value)}, true
	case 1252:
		if value >= 0 && value <= 0x7f || value >= 0xa0 && value <= 0xff {
			return []byte{byte(value)}, true
		}
		for index, candidate := range crtCP1252High {
			if candidate == value {
				return []byte{byte(0x80 + index)}, true
			}
		}
		return nil, false
	case 65001:
		if !utf8.ValidRune(value) || value >= 0xd800 && value <= 0xdfff {
			return nil, false
		}
		var encoded [utf8.UTFMax]byte
		width := utf8.EncodeRune(encoded[:], value)
		return append([]byte(nil), encoded[:width]...), true
	default:
		return nil, false
	}
}

func crtDecodeMultibyteString(value []byte, codePage uint32) ([]rune, bool) {
	if codePage == 65001 {
		if !utf8.Valid(value) {
			return nil, false
		}
		return []rune(string(value)), true
	}
	result := make([]rune, 0, len(value))
	for _, current := range value {
		switch codePage {
		case 20127:
			if current > 0x7f {
				return nil, false
			}
			result = append(result, rune(current))
		case 1252:
			if current >= 0x80 && current <= 0x9f {
				result = append(result, crtCP1252High[current-0x80])
			} else {
				result = append(result, rune(current))
			}
		default:
			return nil, false
		}
	}
	return result, true
}

func crtUTF16Runes(value []uint16) ([]rune, bool) {
	result := make([]rune, 0, len(value))
	for index := 0; index < len(value); index++ {
		unit := value[index]
		if unit >= 0xd800 && unit <= 0xdbff {
			if index+1 >= len(value) || value[index+1] < 0xdc00 || value[index+1] > 0xdfff {
				return nil, false
			}
			result = append(result, 0x10000+(rune(unit)-0xd800)*0x400+rune(value[index+1]-0xdc00))
			index++
			continue
		}
		if unit >= 0xdc00 && unit <= 0xdfff {
			return nil, false
		}
		result = append(result, rune(unit))
	}
	return result, true
}

func crtLocaleConversionFailure(ctx *ntapi.TrapContext, countResult bool) uint32 {
	if !crtWriteErrno(ctx, 42) {
		return crtMemoryAccessFailure(ctx)
	}
	if countResult {
		return crtSetCountResult(ctx, 0, true)
	}
	return crtSetIntResult(ctx, -1)
}

func crtSetIntResult(ctx *ntapi.TrapContext, value int32) uint32 {
	ctx.SetReturn(uint64(uint32(value)))
	return 0
}

func crtSetCountResult(ctx *ntapi.TrapContext, value uint64, invalid bool) uint32 {
	if invalid {
		if ctx.CPU.GetArch() == arch.ArchI386 {
			ctx.SetReturn(uint64(uint32(math.MaxUint32)))
		} else {
			ctx.SetReturn(math.MaxUint64)
		}
		return 0
	}
	ctx.SetReturn(value)
	return 0
}

func crtMblen(ctx *ntapi.TrapContext) uint32 {
	address, limit := ctx.Arg(0), ctx.Arg(1)
	if address == 0 {
		return crtSetIntResult(ctx, 0)
	}
	value, size, result := crtDecodeMultibyte(ctx, address, limit)
	switch result {
	case crtUTF8MemoryFault:
		return crtMemoryAccessFailure(ctx)
	case crtUTF8Valid:
		if value == 0 {
			return crtSetIntResult(ctx, 0)
		}
		return crtSetIntResult(ctx, int32(size))
	default:
		return crtLocaleConversionFailure(ctx, false)
	}
}

func crtMbtowc(ctx *ntapi.TrapContext) uint32 {
	destination, source, limit := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
	if source == 0 {
		return crtSetIntResult(ctx, 0)
	}
	value, size, result := crtDecodeMultibyte(ctx, source, limit)
	if result == crtUTF8MemoryFault {
		return crtMemoryAccessFailure(ctx)
	}
	if result != crtUTF8Valid || value > 0xffff {
		return crtLocaleConversionFailure(ctx, false)
	}
	if destination != 0 {
		if !crtMemoryRange(ctx.Mem, destination, 2, mmu.PermWrite) || ctx.Mem.Write16(destination, uint16(value)) != nil {
			return crtMemoryAccessFailure(ctx)
		}
	}
	if value == 0 {
		return crtSetIntResult(ctx, 0)
	}
	return crtSetIntResult(ctx, int32(size))
}

func crtWctomb(ctx *ntapi.TrapContext) uint32 {
	destination, value := ctx.Arg(0), uint32(ctx.Arg(1))
	if destination == 0 {
		return crtSetIntResult(ctx, 0)
	}
	if value > 0xffff || value >= 0xd800 && value <= 0xdfff {
		return crtLocaleConversionFailure(ctx, false)
	}
	encoded, ok := crtEncodeMultibyte(crtLocaleCodePage(ctx), rune(value))
	if !ok {
		return crtLocaleConversionFailure(ctx, false)
	}
	if !crtMemoryRange(ctx.Mem, destination, uint64(len(encoded)), mmu.PermWrite) || ctx.Mem.WriteBytes(destination, encoded) != nil {
		return crtMemoryAccessFailure(ctx)
	}
	return crtSetIntResult(ctx, int32(len(encoded)))
}

func crtWriteUTF16Units(mem *mmu.MMU, address uint64, units []uint16) bool {
	if len(units) == 0 {
		return true
	}
	data := make([]byte, len(units)*2)
	for index, value := range units {
		binary.LittleEndian.PutUint16(data[index*2:], value)
	}
	return crtMemoryRange(mem, address, uint64(len(data)), mmu.PermWrite) && mem.WriteBytes(address, data) == nil
}

func crtMbstowcs(ctx *ntapi.TrapContext) uint32 {
	destination, source, limit := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
	if source == 0 {
		return crtMemoryAccessFailure(ctx)
	}
	if destination == 0 {
		value, ok := crtReadNarrowString(ctx.Mem, source)
		if !ok {
			return crtMemoryAccessFailure(ctx)
		}
		runes, ok := crtDecodeMultibyteString(value, crtLocaleCodePage(ctx))
		if !ok {
			return crtLocaleConversionFailure(ctx, true)
		}
		required := uint64(0)
		for _, runeValue := range runes {
			required++
			if runeValue > 0xffff {
				required++
			}
		}
		return crtSetCountResult(ctx, required, false)
	}
	capacity := 256
	if limit < uint64(capacity) {
		capacity = int(limit)
	}
	units := make([]uint16, 0, capacity)
	offset := uint64(0)
	for uint64(len(units)) < limit {
		current := source + offset
		if current < source {
			return crtMemoryAccessFailure(ctx)
		}
		runeValue, width, result := crtDecodeMultibyte(ctx, current, 4)
		if result == crtUTF8MemoryFault {
			return crtMemoryAccessFailure(ctx)
		}
		if result != crtUTF8Valid {
			return crtLocaleConversionFailure(ctx, true)
		}
		if runeValue == 0 {
			units = append(units, 0)
			break
		}
		if runeValue <= 0xffff {
			units = append(units, uint16(runeValue))
		} else {
			if uint64(len(units)+2) > limit {
				break
			}
			runeValue -= 0x10000
			units = append(units, uint16(0xd800+(runeValue>>10)), uint16(0xdc00+(runeValue&0x3ff)))
		}
		offset += uint64(width)
	}
	result := uint64(len(units))
	if result > 0 && units[len(units)-1] == 0 {
		result--
	}
	if len(units) > 0 {
		if !crtWriteUTF16Units(ctx.Mem, destination, units) {
			return crtMemoryAccessFailure(ctx)
		}
	}
	return crtSetCountResult(ctx, result, false)
}

func crtWcstombs(ctx *ntapi.TrapContext) uint32 {
	destination, source, limit := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
	if source == 0 {
		return crtMemoryAccessFailure(ctx)
	}
	codePage := crtLocaleCodePage(ctx)
	if destination == 0 {
		units, ok := crtReadWideString(ctx.Mem, source)
		if !ok {
			return crtMemoryAccessFailure(ctx)
		}
		runes, ok := crtUTF16Runes(units)
		if !ok {
			return crtLocaleConversionFailure(ctx, true)
		}
		required := uint64(0)
		for _, runeValue := range runes {
			value, valid := crtEncodeMultibyte(codePage, runeValue)
			if !valid {
				return crtLocaleConversionFailure(ctx, true)
			}
			required += uint64(len(value))
		}
		return crtSetCountResult(ctx, required, false)
	}
	capacity := 256
	if limit < uint64(capacity) {
		capacity = int(limit)
	}
	value := make([]byte, 0, capacity)
	offset := uint64(0)
	for uint64(len(value)) < limit {
		current := source + offset*2
		if current < source {
			return crtMemoryAccessFailure(ctx)
		}
		first, err := ctx.Mem.Read16(current)
		if err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		if first == 0 {
			value = append(value, 0)
			break
		}
		runeValue := rune(first)
		width := uint64(1)
		if first >= 0xd800 && first <= 0xdbff {
			secondAddress := current + 2
			if secondAddress < current {
				return crtMemoryAccessFailure(ctx)
			}
			second, readErr := ctx.Mem.Read16(secondAddress)
			if readErr != nil {
				return crtMemoryAccessFailure(ctx)
			}
			if second < 0xdc00 || second > 0xdfff {
				return crtLocaleConversionFailure(ctx, true)
			}
			runeValue = 0x10000 + (rune(first)-0xd800)*0x400 + rune(second-0xdc00)
			width = 2
		} else if first >= 0xdc00 && first <= 0xdfff {
			return crtLocaleConversionFailure(ctx, true)
		}
		encoded, valid := crtEncodeMultibyte(codePage, runeValue)
		if !valid {
			return crtLocaleConversionFailure(ctx, true)
		}
		if uint64(len(value)+len(encoded)) > limit {
			break
		}
		value = append(value, encoded...)
		offset += width
	}
	result := uint64(len(value))
	if result > 0 && value[len(value)-1] == 0 {
		result--
	}
	if len(value) > 0 {
		if !crtMemoryRange(ctx.Mem, destination, uint64(len(value)), mmu.PermWrite) || ctx.Mem.WriteBytes(destination, value) != nil {
			return crtMemoryAccessFailure(ctx)
		}
	}
	return crtSetCountResult(ctx, result, false)
}

func registerCRTLocaleContractCases(semantic crtLocaleSemantic) {
	for _, module := range crtLocaleModules {
		for _, architecture := range []string{"i386", "win64"} {
			semantic := semantic
			registerCRTContractCase(crtContractCase{
				CaseID:           semantic.id + ".contract",
				Module:           module,
				ExportName:       semantic.name,
				Architecture:     architecture,
				ImplementationID: semantic.id,
				Signature:        semantic.signature,
				Exercise: func(invocation *crtContractInvocation) {
					exerciseCRTLocaleContract(invocation, semantic.name)
				},
			})
		}
	}
}

func exerciseCRTLocaleContract(invocation *crtContractInvocation, name string) {
	allocate := func(value []byte) (uint64, bool) {
		address := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
		if address == 0 {
			invocation.Failf("locale contract allocation failed")
			return 0, false
		}
		if err := invocation.Mem.WriteBytes(address, value); err != nil {
			invocation.Failf("write locale contract input: %v", err)
			return 0, false
		}
		return address, true
	}
	call := func(watches []crtContractMemoryWatch, args ...uint64) (crtContractResult, bool) {
		result, err := invocation.CallWatching(watches, args...)
		if err != nil {
			invocation.Failf("dispatch locale contract: %v", err)
			return crtContractResult{}, false
		}
		return result, true
	}
	callEILSEQ := func(args ...uint64) (crtContractResult, bool) {
		errnoContext := &ntapi.TrapContext{Mem: invocation.Mem}
		if !crtWriteErrno(errnoContext, 0) {
			invocation.Failf("initialize locale contract errno")
			return crtContractResult{}, false
		}
		errnoAddress := crtErrnoAddress(errnoContext)
		result, ok := call([]crtContractMemoryWatch{{Address: errnoAddress, Size: 4}}, args...)
		if !ok {
			return crtContractResult{}, false
		}
		result.ExpectMemory(0, []byte{42, 0, 0, 0})
		return result, true
	}
	switch name {
	case "isalpha", "isdigit", "isalnum", "isspace", "ispunct", "isprint", "isgraph", "iscntrl", "isupper", "islower":
		scenarios := map[string]struct {
			inputs  [2]uint64
			outputs [2]uint64
		}{
			"isalpha": {inputs: [2]uint64{'A', '7'}, outputs: [2]uint64{1, 0}},
			"isdigit": {inputs: [2]uint64{'7', 'A'}, outputs: [2]uint64{1, 0}},
			"isalnum": {inputs: [2]uint64{'7', '#'}, outputs: [2]uint64{1, 0}},
			"isspace": {inputs: [2]uint64{'\t', 'A'}, outputs: [2]uint64{1, 0}},
			"ispunct": {inputs: [2]uint64{'!', 'A'}, outputs: [2]uint64{1, 0}},
			"isprint": {inputs: [2]uint64{' ', '\n'}, outputs: [2]uint64{1, 0}},
			"isgraph": {inputs: [2]uint64{'!', ' '}, outputs: [2]uint64{1, 0}},
			"iscntrl": {inputs: [2]uint64{'\n', 'A'}, outputs: [2]uint64{1, 0}},
			"isupper": {inputs: [2]uint64{'Q', 'q'}, outputs: [2]uint64{1, 0}},
			"islower": {inputs: [2]uint64{'q', 'Q'}, outputs: [2]uint64{1, 0}},
		}
		scenario := scenarios[name]
		for index, input := range scenario.inputs {
			result, ok := call(nil, input)
			if !ok {
				return
			}
			result.ExpectReturn(scenario.outputs[index])
		}
	case "toupper", "_toupper", "tolower", "_tolower":
		inputs, outputs := [2]uint64{'q', '7'}, [2]uint64{'Q', '7'}
		if name == "tolower" || name == "_tolower" {
			inputs, outputs = [2]uint64{'Q', '7'}, [2]uint64{'q', '7'}
		}
		for index, input := range inputs {
			result, ok := call(nil, input)
			if !ok {
				return
			}
			result.ExpectReturn(outputs[index])
		}
	case "_isctype":
		inputs := [2][2]uint64{
			{'A', uint64(crtCTypeAlpha | crtCTypeUpper)},
			{'7', uint64(crtCTypeDigit)},
		}
		outputs := [2]uint64{
			uint64(crtCTypeAlpha | crtCTypeUpper),
			uint64(crtCTypeDigit),
		}
		for index, input := range inputs {
			result, ok := call(nil, input[0], input[1])
			if !ok {
				return
			}
			result.ExpectReturn(outputs[index])
		}
	case "mblen":
		values := [][]byte{{'A', 0}, {0}}
		limits := [2]uint64{1, 1}
		outputs := [2]uint64{1, 0}
		for index, value := range values {
			source, ok := allocate(value)
			if !ok {
				return
			}
			result, ok := call([]crtContractMemoryWatch{{Address: source, Size: len(value)}}, source, limits[index])
			if !ok {
				return
			}
			result.ExpectReturn(outputs[index])
		}
		if !crtLocaleContractSetCodePage(invocation, 20127) {
			return
		}
		source, ok := allocate([]byte{0x80, 0})
		if !ok {
			return
		}
		result, ok := callEILSEQ(source, 1)
		if !ok {
			return
		}
		result.ExpectReturn(uint64(math.MaxUint32))
	case "mbtowc":
		values := [][]byte{{'A', 0}, {0x80, 0}}
		limits := [2]uint64{1, 1}
		outputs := [2]uint64{1, 1}
		units := [2]uint16{'A', 0x20ac}
		for index, value := range values {
			if index == 1 && !crtLocaleContractSetCodePage(invocation, 1252) {
				return
			}
			source, ok := allocate(value)
			if !ok {
				return
			}
			destination, ok := allocate([]byte{0xcc, 0xcc})
			if !ok {
				return
			}
			expected := make([]byte, 2)
			binary.LittleEndian.PutUint16(expected, units[index])
			result, ok := call([]crtContractMemoryWatch{{Address: destination, Size: 2}}, destination, source, limits[index])
			if !ok {
				return
			}
			result.ExpectReturn(outputs[index])
			result.ExpectMemory(0, expected)
		}
		if !crtLocaleContractSetCodePage(invocation, 20127) {
			return
		}
		source, ok := allocate([]byte{0x80, 0})
		if !ok {
			return
		}
		destination, ok := allocate([]byte{0xcc, 0xcc})
		if !ok {
			return
		}
		result, ok := callEILSEQ(destination, source, 1)
		if !ok {
			return
		}
		result.ExpectReturn(uint64(math.MaxUint32))
	case "wctomb":
		values := [2]uint64{'A', 0x20ac}
		outputs := [][]byte{{'A'}, {0x80}}
		for index, value := range values {
			if index == 1 && !crtLocaleContractSetCodePage(invocation, 1252) {
				return
			}
			destination, ok := allocate([]byte{0xcc, 0xcc, 0xcc, 0xcc})
			if !ok {
				return
			}
			result, ok := call([]crtContractMemoryWatch{{Address: destination, Size: len(outputs[index])}}, destination, value)
			if !ok {
				return
			}
			result.ExpectReturn(uint64(len(outputs[index])))
			result.ExpectMemory(0, outputs[index])
		}
		if !crtLocaleContractSetCodePage(invocation, 20127) {
			return
		}
		destination, ok := allocate([]byte{0xcc, 0xcc, 0xcc})
		if !ok {
			return
		}
		result, ok := callEILSEQ(destination, 0x20ac)
		if !ok {
			return
		}
		result.ExpectReturn(uint64(math.MaxUint32))
		result, ok = call(nil, 0, 0x20ac)
		if !ok {
			return
		}
		result.ExpectReturn(0)
	case "mbstowcs":
		source, ok := allocate([]byte("go\x00"))
		if !ok {
			return
		}
		result, ok := call([]crtContractMemoryWatch{{Address: source, Size: 3}}, 0, source, 0)
		if !ok {
			return
		}
		result.ExpectReturn(2)
		if !crtLocaleContractSetCodePage(invocation, 1252) {
			return
		}
		source, ok = allocate([]byte{0x80, 0})
		if !ok {
			return
		}
		expected := crtWideBytes([]uint16{0x20ac}, true)
		destination, ok := allocate(make([]byte, len(expected)))
		if !ok {
			return
		}
		result, ok = call(
			[]crtContractMemoryWatch{{Address: destination, Size: len(expected)}},
			destination, source, 2,
		)
		if !ok {
			return
		}
		result.ExpectReturn(1)
		result.ExpectMemory(0, expected)
		if !crtLocaleContractSetCodePage(invocation, 20127) {
			return
		}
		source, ok = allocate([]byte{0x80, 0})
		if !ok {
			return
		}
		result, ok = callEILSEQ(0, source, 0)
		if !ok {
			return
		}
		failure := uint64(math.MaxUint64)
		if invocation.Is32 {
			failure = uint64(math.MaxUint32)
		}
		result.ExpectReturn(failure)
	case "wcstombs":
		source, ok := allocate(crtWideASCII("go"))
		if !ok {
			return
		}
		result, ok := call([]crtContractMemoryWatch{{Address: source, Size: 6}}, 0, source, 0)
		if !ok {
			return
		}
		result.ExpectReturn(2)
		if !crtLocaleContractSetCodePage(invocation, 1252) {
			return
		}
		source, ok = allocate(crtWideBytes([]uint16{0x20ac}, true))
		if !ok {
			return
		}
		destination, ok := allocate([]byte{0xcc, 0xcc})
		if !ok {
			return
		}
		result, ok = call(
			[]crtContractMemoryWatch{{Address: destination, Size: 2}},
			destination, source, 2,
		)
		if !ok {
			return
		}
		result.ExpectReturn(1)
		result.ExpectMemory(0, []byte{0x80, 0})
		if !crtLocaleContractSetCodePage(invocation, 65001) {
			return
		}
		destination, ok = allocate([]byte{0xcc, 0xcc})
		if !ok {
			return
		}
		result, ok = call(
			[]crtContractMemoryWatch{{Address: destination, Size: 2}},
			destination, source, 2,
		)
		if !ok {
			return
		}
		result.ExpectReturn(0)
		result.ExpectMemory(0, []byte{0xcc, 0xcc})
		if !crtLocaleContractSetCodePage(invocation, 20127) {
			return
		}
		result, ok = callEILSEQ(0, source, 0)
		if !ok {
			return
		}
		failure := uint64(math.MaxUint64)
		if invocation.Is32 {
			failure = uint64(math.MaxUint32)
		}
		result.ExpectReturn(failure)
	case "setlocale":
		values := []struct {
			input     string
			canonical string
			codePage  uint32
		}{
			{input: "C", canonical: "C", codePage: 20127},
			{input: "", canonical: "English_United States.1252", codePage: 1252},
			{input: "French_France.1252", canonical: "French_France.1252", codePage: 1252},
		}
		for _, value := range values {
			sourceData := append([]byte(value.input), 0)
			source, ok := allocate(sourceData)
			if !ok {
				return
			}
			result, ok := call([]crtContractMemoryWatch{{Address: source, Size: len(sourceData)}}, 0, source)
			if !ok {
				return
			}
			actual, readOK := crtReadNarrowString(invocation.Mem, result.Return)
			result.recordAssertion(result.Return != 0 && readOK && string(actual) == value.canonical, "setlocale result %#x contains %q", result.Return, actual)
			runtime := crtLocaleContractRuntime(invocation)
			runtimeOK := false
			if runtime != nil {
				runtime.mu.Lock()
				runtimeOK = runtime.name == value.canonical && runtime.codePage == value.codePage
				runtime.mu.Unlock()
			}
			result.recordAssertion(runtimeOK, "setlocale runtime did not retain %q", value.canonical)
		}
	case "_setmbcp":
		inputs := [3]uint64{0, 1252, 99999}
		outputs := [3]uint64{0, 0, uint64(math.MaxUint32)}
		codePages := [3]uint32{20127, 1252, 1252}
		for index, input := range inputs {
			result, ok := call(nil, input)
			if !ok {
				return
			}
			result.ExpectReturn(outputs[index])
			runtime := crtLocaleContractRuntime(invocation)
			runtimeOK := false
			if runtime != nil {
				runtime.mu.Lock()
				runtimeOK = runtime.codePage == codePages[index]
				runtime.mu.Unlock()
			}
			result.recordAssertion(runtimeOK, "_setmbcp runtime code page changed unexpectedly")
			if index == 2 {
				result.recordAssertion(crtReadErrno(invocation.Mem, 0) == 22, "_setmbcp errno is %d", crtReadErrno(invocation.Mem, 0))
			}
		}
	default:
		invocation.Failf("missing locale contract for %s", name)
	}
}

func crtLocaleContractRuntime(invocation *crtContractInvocation) *crtLocaleRuntime {
	crtLocaleRuntimes.Lock()
	defer crtLocaleRuntimes.Unlock()
	for key, runtime := range crtLocaleRuntimes.values {
		if key.mem == invocation.Mem {
			return runtime
		}
	}
	return nil
}

func crtLocaleContractSetCodePage(invocation *crtContractInvocation, codePage uint32) bool {
	runtime := crtLocaleContractRuntime(invocation)
	if runtime == nil {
		invocation.Failf("locale contract runtime is absent")
		return false
	}
	runtime.mu.Lock()
	runtime.codePage = codePage
	runtime.mu.Unlock()
	return true
}
