//go:build guest_windows

package main

import (
	"bytes"
	"fmt"
	"math"
	gorand "math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	gotime "time"
	"unicode"
	"unicode/utf16"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

type crtModuleConfig struct {
	iobBase   func() uint64
	iobStride uint64
}

type crtFileState struct {
	fd    int
	eof   bool
	err   bool
	tmp   string
	stdio int
}

type crtSupportState struct {
	mu          sync.Mutex
	files       map[uint64]*crtFileState
	nextFD      int
	tmpCounter  uint64
	rng         *gorand.Rand
	locale      string
	localeObjs  map[uint64]string
	errnoByTEB  map[uint64]uint64
	alignedRaw  map[uint64]uint64
	alignedSize map[uint64]uint64
	strtok      map[uint64]uint64
	wcstok      map[uint64]uint64
	signals     map[int]uint64
	localeconv  uint64
}

var (
	crtSupportMu sync.Mutex
	crtSupport   = map[*HandlerCtx]*crtSupportState{}
)

func getCRTSupport(hctx *HandlerCtx) *crtSupportState {
	crtSupportMu.Lock()
	defer crtSupportMu.Unlock()
	if st, ok := crtSupport[hctx]; ok {
		return st
	}
	st := &crtSupportState{
		files:       map[uint64]*crtFileState{},
		nextFD:      3,
		rng:         gorand.New(gorand.NewSource(1)),
		locale:      "C",
		localeObjs:  map[uint64]string{},
		errnoByTEB:  map[uint64]uint64{},
		alignedRaw:  map[uint64]uint64{},
		alignedSize: map[uint64]uint64{},
		strtok:      map[uint64]uint64{},
		wcstok:      map[uint64]uint64{},
		signals:     map[int]uint64{},
	}
	crtSupport[hctx] = st
	return st
}

func readCString(mem *mmu.MMU, addr uint64, limit int) string {
	if addr == 0 {
		return ""
	}
	if limit <= 0 {
		limit = 1 << 20
	}
	var out []byte
	for i := 0; i < limit; i++ {
		b, err := mem.Read8(addr + uint64(i))
		if err != nil || b == 0 {
			break
		}
		out = append(out, b)
	}
	return string(out)
}

func readUTF16(mem *mmu.MMU, addr uint64, limit int) string {
	if addr == 0 {
		return ""
	}
	if limit <= 0 {
		limit = 1 << 20
	}
	var chars []uint16
	for i := 0; i < limit; i++ {
		w, err := mem.Read16(addr + uint64(i)*2)
		if err != nil || w == 0 {
			break
		}
		chars = append(chars, w)
	}
	return string(utf16.Decode(chars))
}

func writeCString(mem *mmu.MMU, addr uint64, s string, max int) int {
	if addr == 0 {
		return 0
	}
	n := len(s)
	if max > 0 && n >= max {
		n = max - 1
	}
	for i := 0; i < n; i++ {
		mem.Write8(addr+uint64(i), s[i])
	}
	if max != 0 {
		mem.Write8(addr+uint64(n), 0)
	}
	return n
}

func writeUTF16(mem *mmu.MMU, addr uint64, s string, max int) int {
	if addr == 0 {
		return 0
	}
	chars := utf16.Encode([]rune(s))
	n := len(chars)
	if max > 0 && n >= max {
		n = max - 1
	}
	for i := 0; i < n; i++ {
		mem.Write16(addr+uint64(i*2), chars[i])
	}
	if max != 0 {
		mem.Write16(addr+uint64(n*2), 0)
	}
	return n
}

func collectCallArgs(ctx *ntapi.TrapContext, start, count int) []uint64 {
	args := make([]uint64, 0, count)
	for i := 0; i < count; i++ {
		args = append(args, ctx.Arg(start+i))
	}
	return args
}

func collectVAList(mem *mmu.MMU, vaList uint64, count int) []uint64 {
	args := make([]uint64, 0, count)
	for i := 0; i < count; i++ {
		v, _ := mem.Read64(vaList + uint64(i*8))
		args = append(args, v)
	}
	return args
}

func intMask(bits int) uint64 {
	if bits >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << bits) - 1
}

func signExtend(v uint64, bits int) int64 {
	if bits >= 64 {
		return int64(v)
	}
	v &= intMask(bits)
	sign := uint64(1) << (bits - 1)
	if v&sign != 0 {
		v |= ^intMask(bits)
	}
	return int64(v)
}

func formatInteger(raw uint64, bits int, signed bool, base int, upper bool, flags string, width, precision int) string {
	left := strings.Contains(flags, "-")
	zero := strings.Contains(flags, "0") && !left && precision < 0
	plus := strings.Contains(flags, "+")
	space := strings.Contains(flags, " ") && !plus
	alt := strings.Contains(flags, "#")
	prefix := ""
	body := ""
	if signed {
		val := signExtend(raw, bits)
		neg := val < 0
		mag := uint64(val)
		if neg {
			mag = uint64(-val)
		}
		body = strconv.FormatUint(mag, base)
		if precision == 0 && mag == 0 {
			body = ""
		}
		if neg {
			prefix = "-"
		} else if plus {
			prefix = "+"
		} else if space {
			prefix = " "
		}
	} else {
		val := raw & intMask(bits)
		body = strconv.FormatUint(val, base)
		if precision == 0 && val == 0 {
			body = ""
		}
		if alt && val != 0 {
			if base == 8 {
				prefix = "0"
			} else if base == 16 {
				prefix = "0x"
				if upper {
					prefix = "0X"
				}
			}
		}
	}
	if upper {
		body = strings.ToUpper(body)
	}
	if precision > len(body) {
		body = strings.Repeat("0", precision-len(body)) + body
	}
	padChar := " "
	if zero {
		padChar = "0"
	}
	out := prefix + body
	if width > len(out) {
		pad := strings.Repeat(padChar, width-len(out))
		if left {
			out += pad
		} else if padChar == "0" && prefix != "" {
			out = prefix + pad + body
		} else {
			out = pad + out
		}
	}
	return out
}

func formatString(mem *mmu.MMU, format string, args []uint64, wideFmt bool) string {
	argi := 0
	next := func() uint64 {
		if argi >= len(args) {
			return 0
		}
		v := args[argi]
		argi++
		return v
	}
	readArgString := func(ptr uint64, wide bool) string {
		if ptr == 0 {
			return "(null)"
		}
		if wide {
			return readUTF16(mem, ptr, -1)
		}
		return readCString(mem, ptr, -1)
	}
	var out strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			out.WriteByte(format[i])
			continue
		}
		i++
		if i >= len(format) {
			break
		}
		if format[i] == '%' {
			out.WriteByte('%')
			continue
		}
		flags := ""
		for i < len(format) && strings.ContainsRune("-+ 0#", rune(format[i])) {
			flags += string(format[i])
			i++
		}
		width := -1
		if i < len(format) && format[i] == '*' {
			width = int(signExtend(next(), 32))
			if width < 0 {
				width = -width
				if !strings.Contains(flags, "-") {
					flags += "-"
				}
			}
			i++
		} else {
			start := i
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				i++
			}
			if start != i {
				width, _ = strconv.Atoi(format[start:i])
			}
		}
		precision := -1
		if i < len(format) && format[i] == '.' {
			i++
			if i < len(format) && format[i] == '*' {
				precision = int(signExtend(next(), 32))
				if precision < 0 {
					precision = -1
				}
				i++
			} else {
				start := i
				for i < len(format) && format[i] >= '0' && format[i] <= '9' {
					i++
				}
				precision = 0
				if start != i {
					precision, _ = strconv.Atoi(format[start:i])
				}
			}
		}
		length := ""
		if i < len(format) {
			switch format[i] {
			case 'h', 'l', 'z', 't':
				length = string(format[i])
				i++
				if i < len(format) && format[i] == format[i-1] {
					length += string(format[i])
					i++
				}
			case 'I':
				if i+2 < len(format) && format[i+1] == '6' && format[i+2] == '4' {
					length = "I64"
					i += 3
				}
			}
		}
		if i >= len(format) {
			break
		}
		verb := format[i]
		bits := 32
		if length == "ll" || length == "I64" || length == "z" || length == "t" {
			bits = 64
		} else if length == "h" {
			bits = 16
		}
		switch verb {
		case 'd', 'i':
			out.WriteString(formatInteger(next(), bits, true, 10, false, flags, max(width, 0), precision))
		case 'u':
			out.WriteString(formatInteger(next(), bits, false, 10, false, flags, max(width, 0), precision))
		case 'x':
			out.WriteString(formatInteger(next(), bits, false, 16, false, flags, max(width, 0), precision))
		case 'X':
			out.WriteString(formatInteger(next(), bits, false, 16, true, flags, max(width, 0), precision))
		case 'p':
			out.WriteString(formatInteger(next(), 64, false, 16, false, "#", max(width, 0), precision))
		case 'c', 'C':
			r := rune(next())
			s := string(r)
			if !wideFmt && verb == 'C' {
				s = string([]byte{byte(r)})
			}
			if width > 0 && len([]rune(s)) < width {
				pad := strings.Repeat(" ", width-len([]rune(s)))
				if strings.Contains(flags, "-") {
					s += pad
				} else {
					s = pad + s
				}
			}
			out.WriteString(s)
		case 's', 'S':
			isWide := wideFmt
			if verb == 'S' {
				isWide = !wideFmt
			}
			if length == "h" {
				isWide = false
			} else if length == "l" || length == "ll" {
				isWide = true
			}
			s := readArgString(next(), isWide)
			rs := []rune(s)
			if precision >= 0 && len(rs) > precision {
				s = string(rs[:precision])
			}
			if width > 0 && len([]rune(s)) < width {
				pad := strings.Repeat(" ", width-len([]rune(s)))
				if strings.Contains(flags, "-") {
					s += pad
				} else {
					s = pad + s
				}
			}
			out.WriteString(s)
		case 'f', 'F', 'e', 'E', 'g', 'G':
			prec := precision
			if prec < 0 {
				prec = 6
			}
			f := math.Float64frombits(next())
			spec := "%" + flags
			if width > 0 {
				spec += strconv.Itoa(width)
			}
			spec += "." + strconv.Itoa(prec) + string(verb)
			out.WriteString(fmt.Sprintf(spec, f))
		case 'n':
			ptr := next()
			if ptr != 0 {
				mem.Write32(ptr, uint32(out.Len()))
			}
		default:
			out.WriteByte('%')
			out.WriteByte(verb)
		}
	}
	return out.String()
}

func parseScanf(input, format string, mem *mmu.MMU, args []uint64, wide bool) int {
	in := input
	argi := 0
	assigned := 0
	consumed := 0
	next := func() uint64 {
		if argi >= len(args) {
			return 0
		}
		v := args[argi]
		argi++
		return v
	}
	skipWS := func() {
		trimmed := strings.TrimLeftFunc(in, unicode.IsSpace)
		consumed += len(in) - len(trimmed)
		in = trimmed
	}
	for i := 0; i < len(format); i++ {
		if unicode.IsSpace(rune(format[i])) {
			skipWS()
			continue
		}
		if format[i] != '%' {
			if len(in) == 0 || in[0] != format[i] {
				break
			}
			in = in[1:]
			consumed++
			continue
		}
		i++
		if i >= len(format) {
			break
		}
		if format[i] == '%' {
			if len(in) == 0 || in[0] != '%' {
				break
			}
			in = in[1:]
			consumed++
			continue
		}
		skipWS()
		switch format[i] {
		case 'd':
			j := 0
			if j < len(in) && (in[j] == '+' || in[j] == '-') {
				j++
			}
			for j < len(in) && unicode.IsDigit(rune(in[j])) {
				j++
			}
			if j == 0 || (j == 1 && (in[0] == '+' || in[0] == '-')) {
				return assigned
			}
			v, _ := strconv.ParseInt(in[:j], 10, 32)
			if p := next(); p != 0 {
				mem.Write32(p, uint32(int32(v)))
			}
			in = in[j:]
			consumed += j
			assigned++
		case 'x':
			j := 0
			for j < len(in) && strings.ContainsRune("0123456789abcdefABCDEF", rune(in[j])) {
				j++
			}
			if j == 0 {
				return assigned
			}
			v, _ := strconv.ParseUint(in[:j], 16, 32)
			if p := next(); p != 0 {
				mem.Write32(p, uint32(v))
			}
			in = in[j:]
			consumed += j
			assigned++
		case 'f', 'e', 'g':
			j := 0
			if j < len(in) && (in[j] == '+' || in[j] == '-') {
				j++
			}
			for j < len(in) && (unicode.IsDigit(rune(in[j])) || strings.ContainsRune(".eE+-", rune(in[j]))) {
				j++
			}
			if j == 0 {
				return assigned
			}
			v, _ := strconv.ParseFloat(in[:j], 64)
			if p := next(); p != 0 {
				mem.Write64(p, math.Float64bits(v))
			}
			in = in[j:]
			consumed += j
			assigned++
		case 's':
			j := 0
			for j < len(in) && !unicode.IsSpace(rune(in[j])) {
				j++
			}
			if j == 0 {
				return assigned
			}
			if p := next(); p != 0 {
				if wide {
					writeUTF16(mem, p, in[:j], -1)
				} else {
					writeCString(mem, p, in[:j], -1)
				}
			}
			in = in[j:]
			consumed += j
			assigned++
		case 'c':
			if len(in) == 0 {
				return assigned
			}
			if p := next(); p != 0 {
				if wide {
					mem.Write16(p, uint16(in[0]))
				} else {
					mem.Write8(p, in[0])
				}
			}
			in = in[1:]
			consumed++
			assigned++
		case 'n':
			if p := next(); p != 0 {
				mem.Write32(p, uint32(consumed))
			}
		default:
			return assigned
		}
	}
	return assigned
}

func digitValue(ch byte) int {
	switch {
	case ch >= '0' && ch <= '9':
		return int(ch - '0')
	case ch >= 'a' && ch <= 'z':
		return int(ch-'a') + 10
	case ch >= 'A' && ch <= 'Z':
		return int(ch-'A') + 10
	default:
		return -1
	}
}

func parseIntPrefix(s string, base int, unsigned bool) (uint64, int, bool) {
	i := 0
	for i < len(s) && unicode.IsSpace(rune(s[i])) {
		i++
	}
	signStart := i
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	digitStart := i
	if base == 0 {
		base = 10
		if i+1 < len(s) && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') {
			base = 16
			i += 2
			digitStart = i
		} else if i < len(s) && s[i] == '0' {
			base = 8
			i++
			digitStart = i - 1
		}
	} else if base == 16 && i+1 < len(s) && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') {
		i += 2
		digitStart = i
	}
	for i < len(s) {
		if dv := digitValue(s[i]); dv < 0 || dv >= base {
			break
		}
		i++
	}
	if i == digitStart {
		return 0, signStart, false
	}
	u, err := strconv.ParseUint(s[digitStart:i], base, 64)
	if err != nil {
		return 0, signStart, false
	}
	if neg && !unsigned {
		return uint64(-int64(u)), i, true
	}
	return u, i, true
}

func parseFloatPrefix(s string) (float64, int, bool) {
	i := 0
	for i < len(s) && unicode.IsSpace(rune(s[i])) {
		i++
	}
	start := i
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	digits := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
		digits++
	}
	if i < len(s) && s[i] == '.' {
		i++
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
			digits++
		}
	}
	if digits == 0 {
		return 0, start, false
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		expStart := i
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		expDigits := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
			expDigits++
		}
		if expDigits == 0 {
			i = expStart
		}
	}
	v, err := strconv.ParseFloat(s[start:i], 64)
	if err != nil {
		return 0, start, false
	}
	return v, i, true
}

func duplicateGuestString(hctx *HandlerCtx, addr uint64, wide bool) uint64 {
	mem := hctx.Mem
	if addr == 0 {
		return 0
	}
	if wide {
		s := readUTF16(mem, addr, -1)
		chars := utf16.Encode([]rune(s))
		dst := hctx.HeapAlloc(uint64(len(chars)+1)*2, false)
		writeUTF16(mem, dst, s, -1)
		return dst
	}
	s := readCString(mem, addr, -1)
	dst := hctx.HeapAlloc(uint64(len(s)+1), false)
	writeCString(mem, dst, s, -1)
	return dst
}

func tmWrite(mem *mmu.MMU, addr uint64, t gotime.Time) {
	fields := []int32{
		int32(t.Second()), int32(t.Minute()), int32(t.Hour()), int32(t.Day()),
		int32(t.Month() - 1), int32(t.Year() - 1900), int32(t.Weekday()),
		int32(t.YearDay() - 1), 0,
	}
	for i, v := range fields {
		mem.Write32(addr+uint64(i*4), uint32(v))
	}
}

func tmRead(mem *mmu.MMU, addr uint64, loc *gotime.Location) gotime.Time {
	read := func(off uint64) int32 {
		v, _ := mem.Read32(addr + off)
		return int32(v)
	}
	return gotime.Date(int(read(20))+1900, gotime.Month(read(16))+1, int(read(12)), int(read(8)), int(read(4)), int(read(0)), 0, loc)
}

func strftimeLayout(s string) string {
	repl := strings.NewReplacer(
		"%Y", "2006", "%y", "06", "%m", "01", "%d", "02",
		"%H", "15", "%M", "04", "%S", "05", "%a", "Mon",
		"%A", "Monday", "%b", "Jan", "%B", "January", "%p", "PM",
		"%T", "15:04:05", "%R", "15:04", "%F", "2006-01-02", "%%", "%",
	)
	return repl.Replace(s)
}

func fileForFP(hctx *HandlerCtx, st *crtSupportState, cfg crtModuleConfig, fp uint64) (*crtFileState, *os.File) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if fs, ok := st.files[fp]; ok {
		return fs, hctx.CrtFiles[fp]
	}
	if cfg.iobBase != nil {
		base := cfg.iobBase()
		if base != 0 && cfg.iobStride != 0 {
			for i := 0; i < 3; i++ {
				if fp == base+uint64(i)*cfg.iobStride {
					return &crtFileState{fd: i, stdio: i}, nil
				}
			}
		}
	}
	return nil, nil
}

func openGuestFile(hctx *HandlerCtx, st *crtSupportState, path, mode string) uint64 {
	host := winPathToVFS(path)
	if strings.HasPrefix(host, "/") {
		host = "." + host
	}
	_ = os.MkdirAll(filepath.Dir(filepath.Clean(host)), 0o755)
	flags := os.O_RDONLY
	switch {
	case strings.Contains(mode, "a") && strings.Contains(mode, "+"):
		flags = os.O_RDWR | os.O_CREATE | os.O_APPEND
	case strings.Contains(mode, "a"):
		flags = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	case strings.Contains(mode, "w") && strings.Contains(mode, "+"):
		flags = os.O_RDWR | os.O_CREATE | os.O_TRUNC
	case strings.Contains(mode, "w"):
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	case strings.Contains(mode, "+"):
		flags = os.O_RDWR
	}
	f, err := os.OpenFile(filepath.Clean(host), flags, 0o644)
	if err != nil {
		return 0
	}
	fp := hctx.CrtNextFP
	hctx.CrtNextFP += 64
	hctx.CrtFiles[fp] = f
	st.mu.Lock()
	st.files[fp] = &crtFileState{fd: st.nextFD}
	st.nextFD++
	st.mu.Unlock()
	return fp
}

func registerCommonCRTOverrides(hctx *HandlerCtx, synth *ntapi.SynthPE, cfg crtModuleConfig) {
	mem := hctx.Mem
	d := hctx.Disp
	st := getCRTSupport(hctx)

	registerFormatBuffer := func(name string, wideFmt, wideOut bool, countArg, fmtArg, bufArg, startArg int) {
		d.RegisterAutoStubHandler(synth, name, func(ctx *ntapi.TrapContext) uint32 {
			format := readCString(mem, ctx.Arg(fmtArg), -1)
			if wideFmt {
				format = readUTF16(mem, ctx.Arg(fmtArg), -1)
			}
			out := formatString(mem, format, collectCallArgs(ctx, startArg, 24), wideFmt)
			if wideOut {
				writeUTF16(mem, ctx.Arg(bufArg), out, int(ctx.Arg(countArg)))
			} else {
				writeCString(mem, ctx.Arg(bufArg), out, int(ctx.Arg(countArg)))
			}
			ctx.SetReturn(uint64(len([]rune(out))))
			return 0
		})
	}
	registerFormatBuffer("snprintf", false, false, 1, 2, 0, 3)
	registerFormatBuffer("_snprintf", false, false, 1, 2, 0, 3)
	registerFormatBuffer("swprintf", true, true, 1, 2, 0, 3)
	registerFormatBuffer("_snwprintf", true, true, 1, 2, 0, 3)

	for _, spec := range []struct {
		name             string
		wideFmt, wideOut bool
		fmtArg, bufArg   int
		startArg, vaArg  int
		streamArg        int
	}{
		{"sprintf", false, false, 1, 0, 2, -1, -1},
		{"vsprintf", false, false, 1, 0, -1, 2, -1},
		{"_vsnprintf", false, false, 2, 0, -1, 3, -1},
		{"_vsnwprintf", true, true, 2, 0, -1, 3, -1},
		{"fprintf", false, false, 1, -1, 2, -1, 0},
		{"fwprintf", true, false, 1, -1, 2, -1, 0},
		{"printf", false, false, 0, -1, 1, -1, 0},
		{"wprintf", true, false, 0, -1, 1, -1, 0},
		{"vfprintf", false, false, 1, -1, -1, 2, 0},
		{"__stdio_common_vsprintf", false, false, 3, 1, -1, 5, -1},
		{"__stdio_common_vswprintf", true, true, 3, 1, -1, 5, -1},
		{"__stdio_common_vfprintf", false, false, 2, -1, -1, 4, 1},
		{"__stdio_common_vfwprintf", true, false, 2, -1, -1, 4, 1},
	} {
		spec := spec
		d.RegisterAutoStubHandler(synth, spec.name, func(ctx *ntapi.TrapContext) uint32 {
			format := readCString(mem, ctx.Arg(spec.fmtArg), -1)
			if spec.wideFmt {
				format = readUTF16(mem, ctx.Arg(spec.fmtArg), -1)
			}
			args := collectCallArgs(ctx, spec.startArg, 24)
			if spec.vaArg >= 0 {
				args = collectVAList(mem, ctx.Arg(spec.vaArg), 24)
			}
			out := formatString(mem, format, args, spec.wideFmt)
			if spec.bufArg >= 0 {
				if spec.wideOut {
					writeUTF16(mem, ctx.Arg(spec.bufArg), out, int(ctx.Arg(2)))
				} else {
					writeCString(mem, ctx.Arg(spec.bufArg), out, func() int {
						if strings.Contains(spec.name, "common") {
							return int(ctx.Arg(2))
						}
						return -1
					}())
				}
			}
			if spec.streamArg >= 0 {
				fp := ctx.Arg(spec.streamArg)
				fs, f := fileForFP(hctx, st, cfg, fp)
				switch {
				case fs != nil && fs.stdio == 2:
					_, _ = os.Stderr.WriteString(out)
				case fs != nil && (fs.stdio == 1 || spec.name == "printf" || spec.name == "wprintf"):
					_, _ = os.Stdout.WriteString(out)
				case f != nil:
					_, _ = f.WriteString(out)
				default:
					_, _ = os.Stdout.WriteString(out)
				}
			}
			ctx.SetReturn(uint64(len([]rune(out))))
			return 0
		})
	}

	for _, spec := range []struct {
		name string
		wide bool
	}{
		{"sscanf", false}, {"swscanf", true}, {"__stdio_common_vsscanf", false}, {"__stdio_common_vswscanf", true},
	} {
		spec := spec
		d.RegisterAutoStubHandler(synth, spec.name, func(ctx *ntapi.TrapContext) uint32 {
			input := readCString(mem, ctx.Arg(0), -1)
			format := readCString(mem, ctx.Arg(1), -1)
			args := collectCallArgs(ctx, 2, 16)
			if strings.Contains(spec.name, "common") {
				input = readCString(mem, ctx.Arg(1), -1)
				format = readCString(mem, ctx.Arg(2), -1)
				args = collectVAList(mem, ctx.Arg(4), 16)
			}
			if spec.wide {
				input = readUTF16(mem, ctx.Arg(0), -1)
				format = readUTF16(mem, ctx.Arg(1), -1)
				if strings.Contains(spec.name, "common") {
					input = readUTF16(mem, ctx.Arg(1), -1)
					format = readUTF16(mem, ctx.Arg(2), -1)
				}
			}
			ctx.SetReturn(uint64(parseScanf(input, format, mem, args, spec.wide)))
			return 0
		})
	}

	for _, spec := range []struct {
		name string
		wide bool
	}{
		{"fopen", false}, {"_wfopen", true},
	} {
		spec := spec
		d.RegisterAutoStubHandler(synth, spec.name, func(ctx *ntapi.TrapContext) uint32 {
			path := readCString(mem, ctx.Arg(0), -1)
			mode := readCString(mem, ctx.Arg(1), -1)
			if spec.wide {
				path = readUTF16(mem, ctx.Arg(0), -1)
				mode = readUTF16(mem, ctx.Arg(1), -1)
			}
			ctx.SetReturn(openGuestFile(hctx, st, path, mode))
			return 0
		})
	}
	d.RegisterAutoStubHandler(synth, "fopen_s", func(ctx *ntapi.TrapContext) uint32 {
		pp, path, mode := ctx.Arg(0), readCString(mem, ctx.Arg(1), -1), readCString(mem, ctx.Arg(2), -1)
		fp := openGuestFile(hctx, st, path, mode)
		if pp != 0 {
			mem.Write64(pp, fp)
		}
		if fp == 0 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(synth, "_wfopen_s", func(ctx *ntapi.TrapContext) uint32 {
		pp, path, mode := ctx.Arg(0), readUTF16(mem, ctx.Arg(1), -1), readUTF16(mem, ctx.Arg(2), -1)
		fp := openGuestFile(hctx, st, path, mode)
		if pp != 0 {
			mem.Write64(pp, fp)
		}
		if fp == 0 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(synth, "rewind", func(ctx *ntapi.TrapContext) uint32 {
		fp := ctx.Arg(0)
		if _, f := fileForFP(hctx, st, cfg, fp); f != nil {
			_, _ = f.Seek(0, 0)
		}
		st.mu.Lock()
		if fs := st.files[fp]; fs != nil {
			fs.eof = false
			fs.err = false
		}
		st.mu.Unlock()
		return 0
	})
	d.RegisterAutoStubHandler(synth, "fgetpos", func(ctx *ntapi.TrapContext) uint32 {
		if pos, fpos := ctx.Arg(1), ctx.Arg(0); pos != 0 {
			if _, f := fileForFP(hctx, st, cfg, fpos); f != nil {
				cur, _ := f.Seek(0, 1)
				mem.Write64(pos, uint64(cur))
				ctx.SetReturn(0)
				return 0
			}
		}
		ctx.SetReturn(^uint64(0))
		return 0
	})
	d.RegisterAutoStubHandler(synth, "fsetpos", func(ctx *ntapi.TrapContext) uint32 {
		if _, f := fileForFP(hctx, st, cfg, ctx.Arg(0)); f != nil && ctx.Arg(1) != 0 {
			pos, _ := mem.Read64(ctx.Arg(1))
			_, _ = f.Seek(int64(pos), 0)
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(^uint64(0))
		return 0
	})
	d.RegisterAutoStubHandler(synth, "clearerr", func(ctx *ntapi.TrapContext) uint32 {
		st.mu.Lock()
		if fs, ok := st.files[ctx.Arg(0)]; ok {
			fs.eof = false
			fs.err = false
		}
		st.mu.Unlock()
		return 0
	})
	d.RegisterAutoStubHandler(synth, "tmpnam", func(ctx *ntapi.TrapContext) uint32 {
		st.mu.Lock()
		st.tmpCounter++
		name := fmt.Sprintf(".raven-tmp-%d.tmp", st.tmpCounter)
		st.mu.Unlock()
		buf := ctx.Arg(0)
		if buf == 0 {
			buf = mem.Mmap(0, 260, mmu.PermRead|mmu.PermWrite)
		}
		writeCString(mem, buf, name, 260)
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(synth, "tmpfile", func(ctx *ntapi.TrapContext) uint32 {
		st.mu.Lock()
		st.tmpCounter++
		name := fmt.Sprintf(".raven-tmp-%d.tmp", st.tmpCounter)
		st.mu.Unlock()
		f, err := os.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		fp := hctx.CrtNextFP
		hctx.CrtNextFP += 64
		hctx.CrtFiles[fp] = f
		st.mu.Lock()
		st.files[fp] = &crtFileState{fd: st.nextFD, tmp: name}
		st.nextFD++
		st.mu.Unlock()
		ctx.SetReturn(fp)
		return 0
	})
	d.RegisterAutoStubHandler(synth, "_fileno", func(ctx *ntapi.TrapContext) uint32 {
		if fs, _ := fileForFP(hctx, st, cfg, ctx.Arg(0)); fs != nil {
			ctx.SetReturn(uint64(fs.fd))
			return 0
		}
		ctx.SetReturn(^uint64(0))
		return 0
	})
	d.RegisterAutoStubHandler(synth, "fclose", func(ctx *ntapi.TrapContext) uint32 {
		fp := ctx.Arg(0)
		st.mu.Lock()
		fs := st.files[fp]
		delete(st.files, fp)
		st.mu.Unlock()
		if f := hctx.CrtFiles[fp]; f != nil {
			_ = f.Close()
			delete(hctx.CrtFiles, fp)
		}
		if fs != nil && fs.tmp != "" {
			_ = os.Remove(fs.tmp)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(synth, "fread", func(ctx *ntapi.TrapContext) uint32 {
		ptr, size, count, fp := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		fs, f := fileForFP(hctx, st, cfg, fp)
		if fs == nil || ptr == 0 || size == 0 || count == 0 {
			ctx.SetReturn(0)
			return 0
		}
		buf := make([]byte, size*count)
		n := 0
		var err error
		if f != nil {
			n, err = f.Read(buf)
		} else if fs.stdio == 0 {
			n, err = os.Stdin.Read(buf)
		}
		if n > 0 {
			mem.WriteBytes(ptr, buf[:n])
		}
		st.mu.Lock()
		if real, ok := st.files[fp]; ok {
			real.eof = n == 0
			real.err = err != nil && n == 0
		}
		st.mu.Unlock()
		ctx.SetReturn(uint64(n) / size)
		return 0
	})
	d.RegisterAutoStubHandler(synth, "fwrite", func(ctx *ntapi.TrapContext) uint32 {
		ptr, size, count, fp := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		fs, f := fileForFP(hctx, st, cfg, fp)
		if fs == nil || ptr == 0 || size == 0 || count == 0 {
			ctx.SetReturn(0)
			return 0
		}
		buf, _ := mem.ReadBytes(ptr, int(size*count))
		n := 0
		var err error
		switch {
		case fs.stdio == 2:
			n, err = os.Stderr.Write(buf)
		case fs.stdio == 1:
			n, err = os.Stdout.Write(buf)
		case f != nil:
			n, err = f.Write(buf)
		}
		st.mu.Lock()
		if real := st.files[fp]; real != nil {
			real.err = err != nil
		}
		st.mu.Unlock()
		ctx.SetReturn(uint64(n) / size)
		return 0
	})
	d.RegisterAutoStubHandler(synth, "fgets", func(ctx *ntapi.TrapContext) uint32 {
		buf, n, fp := ctx.Arg(0), int(ctx.Arg(1)), ctx.Arg(2)
		fs, f := fileForFP(hctx, st, cfg, fp)
		if fs == nil || f == nil || buf == 0 || n <= 0 {
			ctx.SetReturn(0)
			return 0
		}
		tmp := make([]byte, 0, n-1)
		one := []byte{0}
		for len(tmp) < n-1 {
			m, _ := f.Read(one)
			if m == 0 {
				break
			}
			tmp = append(tmp, one[0])
			if one[0] == '\n' {
				break
			}
		}
		if len(tmp) == 0 {
			st.mu.Lock()
			if real, ok := st.files[fp]; ok {
				real.eof = true
			}
			st.mu.Unlock()
			ctx.SetReturn(0)
			return 0
		}
		mem.WriteBytes(buf, tmp)
		mem.Write8(buf+uint64(len(tmp)), 0)
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(synth, "fputs", func(ctx *ntapi.TrapContext) uint32 {
		s, fp := readCString(mem, ctx.Arg(0), -1), ctx.Arg(1)
		fs, f := fileForFP(hctx, st, cfg, fp)
		if fs == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		switch {
		case fs.stdio == 2:
			_, _ = os.Stderr.WriteString(s)
		case fs.stdio == 1:
			_, _ = os.Stdout.WriteString(s)
		case f != nil:
			_, _ = f.WriteString(s)
		}
		ctx.SetReturn(uint64(len(s)))
		return 0
	})
	d.RegisterAutoStubHandler(synth, "fseek", func(ctx *ntapi.TrapContext) uint32 {
		fp := ctx.Arg(0)
		if _, f := fileForFP(hctx, st, cfg, fp); f != nil {
			if _, err := f.Seek(int64(ctx.Arg(1)), int(ctx.Arg(2))); err == nil {
				st.mu.Lock()
				if real := st.files[fp]; real != nil {
					real.eof = false
					real.err = false
				}
				st.mu.Unlock()
				ctx.SetReturn(0)
				return 0
			}
			st.mu.Lock()
			if real := st.files[fp]; real != nil {
				real.err = true
			}
			st.mu.Unlock()
		}
		ctx.SetReturn(^uint64(0))
		return 0
	})
	d.RegisterAutoStubHandler(synth, "ftell", func(ctx *ntapi.TrapContext) uint32 {
		if _, f := fileForFP(hctx, st, cfg, ctx.Arg(0)); f != nil {
			pos, _ := f.Seek(0, 1)
			ctx.SetReturn(uint64(pos))
			return 0
		}
		ctx.SetReturn(^uint64(0))
		return 0
	})
	d.RegisterAutoStubHandler(synth, "fflush", func(ctx *ntapi.TrapContext) uint32 {
		if _, f := fileForFP(hctx, st, cfg, ctx.Arg(0)); f != nil {
			_ = f.Sync()
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(synth, "feof", func(ctx *ntapi.TrapContext) uint32 {
		st.mu.Lock()
		defer st.mu.Unlock()
		if fs, ok := st.files[ctx.Arg(0)]; ok && fs.eof {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(synth, "ferror", func(ctx *ntapi.TrapContext) uint32 {
		st.mu.Lock()
		defer st.mu.Unlock()
		if fs, ok := st.files[ctx.Arg(0)]; ok && fs.err {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})

	for _, name := range []string{"errno", "_errno"} {
		d.RegisterAutoStubHandler(synth, name, func(ctx *ntapi.TrapContext) uint32 {
			teb := uint64(0)
			if ctx.State != nil {
				teb = ctx.State.TEBAddr
			}
			st.mu.Lock()
			slot := st.errnoByTEB[teb]
			if slot == 0 {
				slot = mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
				st.errnoByTEB[teb] = slot
			}
			st.mu.Unlock()
			ctx.SetReturn(slot)
			return 0
		})
	}

	d.RegisterAutoStubHandler(synth, "setlocale", func(ctx *ntapi.TrapContext) uint32 {
		st.mu.Lock()
		if p := ctx.Arg(1); p != 0 {
			st.locale = readCString(mem, p, -1)
			if st.locale == "" {
				st.locale = "C"
			}
		}
		loc := st.locale
		st.mu.Unlock()
		buf := mem.Mmap(0, uint64(len(loc)+1), mmu.PermRead|mmu.PermWrite)
		writeCString(mem, buf, loc, -1)
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(synth, "_wsetlocale", func(ctx *ntapi.TrapContext) uint32 {
		st.mu.Lock()
		if p := ctx.Arg(1); p != 0 {
			st.locale = readUTF16(mem, p, -1)
			if st.locale == "" {
				st.locale = "C"
			}
		}
		loc := st.locale
		st.mu.Unlock()
		buf := mem.Mmap(0, 64, mmu.PermRead|mmu.PermWrite)
		writeUTF16(mem, buf, loc, -1)
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(synth, "_get_current_locale", func(ctx *ntapi.TrapContext) uint32 {
		st.mu.Lock()
		loc := st.locale
		st.mu.Unlock()
		obj := mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
		str := mem.Mmap(0, uint64(len(loc)+1), mmu.PermRead|mmu.PermWrite)
		writeCString(mem, str, loc, -1)
		mem.Write64(obj, str)
		st.mu.Lock()
		st.localeObjs[obj] = loc
		st.mu.Unlock()
		ctx.SetReturn(obj)
		return 0
	})
	d.RegisterAutoStubHandler(synth, "_free_locale", func(ctx *ntapi.TrapContext) uint32 {
		st.mu.Lock()
		delete(st.localeObjs, ctx.Arg(0))
		st.mu.Unlock()
		return 0
	})
	d.RegisterAutoStubHandler(synth, "localeconv", func(ctx *ntapi.TrapContext) uint32 {
		st.mu.Lock()
		defer st.mu.Unlock()
		if st.localeconv == 0 {
			st.localeconv = mem.Mmap(0, 256, mmu.PermRead|mmu.PermWrite)
			dec := st.localeconv + 128
			thou := dec + 8
			writeCString(mem, dec, ".", -1)
			writeCString(mem, thou, ",", -1)
			mem.Write64(st.localeconv, dec)
			mem.Write64(st.localeconv+8, thou)
		}
		ctx.SetReturn(st.localeconv)
		return 0
	})

	for _, spec := range []struct {
		name string
		wide bool
	}{{"getenv", false}, {"_wgetenv", true}} {
		spec := spec
		d.RegisterAutoStubHandler(synth, spec.name, func(ctx *ntapi.TrapContext) uint32 {
			name := readCString(mem, ctx.Arg(0), -1)
			if spec.wide {
				name = readUTF16(mem, ctx.Arg(0), -1)
			}
			val := hctx.EnvVars[name]
			if val == "" {
				val = os.Getenv(name)
			}
			if val == "" {
				ctx.SetReturn(0)
				return 0
			}
			buf := mem.Mmap(0, uint64(len(val)+2)*2, mmu.PermRead|mmu.PermWrite)
			if spec.wide {
				writeUTF16(mem, buf, val, -1)
			} else {
				writeCString(mem, buf, val, -1)
			}
			ctx.SetReturn(buf)
			return 0
		})
	}

	for _, spec := range []struct {
		name string
		wide bool
	}{{"strdup", false}, {"_strdup", false}, {"_wcsdup", true}} {
		spec := spec
		d.RegisterAutoStubHandler(synth, spec.name, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(duplicateGuestString(hctx, ctx.Arg(0), spec.wide))
			return 0
		})
	}

	d.RegisterAutoStubHandler(synth, "getenv_s", func(ctx *ntapi.TrapContext) uint32 {
		name := readCString(mem, ctx.Arg(3), -1)
		val := hctx.EnvVars[name]
		if val == "" {
			val = os.Getenv(name)
		}
		if p := ctx.Arg(0); p != 0 {
			mem.Write64(p, uint64(len(val)+1))
		}
		if ctx.Arg(1) != 0 && ctx.Arg(2) > 0 {
			writeCString(mem, ctx.Arg(1), val, int(ctx.Arg(2)))
		}
		ctx.SetReturn(0)
		return 0
	})

	for _, spec := range []struct {
		name string
		wide bool
	}{{"strtok", false}, {"wcstok", true}} {
		spec := spec
		d.RegisterAutoStubHandler(synth, spec.name, func(ctx *ntapi.TrapContext) uint32 {
			key := ctx.Arg(1)
			cur := ctx.Arg(0)
			st.mu.Lock()
			if cur == 0 {
				if spec.wide {
					cur = st.wcstok[key]
				} else {
					cur = st.strtok[key]
				}
			}
			st.mu.Unlock()
			if cur == 0 {
				ctx.SetReturn(0)
				return 0
			}
			if spec.wide {
				delim := []rune(readUTF16(mem, ctx.Arg(1), -1))
				has := func(r rune) bool {
					for _, d := range delim {
						if d == r {
							return true
						}
					}
					return false
				}
				for {
					w, _ := mem.Read16(cur)
					if w == 0 {
						ctx.SetReturn(0)
						return 0
					}
					if !has(rune(w)) {
						break
					}
					cur += 2
				}
				start := cur
				for {
					w, _ := mem.Read16(cur)
					if w == 0 {
						st.mu.Lock()
						st.wcstok[key] = 0
						st.mu.Unlock()
						ctx.SetReturn(start)
						return 0
					}
					if has(rune(w)) {
						mem.Write16(cur, 0)
						st.mu.Lock()
						st.wcstok[key] = cur + 2
						st.mu.Unlock()
						ctx.SetReturn(start)
						return 0
					}
					cur += 2
				}
			}
			delim := readCString(mem, ctx.Arg(1), -1)
			for {
				b, _ := mem.Read8(cur)
				if b == 0 {
					ctx.SetReturn(0)
					return 0
				}
				if !strings.ContainsRune(delim, rune(b)) {
					break
				}
				cur++
			}
			start := cur
			for {
				b, _ := mem.Read8(cur)
				if b == 0 {
					st.mu.Lock()
					st.strtok[key] = 0
					st.mu.Unlock()
					ctx.SetReturn(start)
					return 0
				}
				if strings.ContainsRune(delim, rune(b)) {
					mem.Write8(cur, 0)
					st.mu.Lock()
					st.strtok[key] = cur + 1
					st.mu.Unlock()
					ctx.SetReturn(start)
					return 0
				}
				cur++
			}
		})
	}

	for _, spec := range []struct {
		name     string
		wide     bool
		float    bool
		unsigned bool
	}{
		{"wcstol", true, false, false}, {"wcstoul", true, false, true}, {"wcstod", true, true, false},
		{"_itoa", false, false, false}, {"_ltoa", false, false, false}, {"_itow", true, false, false},
	} {
		spec := spec
		d.RegisterAutoStubHandler(synth, spec.name, func(ctx *ntapi.TrapContext) uint32 {
			switch spec.name {
			case "wcstol", "wcstoul":
				s := strings.TrimLeftFunc(readUTF16(mem, ctx.Arg(0), -1), unicode.IsSpace)
				base := int(ctx.Arg(2))
				if base == 0 {
					base = 10
				}
				if spec.unsigned {
					v, _ := strconv.ParseUint(s, base, 64)
					if p := ctx.Arg(1); p != 0 {
						mem.Write64(p, ctx.Arg(0)+uint64(len([]rune(strings.TrimSpace(s)))))
					}
					ctx.SetReturn(v)
				} else {
					v, _ := strconv.ParseInt(s, base, 64)
					if p := ctx.Arg(1); p != 0 {
						mem.Write64(p, ctx.Arg(0)+uint64(len([]rune(strings.TrimSpace(s)))))
					}
					ctx.SetReturn(uint64(v))
				}
			case "wcstod":
				s := strings.TrimLeftFunc(readUTF16(mem, ctx.Arg(0), -1), unicode.IsSpace)
				v, _ := strconv.ParseFloat(s, 64)
				if p := ctx.Arg(1); p != 0 {
					mem.Write64(p, ctx.Arg(0)+uint64(len([]rune(strings.TrimSpace(s)))))
				}
				ctx.SetFloatReturn(v)
			default:
				base := int(ctx.Arg(2))
				if base == 0 {
					base = 10
				}
				s := strconv.FormatInt(int64(int32(ctx.Arg(0))), base)
				if spec.wide {
					writeUTF16(mem, ctx.Arg(1), s, -1)
				} else {
					writeCString(mem, ctx.Arg(1), s, -1)
				}
				ctx.SetReturn(ctx.Arg(1))
			}
			return 0
		})
	}

	for _, spec := range []struct {
		name     string
		wide     bool
		float    bool
		unsigned bool
	}{
		{"atoi", false, false, false}, {"atol", false, false, false}, {"atof", false, true, false},
		{"strtol", false, false, false}, {"strtoul", false, false, true}, {"strtod", false, true, false},
	} {
		spec := spec
		d.RegisterAutoStubHandler(synth, spec.name, func(ctx *ntapi.TrapContext) uint32 {
			var s string
			if spec.wide {
				s = readUTF16(mem, ctx.Arg(0), -1)
			} else {
				s = readCString(mem, ctx.Arg(0), -1)
			}
			if spec.float {
				v, consumed, ok := parseFloatPrefix(s)
				if !ok {
					if spec.name == "strtod" && ctx.Arg(1) != 0 {
						mem.Write64(ctx.Arg(1), ctx.Arg(0))
					}
					ctx.SetFloatReturn(0)
					return 0
				}
				if spec.name == "strtod" && ctx.Arg(1) != 0 {
					mem.Write64(ctx.Arg(1), ctx.Arg(0)+uint64(consumed))
				}
				ctx.SetFloatReturn(v)
				return 0
			}
			base := 10
			if strings.HasPrefix(spec.name, "strto") {
				base = int(ctx.Arg(2))
			}
			v, consumed, ok := parseIntPrefix(s, base, spec.unsigned)
			if strings.HasPrefix(spec.name, "strto") && ctx.Arg(1) != 0 {
				if ok {
					mem.Write64(ctx.Arg(1), ctx.Arg(0)+uint64(consumed))
				} else {
					mem.Write64(ctx.Arg(1), ctx.Arg(0))
				}
			}
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			ctx.SetReturn(v)
			return 0
		})
	}

	for _, name := range []string{"localtime", "gmtime", "mktime", "strftime", "wcsftime", "_time64", "time"} {
		name := name
		d.RegisterAutoStubHandler(synth, name, func(ctx *ntapi.TrapContext) uint32 {
			switch name {
			case "_time64", "time":
				now := uint64(gotime.Now().Unix())
				if p := ctx.Arg(0); p != 0 {
					if name == "time" {
						mem.Write32(p, uint32(now))
					} else {
						mem.Write64(p, now)
					}
				}
				ctx.SetReturn(now)
			case "localtime", "gmtime":
				var ts int64
				if ctx.Arg(0) != 0 {
					raw, _ := mem.Read64(ctx.Arg(0))
					ts = int64(raw)
				}
				loc := gotime.UTC
				if name == "localtime" {
					loc = gotime.Now().Location()
				}
				buf := mem.Mmap(0, 64, mmu.PermRead|mmu.PermWrite)
				tmWrite(mem, buf, gotime.Unix(ts, 0).In(loc))
				ctx.SetReturn(buf)
			case "mktime":
				t := tmRead(mem, ctx.Arg(0), gotime.Now().Location())
				ctx.SetReturn(uint64(t.Unix()))
			case "strftime", "wcsftime":
				format := readCString(mem, ctx.Arg(2), -1)
				if name == "wcsftime" {
					format = readUTF16(mem, ctx.Arg(2), -1)
				}
				t := tmRead(mem, ctx.Arg(3), gotime.Now().Location())
				out := t.Format(strftimeLayout(format))
				if name == "wcsftime" {
					ctx.SetReturn(uint64(writeUTF16(mem, ctx.Arg(0), out, int(ctx.Arg(1)))))
				} else {
					ctx.SetReturn(uint64(writeCString(mem, ctx.Arg(0), out, int(ctx.Arg(1)))))
				}
			}
			return 0
		})
	}
	d.RegisterAutoStubHandler(synth, "clock", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(gotime.Since(hctx.BootTime).Milliseconds()))
		return 0
	})
	d.RegisterAutoStubHandler(synth, "difftime", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetFloatReturn(float64(int64(ctx.Arg(0)) - int64(ctx.Arg(1))))
		return 0
	})

	d.RegisterAutoStubHandler(synth, "_msize", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		st.mu.Lock()
		if sz, ok := st.alignedSize[ptr]; ok {
			st.mu.Unlock()
			ctx.SetReturn(sz)
			return 0
		}
		st.mu.Unlock()
		block, _ := mem.Read64(ptr - 16)
		if block >= 16 {
			ctx.SetReturn(block - 16)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(synth, "_aligned_malloc", func(ctx *ntapi.TrapContext) uint32 {
		size, align := ctx.Arg(0), ctx.Arg(1)
		if align < 8 {
			align = 8
		}
		raw := hctx.HeapAlloc(size+align+8, false)
		aligned := (raw + 8 + align - 1) &^ (align - 1)
		st.mu.Lock()
		st.alignedRaw[aligned] = raw
		st.alignedSize[aligned] = size
		st.mu.Unlock()
		ctx.SetReturn(aligned)
		return 0
	})
	d.RegisterAutoStubHandler(synth, "_aligned_free", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		st.mu.Lock()
		raw := st.alignedRaw[ptr]
		delete(st.alignedRaw, ptr)
		delete(st.alignedSize, ptr)
		st.mu.Unlock()
		if raw != 0 {
			hctx.HeapFree(raw)
		} else {
			hctx.HeapFree(ptr)
		}
		return 0
	})

	d.RegisterAutoStubHandler(synth, "system", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(^uint64(0))
		return 0
	})
	d.RegisterAutoStubHandler(synth, "_wsystem", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(^uint64(0))
		return 0
	})
	d.RegisterAutoStubHandler(synth, "signal", func(ctx *ntapi.TrapContext) uint32 {
		st.mu.Lock()
		prev := st.signals[int(ctx.Arg(0))]
		st.signals[int(ctx.Arg(0))] = ctx.Arg(1)
		st.mu.Unlock()
		ctx.SetReturn(prev)
		return 0
	})
	d.RegisterAutoStubHandler(synth, "raise", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(synth, "rand", func(ctx *ntapi.TrapContext) uint32 {
		st.mu.Lock()
		defer st.mu.Unlock()
		ctx.SetReturn(uint64(st.rng.Int31n(0x7fff + 1)))
		return 0
	})
	d.RegisterAutoStubHandler(synth, "srand", func(ctx *ntapi.TrapContext) uint32 {
		st.mu.Lock()
		st.rng = gorand.New(gorand.NewSource(int64(ctx.Arg(0))))
		st.mu.Unlock()
		return 0
	})
	d.RegisterAutoStubHandler(synth, "qsort", func(ctx *ntapi.TrapContext) uint32 {
		base, n, size, compar := ctx.Arg(0), int(ctx.Arg(1)), int(ctx.Arg(2)), ctx.Arg(3)
		compare := func(a, b uint64) int64 {
			if compar != 0 && hctx.GuestCallTrampoline != nil {
				ret, err := ntapi.CallGuestFunction(ctx.CPU, mem, hctx.GuestCallTrampoline, compar, []uint64{a, b}, ctx.Trace)
				if err == nil {
					return int64(ret)
				}
			}
			ab, _ := mem.ReadBytes(a, size)
			bb, _ := mem.ReadBytes(b, size)
			return int64(bytes.Compare(ab, bb))
		}
		swap := func(a, b uint64) {
			ab, _ := mem.ReadBytes(a, size)
			bb, _ := mem.ReadBytes(b, size)
			mem.WriteBytes(a, bb)
			mem.WriteBytes(b, ab)
		}
		for i := 1; i < n; i++ {
			for j := i; j > 0; j-- {
				a := base + uint64((j-1)*size)
				b := base + uint64(j*size)
				if compare(a, b) <= 0 {
					break
				}
				swap(a, b)
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(synth, "bsearch", func(ctx *ntapi.TrapContext) uint32 {
		key, base, n, size := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2)), int(ctx.Arg(3))
		needle, _ := mem.ReadBytes(key, size)
		for i := 0; i < n; i++ {
			elem, _ := mem.ReadBytes(base+uint64(i*size), size)
			if bytes.Equal(elem, needle) {
				ctx.SetReturn(base + uint64(i*size))
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
}
