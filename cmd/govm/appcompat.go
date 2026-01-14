package main

import (
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

type appCompatState struct {
	mu     sync.Mutex
	shimDB map[uint32]string // handle -> DB path
	nextDB uint32
}

var appCompat = appCompatState{
	nextDB: 0xA000,
	shimDB: make(map[uint32]string),
}

type compatConfig struct {
	winVersion  uint32
	ntVersion   [2]uint32
	buildNumber uint32
	spMajor     uint32
}

var defaultCompat = compatConfig{
	winVersion:  10,
	ntVersion:   [2]uint32{10, 0},
	buildNumber: 19045,
	spMajor:     0,
}

type actCtxState struct {
	mu         sync.Mutex
	current    uint64
	nextHandle uint64
	nextCookie uint64
}

var appActCtx = actCtxState{
	nextHandle: 0xAC700000,
	nextCookie: 1,
}

func registerAppcompatHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestUTF16 := hctx.ReadGuestUTF16

	writeUTF16StringCount := func(dst uint64, s string, cch uint64) uint64 {
		ws := utf16Encode(s)
		required := uint64(len(ws) + 1)
		if dst == 0 || cch == 0 {
			return required
		}
		n := required
		if n > cch {
			n = cch
		}
		for i := uint64(0); i+1 < n; i++ {
			mem.Write16(dst+i*2, ws[i])
		}
		mem.Write16(dst+(n-1)*2, 0)
		return required
	}

	readUTF16Units := func(ptr uint64, cch int32) []uint16 {
		if ptr == 0 {
			return nil
		}
		if cch == -1 {
			var out []uint16
			for i := uint64(0); ; i++ {
				w, _ := mem.Read16(ptr + i*2)
				if w == 0 {
					break
				}
				out = append(out, w)
			}
			return out
		}
		if cch <= 0 {
			return nil
		}
		out := make([]uint16, cch)
		for i := int32(0); i < cch; i++ {
			out[i], _ = mem.Read16(ptr + uint64(i)*2)
		}
		return out
	}

	normalizeLocaleName := func(name string) string {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "", "!x-sys-default-locale", "!x-user-default-locale", "en-us":
			return "en-US"
		case "en":
			return "en"
		default:
			return ""
		}
	}

	resolveLocaleNameValue := func(name string) string {
		switch normalizeLocaleName(name) {
		case "", "en":
			return "en-US"
		default:
			return "en-US"
		}
	}

	isValidLocaleNameValue := func(name string) bool {
		switch normalizeLocaleName(name) {
		case "en-US", "en":
			return true
		default:
			return strings.TrimSpace(name) == ""
		}
	}

	lcidToLocaleNameValue := func(lcid uint32) string {
		switch lcid {
		case 0x0409, 0x0000, 0x0400, 0x0800:
			return "en-US"
		default:
			return ""
		}
	}

	localeNameToLCIDValue := func(name string) uint32 {
		switch normalizeLocaleName(name) {
		case "en-US", "en":
			return 0x0409
		default:
			return 0
		}
	}

	getLocaleInfoValue := func(lctype uint32) (string, bool) {
		switch lctype & 0x0FFFFFFF {
		case 0x0000000E: // LOCALE_SDECIMAL
			return ".", true
		case 0x0000000F: // LOCALE_STHOUSAND
			return ",", true
		case 0x00000010: // LOCALE_SGROUPING
			return "3;0", true
		case 0x0000001B: // LOCALE_SCURRENCY
			return "$", true
		case 0x0000001C: // LOCALE_SINTLSYMBOL
			return "USD", true
		case 0x0000001F: // LOCALE_SDATE
			return "/", true
		case 0x00000020: // LOCALE_STIME
			return ":", true
		case 0x00000028: // LOCALE_SSHORTDATE
			return "MM/dd/yyyy", true
		case 0x0000002A: // LOCALE_SLONGDATE
			return "dddd, MMMM dd, yyyy", true
		case 0x00000050: // LOCALE_SPOSITIVESIGN
			return "", true
		case 0x00000051: // LOCALE_SNEGATIVESIGN
			return "-", true
		case 0x00000059: // LOCALE_SISO639LANGNAME
			return "en", true
		case 0x0000005A: // LOCALE_SISO3166CTRYNAME
			return "US", true
		case 0x0000005C: // LOCALE_SNAME
			return "en-US", true
		case 0x00000079: // LOCALE_SSHORTTIME
			return "HH:mm:ss", true
		case 0x00001001: // LOCALE_SENGLANGUAGE
			return "English", true
		case 0x00001002: // LOCALE_SENGCOUNTRY
			return "United States", true
		default:
			return "", false
		}
	}

	writeCPInfoExWData := func(addr uint64, codePage uint32) bool {
		if addr == 0 {
			return false
		}
		maxCharSize := uint32(0)
		codePageName := ""
		switch codePage {
		case 65001:
			maxCharSize = 4
			codePageName = "65001 (UTF-8)"
		case 1252:
			maxCharSize = 1
			codePageName = "1252 (ANSI - Latin I)"
		case 437:
			maxCharSize = 1
			codePageName = "437 (OEM - United States)"
		default:
			return false
		}
		mem.Write32(addr+0, maxCharSize)
		mem.Write8(addr+4, 0x3F)
		mem.Write8(addr+5, 0)
		for i := uint64(0); i < 12; i++ {
			mem.Write8(addr+6+i, 0)
		}
		mem.Write16(addr+18, uint16('?'))
		mem.Write32(addr+20, codePage)
		writeUTF16StringCount(addr+24, codePageName, 260)
		return true
	}

	formatNumberValue := func(value string) string {
		s := strings.TrimSpace(value)
		if s == "" {
			return s
		}
		sign := ""
		if s[0] == '+' || s[0] == '-' {
			sign = s[:1]
			s = s[1:]
		}
		parts := strings.SplitN(s, ".", 2)
		intPart := parts[0]
		fracPart := ""
		if len(parts) == 2 {
			fracPart = parts[1]
		}
		for _, ch := range intPart {
			if ch < '0' || ch > '9' {
				return value
			}
		}
		for _, ch := range fracPart {
			if ch < '0' || ch > '9' {
				return value
			}
		}
		if intPart == "" {
			intPart = "0"
		}
		var groups []string
		for len(intPart) > 3 {
			groups = append([]string{intPart[len(intPart)-3:]}, groups...)
			intPart = intPart[:len(intPart)-3]
		}
		groups = append([]string{intPart}, groups...)
		out := sign + strings.Join(groups, ",")
		if fracPart != "" {
			out += "." + fracPart
		}
		return out
	}

	compareUTF16Ordinal := func(a, b []uint16, ignoreCase bool) uint64 {
		if ignoreCase {
			a = utf16Encode(strings.ToUpper(string(utf16.Decode(a))))
			b = utf16Encode(strings.ToUpper(string(utf16.Decode(b))))
		}
		limit := len(a)
		if len(b) < limit {
			limit = len(b)
		}
		for i := 0; i < limit; i++ {
			if a[i] < b[i] {
				return 1
			}
			if a[i] > b[i] {
				return 3
			}
		}
		if len(a) < len(b) {
			return 1
		}
		if len(a) > len(b) {
			return 3
		}
		return 2
	}

	const (
		verMinorVersion     = 0x0000001
		verMajorVersion     = 0x0000002
		verBuildNumber      = 0x0000004
		verPlatformID       = 0x0000008
		verServicePackMinor = 0x0000010
		verServicePackMajor = 0x0000020
		verSuiteName        = 0x0000040
		verProductType      = 0x0000080

		verEqual        = 1
		verGreater      = 2
		verGreaterEqual = 3
		verLess         = 4
		verLessEqual    = 5
		verAnd          = 6
		verOr           = 7
	)

	conditionForType := func(mask uint64, typeMask uint32) uint8 {
		for i := 0; i < 8; i++ {
			if typeMask == (1 << i) {
				return uint8((mask >> (i * 3)) & 0x7)
			}
		}
		return 0
	}

	compareU32 := func(a, b uint32) int {
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	}

	compareVersionTuple := func(cur, req []uint32) int {
		for i := 0; i < len(cur) && i < len(req); i++ {
			if cur[i] < req[i] {
				return -1
			}
			if cur[i] > req[i] {
				return 1
			}
		}
		return 0
	}

	checkCondition := func(cmp int, cond uint8) bool {
		switch cond {
		case verEqual:
			return cmp == 0
		case verGreater:
			return cmp > 0
		case verGreaterEqual:
			return cmp >= 0
		case verLess:
			return cmp < 0
		case verLessEqual:
			return cmp <= 0
		default:
			return false
		}
	}

	registerCompatDLL := func(dll *ntapi.SynthPE) {
		if dll == nil {
			return
		}

		d.RegisterAutoStubHandler(dll, "GetDateFormatEx", func(ctx *ntapi.TrapContext) uint32 {
			s := time.Now().Format("01/02/2006")
			ctx.SetReturn(writeUTF16StringCount(ctx.Arg(4), s, ctx.Arg(5)))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "GetTimeFormatEx", func(ctx *ntapi.TrapContext) uint32 {
			s := time.Now().Format("15:04:05")
			ctx.SetReturn(writeUTF16StringCount(ctx.Arg(4), s, ctx.Arg(5)))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "GetNumberFormatEx", func(ctx *ntapi.TrapContext) uint32 {
			formatted := formatNumberValue(readGuestUTF16(ctx.Arg(2)))
			ctx.SetReturn(writeUTF16StringCount(ctx.Arg(4), formatted, ctx.Arg(5)))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "CompareStringOrdinal", func(ctx *ntapi.TrapContext) uint32 {
			a := readUTF16Units(ctx.Arg(0), int32(ctx.Arg(1)))
			b := readUTF16Units(ctx.Arg(2), int32(ctx.Arg(3)))
			ctx.SetReturn(compareUTF16Ordinal(a, b, ctx.Arg(4) != 0))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "FindNLSString", func(ctx *ntapi.TrapContext) uint32 {
			if p := ctx.Arg(6); p != 0 {
				mem.Write32(p, 0)
			}
			ctx.SetReturn(^uint64(0))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "FindNLSStringEx", func(ctx *ntapi.TrapContext) uint32 {
			if p := ctx.Arg(6); p != 0 {
				mem.Write32(p, 0)
			}
			ctx.SetReturn(^uint64(0))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "ResolveLocaleName", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(writeUTF16StringCount(ctx.Arg(1), resolveLocaleNameValue(readGuestUTF16(ctx.Arg(0))), ctx.Arg(2)))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "GetUserDefaultLocaleName", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(writeUTF16StringCount(ctx.Arg(0), "en-US", ctx.Arg(1)))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "GetSystemDefaultLocaleName", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(writeUTF16StringCount(ctx.Arg(0), "en-US", ctx.Arg(1)))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "IsValidLocaleName", func(ctx *ntapi.TrapContext) uint32 {
			if isValidLocaleNameValue(readGuestUTF16(ctx.Arg(0))) {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(dll, "LCIDToLocaleName", func(ctx *ntapi.TrapContext) uint32 {
			name := lcidToLocaleNameValue(uint32(ctx.Arg(0)))
			if name == "" {
				ctx.SetReturn(0)
				return 0
			}
			ctx.SetReturn(writeUTF16StringCount(ctx.Arg(1), name, ctx.Arg(2)))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "LocaleNameToLCID", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(localeNameToLCIDValue(readGuestUTF16(ctx.Arg(0)))))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "GetLocaleInfoEx", func(ctx *ntapi.TrapContext) uint32 {
			val, ok := getLocaleInfoValue(uint32(ctx.Arg(1)))
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			ctx.SetReturn(writeUTF16StringCount(ctx.Arg(2), val, ctx.Arg(3)))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "IsValidCodePage", func(ctx *ntapi.TrapContext) uint32 {
			switch uint32(ctx.Arg(0)) {
			case 65001, 1252, 437:
				ctx.SetReturn(1)
			default:
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(dll, "GetCPInfoExW", func(ctx *ntapi.TrapContext) uint32 {
			if !writeCPInfoExWData(ctx.Arg(2), uint32(ctx.Arg(0))) {
				ctx.SetReturn(0)
				return 0
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "VerSetConditionMask", func(ctx *ntapi.TrapContext) uint32 {
			mask := ctx.Arg(0)
			typeMask := uint32(ctx.Arg(1))
			condition := uint64(uint8(ctx.Arg(2) & 0x7))
			for i := 0; i < 8; i++ {
				bit := uint32(1 << i)
				if typeMask&bit == 0 {
					continue
				}
				shift := uint(i * 3)
				mask &^= uint64(0x7) << shift
				mask |= condition << shift
			}
			ctx.SetReturn(mask)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "VerifyVersionInfoW", func(ctx *ntapi.TrapContext) uint32 {
			info := ctx.Arg(0)
			typeMask := uint32(ctx.Arg(1))
			condMask := ctx.Arg(2)
			if info == 0 {
				ctx.SetReturn(0)
				return 0
			}

			structSize, _ := mem.Read32(info)
			reqMajor, _ := mem.Read32(info + 4)
			reqMinor, _ := mem.Read32(info + 8)
			reqBuild, _ := mem.Read32(info + 12)
			reqPlatform, _ := mem.Read32(info + 16)
			reqSPMajor := uint32(0)
			reqSPMinor := uint32(0)
			reqSuite := uint32(0)
			reqProduct := uint32(0)
			if structSize >= 284 {
				if v, _ := mem.Read16(info + 276); true {
					reqSPMajor = uint32(v)
				}
				if v, _ := mem.Read16(info + 278); true {
					reqSPMinor = uint32(v)
				}
				if v, _ := mem.Read16(info + 280); true {
					reqSuite = uint32(v)
				}
				if v, _ := mem.Read8(info + 282); true {
					reqProduct = uint32(v)
				}
			}

			currentVersion := map[uint32]uint32{
				verMajorVersion:     defaultCompat.ntVersion[0],
				verMinorVersion:     defaultCompat.ntVersion[1],
				verBuildNumber:      defaultCompat.buildNumber,
				verPlatformID:       2,
				verServicePackMajor: defaultCompat.spMajor,
				verServicePackMinor: 0,
				verSuiteName:        0x300,
				verProductType:      1,
			}
			requestedVersion := map[uint32]uint32{
				verMajorVersion:     reqMajor,
				verMinorVersion:     reqMinor,
				verBuildNumber:      reqBuild,
				verPlatformID:       reqPlatform,
				verServicePackMajor: reqSPMajor,
				verServicePackMinor: reqSPMinor,
				verSuiteName:        reqSuite,
				verProductType:      reqProduct,
			}

			versionOrder := []uint32{
				verMajorVersion,
				verMinorVersion,
				verBuildNumber,
				verServicePackMajor,
				verServicePackMinor,
			}
			firstCond := uint8(0)
			sameCond := true
			var curTuple []uint32
			var reqTuple []uint32
			for _, bit := range versionOrder {
				if typeMask&bit == 0 {
					continue
				}
				cond := conditionForType(condMask, bit)
				if cond == 0 {
					cond = verEqual
				}
				if firstCond == 0 {
					firstCond = cond
				} else if firstCond != cond {
					sameCond = false
				}
				curTuple = append(curTuple, currentVersion[bit])
				reqTuple = append(reqTuple, requestedVersion[bit])
			}

			ok := true
			if len(curTuple) > 0 {
				if sameCond {
					ok = checkCondition(compareVersionTuple(curTuple, reqTuple), firstCond)
				} else {
					for _, bit := range versionOrder {
						if typeMask&bit == 0 {
							continue
						}
						cond := conditionForType(condMask, bit)
						if cond == 0 {
							cond = verEqual
						}
						if !checkCondition(compareU32(currentVersion[bit], requestedVersion[bit]), cond) {
							ok = false
							break
						}
					}
				}
			}

			if ok && typeMask&verPlatformID != 0 {
				cond := conditionForType(condMask, verPlatformID)
				if cond == 0 {
					cond = verEqual
				}
				ok = checkCondition(compareU32(currentVersion[verPlatformID], requestedVersion[verPlatformID]), cond)
			}
			if ok && typeMask&verSuiteName != 0 {
				cond := conditionForType(condMask, verSuiteName)
				switch cond {
				case verOr:
					ok = requestedVersion[verSuiteName] == 0 || (currentVersion[verSuiteName]&requestedVersion[verSuiteName]) != 0
				case verAnd, 0:
					ok = (currentVersion[verSuiteName] & requestedVersion[verSuiteName]) == requestedVersion[verSuiteName]
				default:
					ok = checkCondition(compareU32(currentVersion[verSuiteName], requestedVersion[verSuiteName]), cond)
				}
			}
			if ok && typeMask&verProductType != 0 {
				cond := conditionForType(condMask, verProductType)
				if cond == 0 {
					cond = verEqual
				}
				ok = checkCondition(compareU32(currentVersion[verProductType], requestedVersion[verProductType]), cond)
			}

			if ok {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(dll, "ActivateActCtx", func(ctx *ntapi.TrapContext) uint32 {
			hActCtx := ctx.Arg(0)
			lpCookie := ctx.Arg(1)
			appActCtx.mu.Lock()
			if hActCtx != 0 {
				appActCtx.current = hActCtx
			}
			cookie := appActCtx.nextCookie
			appActCtx.nextCookie++
			appActCtx.mu.Unlock()
			if lpCookie != 0 {
				mem.Write64(lpCookie, cookie)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "DeactivateActCtx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "CreateActCtxW", func(ctx *ntapi.TrapContext) uint32 {
			appActCtx.mu.Lock()
			handle := appActCtx.nextHandle
			appActCtx.nextHandle++
			appActCtx.current = handle
			appActCtx.mu.Unlock()
			ctx.SetReturn(handle)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "ReleaseActCtx", func(ctx *ntapi.TrapContext) uint32 {
			hActCtx := ctx.Arg(0)
			appActCtx.mu.Lock()
			if appActCtx.current == hActCtx {
				appActCtx.current = 0
			}
			appActCtx.mu.Unlock()
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "GetCurrentActCtx", func(ctx *ntapi.TrapContext) uint32 {
			lphActCtx := ctx.Arg(0)
			appActCtx.mu.Lock()
			handle := appActCtx.current
			appActCtx.mu.Unlock()
			if lphActCtx != 0 {
				mem.Write64(lphActCtx, handle)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "FindActCtxSectionStringW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "QueryActCtxW", func(ctx *ntapi.TrapContext) uint32 {
			if p := ctx.Arg(5); p != 0 {
				mem.Write32(p, 0)
			}
			ctx.SetReturn(0)
			return 0
		})
	}

	registerRtlGetVersion := func(dll *ntapi.SynthPE) {
		if dll == nil {
			return
		}
		d.RegisterAutoStubHandler(dll, "RtlGetVersion", func(ctx *ntapi.TrapContext) uint32 {
			buffer := ctx.Arg(0)
			if buffer != 0 {
				structSize, _ := mem.Read32(buffer)
				mem.Write32(buffer+4, defaultCompat.ntVersion[0])
				mem.Write32(buffer+8, defaultCompat.ntVersion[1])
				mem.Write32(buffer+12, defaultCompat.buildNumber)
				mem.Write32(buffer+16, 2)
				mem.Write16(buffer+20, 0)
				if structSize >= 284 {
					mem.Write16(buffer+276, uint16(defaultCompat.spMajor))
					mem.Write16(buffer+278, 0)
					mem.Write16(buffer+280, 0x300)
					mem.Write8(buffer+282, 1)
					mem.Write8(buffer+283, 0)
				}
			}
			ctx.SetReturn(0)
			return 0
		})
	}

	registerApphelpDLL := func(dll *ntapi.SynthPE) {
		if dll == nil {
			return
		}

		d.RegisterAutoStubHandler(dll, "ApphelpCheckShellObject", func(ctx *ntapi.TrapContext) uint32 {
			if pullFlags := ctx.Arg(2); pullFlags != 0 {
				mem.Write32(pullFlags, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "ShimFlushCache", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbGetAppPatchDir", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(writeUTF16StringCount(ctx.Arg(1), `C:\Windows\AppPatch`, ctx.Arg(2)))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbInitDatabase", func(ctx *ntapi.TrapContext) uint32 {
			path := readGuestUTF16(ctx.Arg(1))
			appCompat.mu.Lock()
			handle := appCompat.nextDB
			appCompat.nextDB++
			appCompat.shimDB[handle] = path
			appCompat.mu.Unlock()
			ctx.SetReturn(uint64(handle))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbReleaseDatabase", func(ctx *ntapi.TrapContext) uint32 {
			hSDB := uint32(ctx.Arg(0))
			appCompat.mu.Lock()
			delete(appCompat.shimDB, hSDB)
			appCompat.mu.Unlock()
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbOpenDatabase", func(ctx *ntapi.TrapContext) uint32 {
			path := readGuestUTF16(ctx.Arg(0))
			appCompat.mu.Lock()
			handle := appCompat.nextDB
			appCompat.nextDB++
			appCompat.shimDB[handle] = path
			appCompat.mu.Unlock()
			ctx.SetReturn(uint64(handle))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbCloseDatabase", func(ctx *ntapi.TrapContext) uint32 {
			hSDB := uint32(ctx.Arg(0))
			appCompat.mu.Lock()
			delete(appCompat.shimDB, hSDB)
			appCompat.mu.Unlock()
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbFindFirstTag", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbFindNextTag", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbGetFirstChild", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbGetNextChild", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbGetTagFromTagID", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbReadStringTag", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbReadDWORDTag", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(2))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbReadQWORDTag", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(2))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbReadBinaryTag", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbGetStringTagPtr", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbGetTagDataSize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbTagToString", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbIsNullGUID", func(ctx *ntapi.TrapContext) uint32 {
			pGuid := ctx.Arg(0)
			if pGuid == 0 {
				ctx.SetReturn(1)
				return 0
			}
			allZero := true
			for i := uint64(0); i < 16; i++ {
				b, _ := mem.Read8(pGuid + i)
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbGetMatchingExe", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbFreeFileAttributes", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "SdbGetFileAttributes", func(ctx *ntapi.TrapContext) uint32 {
			if pdwAttrCount := ctx.Arg(2); pdwAttrCount != 0 {
				mem.Write32(pdwAttrCount, 0)
			}
			ctx.SetReturn(0)
			return 0
		})
	}

	registerCompatDLL(hctx.SynthByName["kernelbase.dll"])
	registerCompatDLL(hctx.SynthByName["kernel32.dll"])
	registerRtlGetVersion(hctx.SynthByName["kernelbase.dll"])
	registerRtlGetVersion(hctx.SynthByName["ntdll.dll"])
	registerApphelpDLL(hctx.SynthByName["apphelp.dll"])
}
