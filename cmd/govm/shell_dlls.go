package main

import (
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
)

// csidlToPath maps a CSIDL folder ID to its fake Windows path.
func csidlToPath(csidl int32) string {
	switch csidl & 0xFF {
	case 0x00:
		return `C:\Users\user\Desktop`
	case 0x05:
		return `C:\Users\user\Documents`
	case 0x06:
		return `C:\Users\user\Favorites`
	case 0x08:
		return `C:\Users\user\AppData\Roaming\Microsoft\Windows\Recent`
	case 0x09:
		return `C:\Users\user\AppData\Roaming\Microsoft\Windows\SendTo`
	case 0x0B:
		return `C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu`
	case 0x0D:
		return `C:\Users\user\Music`
	case 0x0E:
		return `C:\Users\user\Videos`
	case 0x10:
		return `C:\Windows\Desktop`
	case 0x11:
		return `C:\`
	case 0x14:
		return `C:\Windows\Fonts`
	case 0x1A:
		return `C:\Users\user\AppData\Roaming`
	case 0x1C:
		return `C:\Users\user\AppData\Local`
	case 0x1D:
		return `C:\Windows\Temp`
	case 0x23:
		return `C:\ProgramData`
	case 0x24:
		return `C:\Windows`
	case 0x25:
		return `C:\Windows\System32`
	case 0x26:
		return `C:\Program Files`
	case 0x27:
		return `C:\Users\user\Pictures`
	case 0x28:
		return `C:\Users\user`
	case 0x29:
		return `C:\Windows\System32`
	case 0x2A:
		return `C:\Program Files`
	case 0x2B:
		return `C:\Program Files\Common Files`
	default:
		return `C:\Users\user`
	}
}

// parseCommandLine splits a Windows command line string respecting double-quotes.
func parseCommandLine(cmd string) []string {
	var args []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		switch {
		case ch == '"':
			inQ = !inQ
		case ch == '\\' && inQ && i+1 < len(cmd) && cmd[i+1] == '"':
			cur.WriteByte('"')
			i++
		case (ch == ' ' || ch == '\t') && !inQ:
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}

// readGUIDString reads a 16-byte GUID from guest memory and formats it.
func readGUIDString(mem interface {
	Read8(uint64) (byte, error)
}, addr uint64) string {
	b := make([]byte, 16)
	for i := range b {
		v, _ := mem.Read8(addr + uint64(i))
		b[i] = v
	}
	d1 := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	d2 := uint16(b[4]) | uint16(b[5])<<8
	d3 := uint16(b[6]) | uint16(b[7])<<8
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func registerShcoreHandlers1(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem

	shcore, ok := hctx.SynthByName["shcore.dll"]
	if !ok {
		return
	}
	_ = shcore

	nextDynID := uint32(ntapi.DynExportIDBase + 0x100) // offset to avoid user32 collision
	d.RegisterDynamicHandler(mem, shcore, "GetDpiForMonitor", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		// hMonitor, dpiType, *dpiX, *dpiY → S_OK
		dpiX := ctx.Arg(2)
		dpiY := ctx.Arg(3)
		if dpiX != 0 {
			mem.Write32(dpiX, 96)
		}
		if dpiY != 0 {
			mem.Write32(dpiY, 96)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, shcore, "GetScaleFactorForMonitor", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		// hMonitor, *pScale → S_OK
		pScale := ctx.Arg(1)
		if pScale != 0 {
			mem.Write32(pScale, 100)
		} // SCALE_100_PERCENT
		ctx.SetReturn(0) // S_OK
		return 0
	})
	nextDynID++
	_ = nextDynID
}

func registerShlwapiHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16
	wideprintf := hctx.Wideprintf

	shlwapi, ok := hctx.SynthByName["shlwapi.dll"]
	if !ok {
		return
	}
	_ = shlwapi

	d.RegisterAutoStubHandler(shlwapi, "PathRemoveFileSpecW", func(ctx *ntapi.TrapContext) uint32 {
		path := ctx.Arg(0)
		// Find last backslash and null-terminate there
		lastSlash := uint64(0)
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(path + i)
			if w == 0 {
				break
			}
			if w == '\\' || w == '/' {
				lastSlash = i
			}
		}
		if lastSlash > 0 {
			ctx.Mem.Write16(path+lastSlash, 0)
			ctx.SetReturn(1) // TRUE
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	// wnsprintfW(lpOut, cchLimitIn, lpFmt, ...) - like snprintf for wide strings
	d.RegisterAutoStubHandler(shlwapi, "wnsprintfW", func(ctx *ntapi.TrapContext) uint32 {
		lpOut := ctx.Arg(0)
		cchLimit := int(int32(ctx.Arg(1)))
		lpFmt := ctx.Arg(2)
		fmtStr := readGuestUTF16(lpFmt)
		var args []uint64
		for i := 3; i < 10; i++ {
			args = append(args, ctx.Arg(i))
		}
		result := wideprintf(fmtStr, args)
		runes := []rune(result)
		n := len(runes)
		if cchLimit > 0 && n >= cchLimit {
			n = cchLimit - 1
		}
		for i := 0; i < n; i++ {
			mem.Write16(lpOut+uint64(i)*2, uint16(runes[i]))
		}
		mem.Write16(lpOut+uint64(n)*2, 0)
		ctx.SetReturn(uint64(n))
		return 0
	})
	// ColorRGBToHLS: convert COLORREF to HLS - store results in out-params
	d.RegisterAutoStubHandler(shlwapi, "ColorRGBToHLS", func(ctx *ntapi.TrapContext) uint32 {
		clr := uint32(ctx.Arg(0))
		pHue := ctx.Arg(1)
		pLum := ctx.Arg(2)
		pSat := ctx.Arg(3)
		r := float64((clr) & 0xFF)
		g := float64((clr >> 8) & 0xFF)
		b := float64((clr >> 16) & 0xFF)
		r /= 255
		g /= 255
		b /= 255
		maxC := math.Max(math.Max(r, g), b)
		minC := math.Min(math.Min(r, g), b)
		l := (maxC + minC) / 2
		var h, s float64
		if maxC != minC {
			d := maxC - minC
			if l > 0.5 {
				s = d / (2 - maxC - minC)
			} else {
				s = d / (maxC + minC)
			}
			switch maxC {
			case r:
				h = (g - b) / d
				if g < b {
					h += 6
				}
			case g:
				h = (b-r)/d + 2
			case b:
				h = (r-g)/d + 4
			}
			h /= 6
		}
		// Windows HLS: Hue 0-240, Lum 0-240, Sat 0-240
		if pHue != 0 {
			mem.Write16(pHue, uint16(h*240))
		}
		if pLum != 0 {
			mem.Write16(pLum, uint16(l*240))
		}
		if pSat != 0 {
			mem.Write16(pSat, uint16(s*240))
		}
		return 0
	})
	// ColorHLSToRGB: convert Windows HLS (0-240 range) to COLORREF
	d.RegisterAutoStubHandler(shlwapi, "ColorHLSToRGB", func(ctx *ntapi.TrapContext) uint32 {
		wH := float64(ctx.Arg(0)) / 240
		wL := float64(ctx.Arg(1)) / 240
		wS := float64(ctx.Arg(2)) / 240
		hue2rgb := func(p, q, t float64) float64 {
			if t < 0 {
				t++
			}
			if t > 1 {
				t--
			}
			if t < 1.0/6 {
				return p + (q-p)*6*t
			}
			if t < 1.0/2 {
				return q
			}
			if t < 2.0/3 {
				return p + (q-p)*(2.0/3-t)*6
			}
			return p
		}
		var r, g, b float64
		if wS == 0 {
			r, g, b = wL, wL, wL
		} else {
			var q float64
			if wL < 0.5 {
				q = wL * (1 + wS)
			} else {
				q = wL + wS - wL*wS
			}
			p := 2*wL - q
			r = hue2rgb(p, q, wH+1.0/3)
			g = hue2rgb(p, q, wH)
			b = hue2rgb(p, q, wH-1.0/3)
		}
		clr := uint32(r*255) | uint32(g*255)<<8 | uint32(b*255)<<16
		ctx.SetReturn(uint64(clr))
		return 0
	})
	// PathFindFileNameW: returns pointer to filename component within the path
	d.RegisterAutoStubHandler(shlwapi, "PathFindFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		path := ctx.Arg(0)
		if path == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lastSlash := path
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(path + i)
			if w == 0 {
				break
			}
			if w == '\\' || w == '/' {
				lastSlash = path + i + 2
			}
		}
		ctx.SetReturn(lastSlash)
		return 0
	})
	// PathFindExtensionW: returns pointer to the extension (".xxx") within path, or end-of-string
	d.RegisterAutoStubHandler(shlwapi, "PathFindExtensionW", func(ctx *ntapi.TrapContext) uint32 {
		path := ctx.Arg(0)
		if path == 0 {
			ctx.SetReturn(0)
			return 0
		}
		ext := uint64(0)
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(path + i)
			if w == 0 {
				if ext == 0 {
					ext = path + i // point to NUL terminator
				}
				break
			}
			if w == '.' {
				ext = path + i
			} else if w == '\\' || w == '/' {
				ext = 0 // reset: dot was in a directory component
			}
		}
		if ext == 0 {
			// find end of string
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(path + i)
				if w == 0 {
					ext = path + i
					break
				}
			}
		}
		ctx.SetReturn(ext)
		return 0
	})
	// PathIsNetworkPathW: returns TRUE for UNC paths (\\server\share) or drive letters mapped to net
	d.RegisterAutoStubHandler(shlwapi, "PathIsNetworkPathW", func(ctx *ntapi.TrapContext) uint32 {
		path := ctx.Arg(0)
		if path == 0 {
			ctx.SetReturn(0)
			return 0
		}
		w0, _ := ctx.Mem.Read16(path)
		w1, _ := ctx.Mem.Read16(path + 2)
		if (w0 == '\\' || w0 == '/') && (w1 == '\\' || w1 == '/') {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	// PathStripPathW: remove directory component in-place, keep only filename
	d.RegisterAutoStubHandler(shlwapi, "PathStripPathW", func(ctx *ntapi.TrapContext) uint32 {
		path := ctx.Arg(0)
		if path == 0 {
			return 0
		}
		lastSep := uint64(0xFFFFFFFFFFFFFFFF)
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(path + i)
			if w == 0 {
				break
			}
			if w == '\\' || w == '/' {
				lastSep = i
			}
		}
		if lastSep != 0xFFFFFFFFFFFFFFFF {
			src := path + lastSep + 2
			dst := path
			for {
				w, _ := ctx.Mem.Read16(src)
				ctx.Mem.Write16(dst, w)
				src += 2
				dst += 2
				if w == 0 {
					break
				}
			}
		}
		return 0
	})
	// PathAddExtensionW: append extension to path if it has none
	d.RegisterAutoStubHandler(shlwapi, "PathAddExtensionW", func(ctx *ntapi.TrapContext) uint32 {
		path := ctx.Arg(0)
		ext := ctx.Arg(1)
		if path == 0 {
			ctx.SetReturn(0)
			return 0
		}
		hasDot := false
		pathLen := uint64(0)
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(path + i)
			if w == 0 {
				pathLen = i
				break
			}
			if w == '\\' || w == '/' {
				hasDot = false
			} else if w == '.' {
				hasDot = true
			}
		}
		if hasDot {
			ctx.SetReturn(0) // already has extension
			return 0
		}
		if ext == 0 {
			ctx.SetReturn(0)
			return 0
		}
		end := path + pathLen
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(ext + i)
			ctx.Mem.Write16(end+i, w)
			if w == 0 {
				break
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	// PathAppendW: append pszMore to pszPath with backslash separator
	d.RegisterAutoStubHandler(shlwapi, "PathAppendW", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		pszMore := ctx.Arg(1)
		if pszPath == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Find end of pszPath
		end := uint64(0)
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(pszPath + i)
			if w == 0 {
				end = pszPath + i
				break
			}
		}
		// Add separator if path doesn't end with one
		if end > pszPath {
			prev, _ := ctx.Mem.Read16(end - 2)
			if prev != '\\' && prev != '/' {
				ctx.Mem.Write16(end, '\\')
				end += 2
			}
		}
		// Copy pszMore
		if pszMore != 0 {
			// Skip leading separators in pszMore
			moreStart := pszMore
			for {
				w, _ := ctx.Mem.Read16(moreStart)
				if w != '\\' && w != '/' {
					break
				}
				moreStart += 2
			}
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(moreStart + i)
				ctx.Mem.Write16(end+i, w)
				if w == 0 {
					break
				}
			}
		} else {
			ctx.Mem.Write16(end, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	// PathCombineW: combine directory + file into dest
	d.RegisterAutoStubHandler(shlwapi, "PathCombineW", func(ctx *ntapi.TrapContext) uint32 {
		lpszDest := ctx.Arg(0)
		lpszDir := ctx.Arg(1)
		lpszFile := ctx.Arg(2)
		if lpszDest == 0 {
			ctx.SetReturn(0)
			return 0
		}
		writeWStr := func(dst uint64, s string) {
			for i, r := range []rune(s) {
				ctx.Mem.Write16(dst+uint64(i)*2, uint16(r))
			}
			ctx.Mem.Write16(dst+uint64(len([]rune(s)))*2, 0)
		}
		// If lpszFile is absolute, use it directly
		if lpszFile != 0 {
			w0, _ := ctx.Mem.Read16(lpszFile)
			w1, _ := ctx.Mem.Read16(lpszFile + 2)
			isAbsolute := (w1 == ':') || (w0 == '\\' || w0 == '/')
			if isAbsolute {
				for i := uint64(0); ; i += 2 {
					w, _ := ctx.Mem.Read16(lpszFile + i)
					ctx.Mem.Write16(lpszDest+i, w)
					if w == 0 {
						break
					}
				}
				ctx.SetReturn(lpszDest)
				return 0
			}
		}
		// Build combined path
		dir := ""
		if lpszDir != 0 {
			dir = readGuestUTF16(lpszDir)
		}
		file := ""
		if lpszFile != 0 {
			file = readGuestUTF16(lpszFile)
		}
		if dir == "" {
			writeWStr(lpszDest, file)
		} else if file == "" {
			writeWStr(lpszDest, dir)
		} else {
			sep := ""
			if len(dir) > 0 && dir[len(dir)-1] != '\\' && dir[len(dir)-1] != '/' {
				sep = "\\"
			}
			writeWStr(lpszDest, dir+sep+file)
		}
		ctx.SetReturn(lpszDest)
		return 0
	})
	// PathIsRelativeW: TRUE if path has no drive letter and doesn't start with \\
	d.RegisterAutoStubHandler(shlwapi, "PathIsRelativeW", func(ctx *ntapi.TrapContext) uint32 {
		path := ctx.Arg(0)
		if path == 0 {
			ctx.SetReturn(1)
			return 0
		}
		w0, _ := ctx.Mem.Read16(path)
		w1, _ := ctx.Mem.Read16(path + 2)
		if w1 == ':' || (w0 == '\\' && w1 == '\\') || (w0 == '/') {
			ctx.SetReturn(0) // absolute
		} else {
			ctx.SetReturn(1) // relative
		}
		return 0
	})
	// PathRemoveExtensionW: strip the extension from path in-place
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveExtensionW", func(ctx *ntapi.TrapContext) uint32 {
		path := ctx.Arg(0)
		if path == 0 {
			return 0
		}
		dotOff := uint64(0xFFFFFFFFFFFFFFFF)
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(path + i)
			if w == 0 {
				break
			}
			if w == '\\' || w == '/' {
				dotOff = 0xFFFFFFFFFFFFFFFF
			} else if w == '.' {
				dotOff = i
			}
		}
		if dotOff != 0xFFFFFFFFFFFFFFFF {
			ctx.Mem.Write16(path+dotOff, 0)
		}
		return 0
	})
	// PathCompactPathExW: truncate path to cchMax characters
	d.RegisterAutoStubHandler(shlwapi, "PathCompactPathExW", func(ctx *ntapi.TrapContext) uint32 {
		pszOut := ctx.Arg(0)
		pszSrc := ctx.Arg(1)
		cchMax := ctx.Arg(2)
		if pszOut == 0 || pszSrc == 0 || cchMax == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Collect source characters
		var runes []uint16
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(pszSrc + i)
			if w == 0 {
				break
			}
			runes = append(runes, w)
		}
		limit := int(cchMax) - 1
		if limit < 0 {
			limit = 0
		}
		if len(runes) > limit {
			// Replace middle with "..." if possible
			if limit > 5 {
				half := (limit - 3) / 2
				var out []uint16
				out = append(out, runes[:half]...)
				out = append(out, '.', '.', '.')
				out = append(out, runes[len(runes)-half:]...)
				runes = out[:limit]
			} else {
				runes = runes[:limit]
			}
		}
		for i, w := range runes {
			ctx.Mem.Write16(pszOut+uint64(i)*2, w)
		}
		ctx.Mem.Write16(pszOut+uint64(len(runes))*2, 0)
		ctx.SetReturn(1)
		return 0
	})
	// PathGetDriveNumberW: return drive index (0='A') or -1 if none
	d.RegisterAutoStubHandler(shlwapi, "PathGetDriveNumberW", func(ctx *ntapi.TrapContext) uint32 {
		path := ctx.Arg(0)
		if path == 0 {
			ctx.SetReturn(0xFFFFFFFF) // (DWORD)-1
			return 0
		}
		w0, _ := ctx.Mem.Read16(path)
		w1, _ := ctx.Mem.Read16(path + 2)
		if w1 == ':' {
			var drv uint16
			if w0 >= 'a' && w0 <= 'z' {
				drv = w0 - 'a'
			} else if w0 >= 'A' && w0 <= 'Z' {
				drv = w0 - 'A'
			} else {
				ctx.SetReturn(0xFFFFFFFF)
				return 0
			}
			ctx.SetReturn(uint64(drv))
		} else {
			ctx.SetReturn(0xFFFFFFFF)
		}
		return 0
	})
	// PathMatchSpecW: simple wildcard match (* and ?)
	d.RegisterAutoStubHandler(shlwapi, "PathMatchSpecW", func(ctx *ntapi.TrapContext) uint32 {
		pszFile := ctx.Arg(0)
		pszSpec := ctx.Arg(1)
		if pszFile == 0 || pszSpec == 0 {
			ctx.SetReturn(0)
			return 0
		}
		file := readGuestUTF16(pszFile)
		spec := readGuestUTF16(pszSpec)
		// Simple case-insensitive wildcard match
		var matchFn func(f, s string) bool
		matchFn = func(f, s string) bool {
			for len(s) > 0 {
				sc := rune(s[0])
				s = s[1:]
				switch sc {
				case '*':
					for i := 0; i <= len(f); i++ {
						if matchFn(f[i:], s) {
							return true
						}
					}
					return false
				case '?':
					if len(f) == 0 {
						return false
					}
					f = f[1:]
				default:
					if len(f) == 0 {
						return false
					}
					fc := rune(f[0])
					f = f[1:]
					if fc >= 'A' && fc <= 'Z' {
						fc += 32
					}
					if sc >= 'A' && sc <= 'Z' {
						sc += 32
					}
					if fc != sc {
						return false
					}
				}
			}
			return len(f) == 0
		}
		if matchFn(file, spec) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	// AssocQueryStringW: file type association query - not supported in emulator
	d.RegisterAutoStubHandler(shlwapi, "AssocQueryStringW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x80004005) // E_FAIL - no associations
		return 0
	})
	// ColorAdjustLuma: adjust luminosity of a COLORREF by n/240
	d.RegisterAutoStubHandler(shlwapi, "ColorAdjustLuma", func(ctx *ntapi.TrapContext) uint32 {
		clr := uint32(ctx.Arg(0))
		n := int32(ctx.Arg(1))
		fScale := ctx.Arg(2) != 0
		r := float64(clr&0xFF) / 255
		g := float64((clr>>8)&0xFF) / 255
		b := float64((clr>>16)&0xFF) / 255
		maxC := math.Max(math.Max(r, g), b)
		minC := math.Min(math.Min(r, g), b)
		l := (maxC + minC) / 2
		var h, s float64
		if maxC != minC {
			d2 := maxC - minC
			if l > 0.5 {
				s = d2 / (2 - maxC - minC)
			} else {
				s = d2 / (maxC + minC)
			}
			switch maxC {
			case r:
				h = (g - b) / d2
				if g < b {
					h += 6
				}
			case g:
				h = (b-r)/d2 + 2
			case b:
				h = (r-g)/d2 + 4
			}
			h /= 6
		}
		// Adjust luma
		delta := float64(n) / 240
		if fScale {
			if n > 0 {
				l += (1 - l) * delta
			} else {
				l += l * delta
			}
		} else {
			l += delta
		}
		if l < 0 {
			l = 0
		} else if l > 1 {
			l = 1
		}
		// Convert back HLS→RGB
		hue2rgb := func(p, q, t float64) float64 {
			if t < 0 {
				t++
			}
			if t > 1 {
				t--
			}
			if t < 1.0/6 {
				return p + (q-p)*6*t
			}
			if t < 1.0/2 {
				return q
			}
			if t < 2.0/3 {
				return p + (q-p)*(2.0/3-t)*6
			}
			return p
		}
		var nr, ng, nb float64
		if s == 0 {
			nr, ng, nb = l, l, l
		} else {
			var q float64
			if l < 0.5 {
				q = l * (1 + s)
			} else {
				q = l + s - l*s
			}
			p := 2*l - q
			nr = hue2rgb(p, q, h+1.0/3)
			ng = hue2rgb(p, q, h)
			nb = hue2rgb(p, q, h-1.0/3)
		}
		result := uint32(nr*255) | uint32(ng*255)<<8 | uint32(nb*255)<<16
		ctx.SetReturn(uint64(result))
		return 0
	})
	// Path existence / type helpers
	d.RegisterAutoStubHandler(shlwapi, "PathFileExistsA", func(ctx *ntapi.TrapContext) uint32 {
		p := winPathToVFS(readGuestString(ctx.Arg(0)))
		if _, err := os.Stat(p); err == nil {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFileExistsW", func(ctx *ntapi.TrapContext) uint32 {
		p := winPathToVFS(readGuestUTF16(ctx.Arg(0)))
		if _, err := os.Stat(p); err == nil {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		p := winPathToVFS(readGuestString(ctx.Arg(0)))
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			ctx.SetReturn(0x10)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		p := winPathToVFS(readGuestUTF16(ctx.Arg(0)))
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			ctx.SetReturn(0x10)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsDirectoryEmptyW", func(ctx *ntapi.TrapContext) uint32 {
		p := winPathToVFS(readGuestUTF16(ctx.Arg(0)))
		entries, err := os.ReadDir(p)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		if len(entries) == 0 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsURLA", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestString(ctx.Arg(0))
		if strings.Contains(s, "://") {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsURLW", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestUTF16(ctx.Arg(0))
		if strings.Contains(s, "://") {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathStripToRootW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		s := readGuestUTF16(buf)
		// Extract root: e.g. "C:\foo\bar" → "C:\"
		root := s
		if len(s) >= 3 && s[1] == ':' {
			root = s[:3]
		}
		ws := utf16Encode(root)
		for i, w := range ws {
			mem.Write16(buf+uint64(i)*2, w)
		}
		mem.Write16(buf+uint64(len(ws))*2, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUnquoteSpacesA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		s := readGuestString(buf)
		if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
			s = s[1 : len(s)-1]
		}
		b := append([]byte(s), 0)
		for i, c := range b {
			mem.Write8(buf+uint64(i), c)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUnquoteSpacesW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		s := readGuestUTF16(buf)
		if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
			s = s[1 : len(s)-1]
		}
		ws := utf16Encode(s)
		for i, w := range ws {
			mem.Write16(buf+uint64(i)*2, w)
		}
		mem.Write16(buf+uint64(len(ws))*2, 0)
		return 0
	})

	// ═══════════════════════════════════════════════════════════════
	// AUTO-GENERATED: Missing shlwapi handlers from ReactOS spec
	// ═══════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(shlwapi, "AppendMenuWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] AppendMenuWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocCreate", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] AssocCreate(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocGetPerceivedType", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] AssocGetPerceivedType(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocIsDangerous", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] AssocIsDangerous(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocQueryKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] AssocQueryKeyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocQueryKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] AssocQueryKeyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocQueryStringA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] AssocQueryStringA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocQueryStringByKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] AssocQueryStringByKeyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocQueryStringByKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] AssocQueryStringByKeyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CLSIDFromProgIDWrap", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] CLSIDFromProgIDWrap(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CLSIDFromStringWrap", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] CLSIDFromStringWrap(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CallMsgFilterWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] CallMsgFilterWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CallWindowProcWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] CallWindowProcWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharLowerBuffWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] CharLowerBuffWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharLowerWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CharLowerWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharNextWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CharNextWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharPrevWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] CharPrevWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharToOemWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CharToOemWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharUpperBuffWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] CharUpperBuffWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharUpperWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CharUpperWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ChrCmpIA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] ChrCmpIA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ChrCmpIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] ChrCmpIW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CompareStringAltW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] CompareStringAltW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CompareStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] CompareStringWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ConnectToConnectionPoint", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] ConnectToConnectionPoint(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CopyAcceleratorTableWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] CopyAcceleratorTableWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CopyFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] CopyFileWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateAcceleratorTableWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] CreateAcceleratorTableWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateColorSpaceWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CreateColorSpaceWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateDCWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] CreateDCWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateDialogIndirectParamWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] CreateDialogIndirectParamWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateDialogParamWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] CreateDialogParamWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateDirectoryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] CreateDirectoryWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateEventWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] CreateEventWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] CreateFileWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateFontIndirectWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CreateFontIndirectWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateFontWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] CreateFontWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateICWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] CreateICWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateMetaFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CreateMetaFileWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateMutexWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] CreateMutexWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateProcessWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] CreateProcessWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateSemaphoreWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] CreateSemaphoreWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateWindowExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] CreateWindowExWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DdeCreateStringHandleWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] DdeCreateStringHandleWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DdeInitializeWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] DdeInitializeWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DdeQueryStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] DdeQueryStringWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DefWindowProcWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] DefWindowProcWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DelayLoadFailureHook", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] DelayLoadFailureHook(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DeleteFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] DeleteFileWrapW(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DeleteMenuWrap", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] DeleteMenuWrap(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DestroyMenuWrap", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] DestroyMenuWrap(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DialogBoxIndirectParamWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] DialogBoxIndirectParamWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DialogBoxParamWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] DialogBoxParamWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DispatchMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] DispatchMessageWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DllGetVersion", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] DllGetVersion(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DoesStringRoundTripA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] DoesStringRoundTripA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DoesStringRoundTripW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] DoesStringRoundTripW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DragQueryFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] DragQueryFileWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DrawTextExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] DrawTextExWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DrawTextWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] DrawTextWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "EndDialogWrap", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] EndDialogWrap(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "EnumFontFamiliesExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] EnumFontFamiliesExWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "EnumFontFamiliesWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] EnumFontFamiliesWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "EnumResourceNamesWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] EnumResourceNamesWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ExpandEnvironmentStringsWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] ExpandEnvironmentStringsWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ExtTextOutWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] ExtTextOutWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ExtractIconExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] ExtractIconExWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ExtractIconWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] ExtractIconWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FDSA_DeleteItem", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] FDSA_DeleteItem(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FDSA_Destroy", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] FDSA_Destroy(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FDSA_Initialize", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] FDSA_Initialize(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FDSA_InsertItem", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] FDSA_InsertItem(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FindFirstFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] FindFirstFileWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FindNextFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] FindNextFileWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FindResourceWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] FindResourceWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FindWindowExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] FindWindowExWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FindWindowWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] FindWindowWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FixSlashesAndColonW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] FixSlashesAndColonW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FormatMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] FormatMessageWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GUIDFromStringA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GUIDFromStringA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GUIDFromStringW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GUIDFromStringW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetAcceptLanguagesA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetAcceptLanguagesA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetAcceptLanguagesW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetAcceptLanguagesW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetCharWidth32WrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetCharWidth32WrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetCharacterPlacementWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] GetCharacterPlacementWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetClassInfoExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetClassInfoExWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetClassInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetClassInfoWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetClassLongWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetClassLongWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetClassNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetClassNameWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetClipboardFormatNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetClipboardFormatNameWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetCurrentDirectoryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetCurrentDirectoryWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetDateFormatWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] GetDateFormatWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetDlgItemTextWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetDlgItemTextWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetEnvironmentVariableWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetEnvironmentVariableWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetFileAttributesWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GetFileAttributesWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetFileVersionInfoSizeWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetFileVersionInfoSizeWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetFileVersionInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetFileVersionInfoWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetFullPathNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetFullPathNameWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetLocaleInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetLocaleInfoWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetLongPathNameWrapA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetLongPathNameWrapA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetLongPathNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetLongPathNameWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetMIMETypeSubKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetMIMETypeSubKeyA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetMIMETypeSubKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetMIMETypeSubKeyW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetMenuItemInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetMenuItemInfoWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetMenuPosFromID", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetMenuPosFromID(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetMenuStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] GetMenuStringWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetMessageWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetModuleFileNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetModuleFileNameWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetModuleHandleWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GetModuleHandleWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetNumberFormatWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] GetNumberFormatWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetObjectWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetObjectWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetOpenFileNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GetOpenFileNameWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetPerfTime", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] GetPerfTime()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetPrivateProfileIntWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetPrivateProfileIntWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetPrivateProfileStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] GetPrivateProfileStringWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetPrivateProfileStructWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] GetPrivateProfileStructWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetProfileStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] GetProfileStringWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetPropWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetPropWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetSaveFileNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GetSaveFileNameWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetShellSecurityDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetShellSecurityDescriptor(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetShortPathNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetShortPathNameWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetStringType3ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetStringType3ExW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetStringTypeExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] GetStringTypeExWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetSystemDirectoryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetSystemDirectoryWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetTempFileNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetTempFileNameWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetTempPathWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetTempPathWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetTextExtentPoint32WrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetTextExtentPoint32WrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetTextFaceWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetTextFaceWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetTextMetricsWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetTextMetricsWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetTimeFormatWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] GetTimeFormatWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetUIVersion", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] GetUIVersion()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetUserNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetUserNameWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetWindowLongWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetWindowLongWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetWindowTextLengthWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GetWindowTextLengthWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetWindowTextWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetWindowTextWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetWindowsDirectoryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetWindowsDirectoryWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GlobalAddAtomWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GlobalAddAtomWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GlobalFindAtomWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GlobalFindAtomWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "HashData", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] HashData(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IConnectionPoint_InvokeWithCancel", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] IConnectionPoint_InvokeWithCancel(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IConnectionPoint_OnChanged", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] IConnectionPoint_OnChanged(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IConnectionPoint_SimpleInvoke", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] IConnectionPoint_SimpleInvoke(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IContextMenu_Invoke", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] IContextMenu_Invoke(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IShellFolder_CompareIDs", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] IShellFolder_CompareIDs(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IShellFolder_EnumObjects", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] IShellFolder_EnumObjects(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IShellFolder_GetDisplayNameOf", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] IShellFolder_GetDisplayNameOf(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IShellFolder_ParseDisplayName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] IShellFolder_ParseDisplayName(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IStream_Read", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] IStream_Read(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IStream_Reset", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IStream_Reset(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IStream_Size", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] IStream_Size(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IStream_Write", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] IStream_Write(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_AtomicRelease", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IUnknown_AtomicRelease(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_CPContainerInvokeParam", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] IUnknown_CPContainerInvokeParam(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_CPContainerOnChanged", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_CPContainerOnChanged(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_EnableModeless", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_EnableModeless(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_Exec", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] IUnknown_Exec(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_GetClassID", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_GetClassID(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_GetSite", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] IUnknown_GetSite(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_GetWindow", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_GetWindow(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_HandleIRestrict", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] IUnknown_HandleIRestrict(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_HasFocusIO", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IUnknown_HasFocusIO(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_OnFocusChangeIS", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] IUnknown_OnFocusChangeIS(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_OnFocusOCS", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_OnFocusOCS(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_ProfferService", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] IUnknown_ProfferService(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_QueryService", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] IUnknown_QueryService(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_QueryServiceExec", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] IUnknown_QueryServiceExec(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_QueryServiceForWebBrowserApp", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] IUnknown_QueryServiceForWebBrowserApp(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_QueryServicePropertyBag", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] IUnknown_QueryServicePropertyBag(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_QueryStatus", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] IUnknown_QueryStatus(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_Set", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_Set(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_SetOwner", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_SetOwner(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_SetSite", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_SetSite(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_TranslateAcceleratorIO", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_TranslateAcceleratorIO(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_TranslateAcceleratorOCS", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] IUnknown_TranslateAcceleratorOCS(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_UIActivateIO", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] IUnknown_UIActivateIO(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "InsertMenuItemWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] InsertMenuItemWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "InsertMenuWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] InsertMenuWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IntlStrEqWorkerA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] IntlStrEqWorkerA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IntlStrEqWorkerW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] IntlStrEqWorkerW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsBadStringPtrWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] IsBadStringPtrWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharAlphaNumericWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharAlphaNumericWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharAlphaWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharAlphaWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharBlankW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharBlankW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharCntrlW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharCntrlW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharDigitW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharDigitW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharLowerWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharLowerWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharPunctW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharPunctW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharSpaceA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharSpaceA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharSpaceW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharSpaceW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharUpperWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharUpperWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharXDigitW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharXDigitW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsDialogMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] IsDialogMessageWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsInternetESCEnabled", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] IsInternetESCEnabled()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsOS", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsOS(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsQSForward", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] IsQSForward(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadAcceleratorsWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] LoadAcceleratorsWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadBitmapWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] LoadBitmapWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadCursorWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] LoadCursorWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadIconWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] LoadIconWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadImageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] LoadImageWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadLibraryExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] LoadLibraryExWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadLibraryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] LoadLibraryWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadMenuWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] LoadMenuWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] LoadStringWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MIME_GetExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] MIME_GetExtensionA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MIME_GetExtensionW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] MIME_GetExtensionW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLBuildResURLA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] MLBuildResURLA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLBuildResURLW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] MLBuildResURLW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLClearMLHInstance", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] MLClearMLHInstance(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLFreeLibrary", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] MLFreeLibrary(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLGetUILanguage", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] MLGetUILanguage()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLIsMLHInstance", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] MLIsMLHInstance(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLLoadLibraryA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] MLLoadLibraryA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLLoadLibraryW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] MLLoadLibraryW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLSetMLHInstance", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] MLSetMLHInstance(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MayExecForward", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] MayExecForward(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MayQSForward", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] MayQSForward(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MessageBoxIndirectWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] MessageBoxIndirectWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MessageBoxWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] MessageBoxWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ModifyMenuWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] ModifyMenuWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MoveFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] MoveFileWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "OemToCharWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] OemToCharWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "OpenEventWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] OpenEventWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "OutputDebugStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] OutputDebugStringWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PageSetupDlgWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PageSetupDlgWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ParseURLA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] ParseURLA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ParseURLW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] ParseURLW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathAddBackslashA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathAddBackslashA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathAddBackslashW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathAddBackslashW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathAddExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathAddExtensionA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathAppendA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathAppendA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathBuildRootA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathBuildRootA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathBuildRootW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathBuildRootW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCanonicalizeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathCanonicalizeA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCanonicalizeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathCanonicalizeW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCombineA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathCombineA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCommonPrefixA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathCommonPrefixA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCommonPrefixW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathCommonPrefixW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCompactPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathCompactPathA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCompactPathExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] PathCompactPathExA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCompactPathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathCompactPathW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCreateFromUrlA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] PathCreateFromUrlA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCreateFromUrlW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] PathCreateFromUrlW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFileExistsAndAttributesA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathFileExistsAndAttributesA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFileExistsAndAttributesW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathFileExistsAndAttributesW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFileExistsDefExtA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathFileExistsDefExtA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFileExistsDefExtAndAttributesW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathFileExistsDefExtAndAttributesW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFileExistsDefExtW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathFileExistsDefExtW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathFindExtensionA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathFindFileNameA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindNextComponentA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathFindNextComponentA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindNextComponentW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathFindNextComponentW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindOnPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathFindOnPathA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindOnPathExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathFindOnPathExA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindOnPathExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathFindOnPathExW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindOnPathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathFindOnPathW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindSuffixArrayA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathFindSuffixArrayA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindSuffixArrayW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathFindSuffixArrayW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathGetArgsA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathGetArgsA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathGetArgsW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathGetArgsW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathGetCharTypeA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathGetCharTypeA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathGetCharTypeW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathGetCharTypeW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathGetDriveNumberA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathGetDriveNumberA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsContentTypeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsContentTypeA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsContentTypeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsContentTypeW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsDirectoryEmptyA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsDirectoryEmptyA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsFileSpecA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsFileSpecA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsFileSpecW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsFileSpecW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsLFNFileSpecA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsLFNFileSpecA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsLFNFileSpecW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsLFNFileSpecW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsNetworkPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsNetworkPathA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsPrefixA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsPrefixA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsPrefixW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsPrefixW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsRelativeA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsRelativeA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsRootA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsRootA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsRootW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsRootW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsSameRootA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsSameRootA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsSameRootW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsSameRootW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsSystemFolderA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsSystemFolderA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsSystemFolderW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsSystemFolderW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsUNCA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsUNCA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsUNCServerA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsUNCServerA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsUNCServerShareA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsUNCServerShareA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsUNCServerShareW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsUNCServerShareW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsUNCServerW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsUNCServerW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsUNCW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsUNCW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsValidCharA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsValidCharA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsValidCharW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsValidCharW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathMakePrettyA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathMakePrettyA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathMakePrettyW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathMakePrettyW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathMakeSystemFolderA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathMakeSystemFolderA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathMakeSystemFolderW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathMakeSystemFolderW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathMatchSpecA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathMatchSpecA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathParseIconLocationA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathParseIconLocationA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathParseIconLocationW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathParseIconLocationW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathQuoteSpacesA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathQuoteSpacesA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathQuoteSpacesW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathQuoteSpacesW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRelativePathToA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] PathRelativePathToA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRelativePathToW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] PathRelativePathToW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveArgsA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveArgsA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveArgsW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveArgsW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveBackslashA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveBackslashA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveBackslashW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveBackslashW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveBlanksA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveBlanksA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveBlanksW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveBlanksW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveExtensionA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveFileSpecA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveFileSpecA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRenameExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathRenameExtensionA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRenameExtensionW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathRenameExtensionW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSearchAndQualifyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathSearchAndQualifyA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSearchAndQualifyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathSearchAndQualifyW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSetDlgItemPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathSetDlgItemPathA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSetDlgItemPathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathSetDlgItemPathW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSkipLeadingSlashesA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathSkipLeadingSlashesA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSkipRootA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathSkipRootA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSkipRootW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathSkipRootW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathStripPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathStripPathA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathStripToRootA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathStripToRootA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUnExpandEnvStringsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathUnExpandEnvStringsA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUnExpandEnvStringsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathUnExpandEnvStringsW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUndecorateA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathUndecorateA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUndecorateW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathUndecorateW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUnmakeSystemFolderA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathUnmakeSystemFolderA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUnmakeSystemFolderW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathUnmakeSystemFolderW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PeekMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] PeekMessageWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PlaySoundWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] PlaySoundWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PostMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] PostMessageWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PostThreadMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] PostThreadMessageWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PrintDlgWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PrintDlgWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "QISearch", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] QISearch(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegCreateKeyExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] RegCreateKeyExWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegCreateKeyWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] RegCreateKeyWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegDeleteKeyWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegDeleteKeyWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegDeleteValueWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegDeleteValueWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegEnumKeyExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] RegEnumKeyExWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegEnumKeyWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] RegEnumKeyWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegEnumValueWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] RegEnumValueWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegOpenKeyExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] RegOpenKeyExWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegOpenKeyWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] RegOpenKeyWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegQueryInfoKeyWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] RegQueryInfoKeyWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegQueryValueExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] RegQueryValueExWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegQueryValueWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] RegQueryValueWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegSetValueExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] RegSetValueExWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegSetValueWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] RegSetValueWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterClassExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] RegisterClassExWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterClassWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] RegisterClassWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterClipboardFormatWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] RegisterClipboardFormatWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterDefaultAcceptHeaders", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegisterDefaultAcceptHeaders(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterExtensionForMIMETypeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegisterExtensionForMIMETypeA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterExtensionForMIMETypeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegisterExtensionForMIMETypeW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterMIMETypeForExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegisterMIMETypeForExtensionA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterMIMETypeForExtensionW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegisterMIMETypeForExtensionW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterWindowMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] RegisterWindowMessageWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RemoveDirectoryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] RemoveDirectoryWrapW(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RemovePropWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] RemovePropWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RunIndirectRegCommand", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] RunIndirectRegCommand(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RunRegCommand", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] RunRegCommand(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAboutInfoA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHAboutInfoA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAboutInfoW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHAboutInfoW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAddDataBlock", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHAddDataBlock(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAllocShared", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHAllocShared(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAnsiToAnsi", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHAnsiToAnsi(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAnsiToUnicode", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHAnsiToUnicode(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAnsiToUnicodeCP", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHAnsiToUnicodeCP(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAreIconsEqual", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHAreIconsEqual(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAutoComplete", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHAutoComplete(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHBoolSystemParametersInfo", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHBoolSystemParametersInfo(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHBrowseForFolderWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHBrowseForFolderWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHChangeNotifyWrap", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHChangeNotifyWrap(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCheckMenuItem", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHCheckMenuItem(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCoCreateInstanceAC", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHCoCreateInstanceAC(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCopyKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHCopyKeyA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCopyKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHCopyKeyW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateMemStream", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHCreateMemStream(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreatePropertyBagOnMemory", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHCreatePropertyBagOnMemory(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreatePropertyBagOnProfileSection", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHCreatePropertyBagOnProfileSection(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreatePropertyBagOnRegKey", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHCreatePropertyBagOnRegKey(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateShellPalette", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHCreateShellPalette(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateStreamOnFileA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHCreateStreamOnFileA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateStreamOnFileEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHCreateStreamOnFileEx(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateStreamOnFileW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHCreateStreamOnFileW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateStreamWrapper", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHCreateStreamWrapper(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateThread", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHCreateThread(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateThreadRef", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHCreateThreadRef(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateWorkerWindowA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHCreateWorkerWindowA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateWorkerWindowW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHCreateWorkerWindowW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDefExtractIconWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHDefExtractIconWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDefWindowProc", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHDefWindowProc(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteEmptyKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHDeleteEmptyKeyA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteEmptyKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHDeleteEmptyKeyW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHDeleteKeyA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHDeleteKeyW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteOrphanKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHDeleteOrphanKeyA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteOrphanKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHDeleteOrphanKeyW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteValueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHDeleteValueA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHDeleteValueW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHEnableMenuItem", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHEnableMenuItem(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHEnumKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHEnumKeyExA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHEnumKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHEnumKeyExW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHEnumValueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHEnumValueA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHEnumValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHEnumValueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHExpandEnvironmentStringsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHExpandEnvironmentStringsA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHExpandEnvironmentStringsForUserA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHExpandEnvironmentStringsForUserA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHExpandEnvironmentStringsForUserW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHExpandEnvironmentStringsForUserW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHExpandEnvironmentStringsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHExpandEnvironmentStringsW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFileOperationWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHFileOperationWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFillRectClr", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHFillRectClr(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFindDataBlock", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHFindDataBlock(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFlushSFCacheWrap", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] SHFlushSFCacheWrap()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFormatDateTimeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHFormatDateTimeA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFormatDateTimeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHFormatDateTimeW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHForwardContextMenuMsg", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHForwardContextMenuMsg(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFreeDataBlockList", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHFreeDataBlockList(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFreeShared", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHFreeShared(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetAppCompatFlags", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGetAppCompatFlags(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetCurColorRes", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] SHGetCurColorRes()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetFileInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHGetFileInfoWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetIniStringUTF7W", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHGetIniStringUTF7W(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetIniStringW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHGetIniStringW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetInverseCMAP", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGetInverseCMAP(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetMachineInfo", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGetMachineInfo(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetMenuFromID", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGetMenuFromID(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetNewLinkInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHGetNewLinkInfoWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetObjectCompatFlags", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGetObjectCompatFlags(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetPathFromIDListWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGetPathFromIDListWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetPerScreenResName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHGetPerScreenResName(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetRestriction", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHGetRestriction(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetShellKey", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHGetShellKey(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetSystemWindowsDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGetSystemWindowsDirectoryA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetSystemWindowsDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGetSystemWindowsDirectoryW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetThreadRef", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGetThreadRef(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetValueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHGetValueA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetValueGoodBootA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHGetValueGoodBootA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetValueGoodBootW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHGetValueGoodBootW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHGetValueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetViewStatePropertyBag", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHGetViewStatePropertyBag(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetWebFolderFilePathA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHGetWebFolderFilePathA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetWebFolderFilePathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHGetWebFolderFilePathW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGlobalCounterCreate", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGlobalCounterCreate(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGlobalCounterCreateNamedA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGlobalCounterCreateNamedA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGlobalCounterCreateNamedW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGlobalCounterCreateNamedW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGlobalCounterDecrement", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGlobalCounterDecrement(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGlobalCounterGetValue", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGlobalCounterGetValue(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGlobalCounterIncrement", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGlobalCounterIncrement(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHInterlockedCompareExchange", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHInterlockedCompareExchange(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHInvokeCommand", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHInvokeCommand(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHInvokeCommandOnContextMenu", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHInvokeCommandOnContextMenu(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHInvokeDefaultCommand", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHInvokeDefaultCommand(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHIsChildOrSelf", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHIsChildOrSelf(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHIsEmptyStream", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHIsEmptyStream(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHIsExpandableFolder", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHIsExpandableFolder(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHIsLowMemoryMachine", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHIsLowMemoryMachine(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHIsSameObject", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHIsSameObject(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLoadFromPropertyBag", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHLoadFromPropertyBag(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLoadIndirectString", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHLoadIndirectString(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLoadMenuPopup", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHLoadMenuPopup(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLoadRegUIStringA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHLoadRegUIStringA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLoadRegUIStringW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHLoadRegUIStringW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLockShared", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHLockShared(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLockSharedEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHLockSharedEx(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHMapHandle", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHMapHandle(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHMenuIndexFromID", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHMenuIndexFromID(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHMessageBoxCheckA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHMessageBoxCheckA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHMessageBoxCheckExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHMessageBoxCheckExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHMessageBoxCheckExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHMessageBoxCheckExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHMessageBoxCheckW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHMessageBoxCheckW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHOpenRegStream2A", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHOpenRegStream2A(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHOpenRegStream2W", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHOpenRegStream2W(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHOpenRegStreamA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHOpenRegStreamA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHOpenRegStreamW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHOpenRegStreamW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPackDispParams", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPackDispParams(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPackDispParamsV", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHPackDispParamsV(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPinDllOfCLSID", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHPinDllOfCLSID(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropagateMessage", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHPropagateMessage(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_Delete", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHPropertyBag_Delete(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadBOOL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadBOOL(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadBOOLOld", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadBOOLOld(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadBSTR", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadBSTR(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadDWORD", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadDWORD(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadGUID", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadGUID(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadInt", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadInt(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadLONG", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadLONG(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadPOINTL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadPOINTL(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadPOINTS", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadPOINTS(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadRECTL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadRECTL(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadSHORT", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadSHORT(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadStr", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadStr(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadStream", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadStream(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadType", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadType(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteBOOL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteBOOL(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteDWORD", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteDWORD(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteGUID", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteGUID(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteInt", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteInt(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteLONG", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteLONG(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WritePOINTL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WritePOINTL(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WritePOINTS", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WritePOINTS(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteRECTL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteRECTL(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteSHORT", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteSHORT(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteStr", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteStr(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteStream", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteStream(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHQueryInfoKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHQueryInfoKeyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHQueryInfoKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHQueryInfoKeyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHQueryValueExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHQueryValueExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHQueryValueExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHQueryValueExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHQueueUserWorkItem", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHQueueUserWorkItem(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHReadDataBlockList", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHReadDataBlockList(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegCloseUSKey", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHRegCloseUSKey(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegCreateUSKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegCreateUSKeyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegCreateUSKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegCreateUSKeyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegDeleteEmptyUSKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHRegDeleteEmptyUSKeyA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegDeleteEmptyUSKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHRegDeleteEmptyUSKeyW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegDeleteUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHRegDeleteUSValueA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegDeleteUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHRegDeleteUSValueW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegDuplicateHKey", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHRegDuplicateHKey(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegEnumUSKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegEnumUSKeyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegEnumUSKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegEnumUSKeyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegEnumUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegEnumUSValueA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegEnumUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegEnumUSValueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetBoolUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHRegGetBoolUSValueA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetBoolUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHRegGetBoolUSValueW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetCLSIDKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegGetCLSIDKeyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetCLSIDKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegGetCLSIDKeyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetIntW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHRegGetIntW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegGetPathA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetPathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegGetPathW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegGetUSValueA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegGetUSValueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetValueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegGetValueA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegGetValueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegOpenUSKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegOpenUSKeyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegOpenUSKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegOpenUSKeyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegQueryInfoUSKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegQueryInfoUSKeyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegQueryInfoUSKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegQueryInfoUSKeyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegQueryUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegQueryUSValueA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegQueryUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegQueryUSValueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegSetPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegSetPathA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegSetPathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegSetPathW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegSetUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegSetUSValueA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegSetUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegSetUSValueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegWriteUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegWriteUSValueA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegWriteUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegWriteUSValueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegisterClassA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHRegisterClassA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegisterClassW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHRegisterClassW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegisterValidateTemplate", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHRegisterValidateTemplate(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHReleaseThreadRef", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] SHReleaseThreadRef()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRemoveAllSubMenus", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHRemoveAllSubMenus(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRemoveDataBlock", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHRemoveDataBlock(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRemoveDefaultDialogFont", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHRemoveDefaultDialogFont(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRestrictionLookup", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHRestrictionLookup(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRunIndirectRegClientCommand", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHRunIndirectRegClientCommand(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSearchMapInt", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHSearchMapInt(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSendMessageBroadcastA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHSendMessageBroadcastA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSendMessageBroadcastW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHSendMessageBroadcastW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetDefaultDialogFont", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHSetDefaultDialogFont(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetIniStringUTF7W", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHSetIniStringUTF7W(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetIniStringW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHSetIniStringW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetParentHwnd", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHSetParentHwnd(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetThreadRef", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHSetThreadRef(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetTimerQueueTimer", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHSetTimerQueueTimer(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetValueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHSetValueA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHSetValueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetWindowBits", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHSetWindowBits(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSimulateDrop", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHSimulateDrop(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSkipJunction", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHSkipJunction(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHStrDupA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHStrDupA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHStrDupW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHStrDupW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHStringFromGUIDA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHStringFromGUIDA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHStringFromGUIDW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHStringFromGUIDW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHStripMneumonicA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHStripMneumonicA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHStripMneumonicW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHStripMneumonicW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHTruncateString", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHTruncateString(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHUnicodeToAnsi", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHUnicodeToAnsi(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHUnicodeToAnsiCP", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHUnicodeToAnsiCP(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHUnicodeToUnicode", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHUnicodeToUnicode(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHUnlockShared", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHUnlockShared(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHUnregisterClassesA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHUnregisterClassesA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHUnregisterClassesW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHUnregisterClassesW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHVerbExistsNA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHVerbExistsNA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHWaitForSendMessageThread", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHWaitForSendMessageThread(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHWeakQueryInterface", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHWeakQueryInterface(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHWeakReleaseInterface", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHWeakReleaseInterface(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHWinHelpOnDemandA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHWinHelpOnDemandA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHWinHelpOnDemandW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHWinHelpOnDemandW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHWriteDataBlockList", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHWriteDataBlockList(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SKAllocValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SKAllocValueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SKDeleteValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SKDeleteValueW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SKGetValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SKGetValueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SKSetValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SKSetValueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SearchPathWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SearchPathWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SendDlgItemMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] SendDlgItemMessageWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SendMessageTimeoutWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] SendMessageTimeoutWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SendMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SendMessageWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetCurrentDirectoryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SetCurrentDirectoryWrapW(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetDlgItemTextWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SetDlgItemTextWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetFileAttributesWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SetFileAttributesWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetMenuItemInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SetMenuItemInfoWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetPropWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SetPropWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetWindowLongWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] SetWindowLongWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetWindowTextWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] SetWindowTextWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetWindowsHookExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SetWindowsHookExWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ShellExecuteExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] ShellExecuteExWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ShellMessageBoxWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] ShellMessageBoxWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StartDocWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StartDocWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StopWatchA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] StopWatchA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StopWatchFlush", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] StopWatchFlush()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StopWatchMode", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] StopWatchMode()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StopWatchW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] StopWatchW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StopWatch_MarkFrameStart", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] StopWatch_MarkFrameStart(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StopWatch_MarkJavaStop", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StopWatch_MarkJavaStop(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StopWatch_SetMsgLastLocation", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] StopWatch_SetMsgLastLocation(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StopWatch_TimerHandler", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] StopWatch_TimerHandler(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCSpnA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCSpnA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCSpnIA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCSpnIA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCSpnIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCSpnIW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCSpnW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCSpnW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCatBuffA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCatBuffA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCatBuffW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCatBuffW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCatW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCatW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrChrA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrChrA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrChrIA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrChrIA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrChrIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrChrIW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrChrNW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrChrNW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrChrW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrChrW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpCA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCmpCA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpCW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCmpCW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpICA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCmpICA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpICW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCmpICW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCmpIW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpLogicalW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCmpLogicalW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCmpNA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNCA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCmpNCA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNCW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCmpNCW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNIA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCmpNIA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNICA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCmpNICA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNICW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCmpNICW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCmpNIW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCmpNW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCmpW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCpyNW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCpyNW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCpyNXA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCpyNXA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCpyNXW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCpyNXW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCpyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCpyW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrDupA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] StrDupA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrDupW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] StrDupW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFormatByteSize64A", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrFormatByteSize64A(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFormatByteSizeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrFormatByteSizeA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFormatByteSizeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrFormatByteSizeW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFormatKBSizeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrFormatKBSizeA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFormatKBSizeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrFormatKBSizeW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFromTimeIntervalA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] StrFromTimeIntervalA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFromTimeIntervalW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] StrFromTimeIntervalW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrIsIntlEqualA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] StrIsIntlEqualA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrIsIntlEqualW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] StrIsIntlEqualW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrNCatA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrNCatA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrNCatW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrNCatW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrPBrkA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrPBrkA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrPBrkW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrPBrkW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRChrA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRChrA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRChrIA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRChrIA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRChrIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRChrIW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRChrW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRChrW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRStrIA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRStrIA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRStrIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRStrIW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRetToBSTR", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRetToBSTR(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRetToBufA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] StrRetToBufA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRetToBufW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] StrRetToBufW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRetToStrA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRetToStrA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRetToStrW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRetToStrW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrSpnA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrSpnA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrSpnW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrSpnW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrStrA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrStrA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrStrIA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrStrIA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrStrIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrStrIW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrStrNIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrStrNIW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrStrNW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrStrNW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrStrW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrStrW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrToInt64ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrToInt64ExA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrToInt64ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrToInt64ExW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrToIntA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] StrToIntA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrToIntExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrToIntExA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrToIntExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrToIntExW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrToIntW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] StrToIntW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrTrimA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrTrimA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrTrimW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrTrimW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SystemParametersInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] SystemParametersInfoWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "TrackPopupMenuExWrap", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] TrackPopupMenuExWrap(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "TrackPopupMenuWrap", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] TrackPopupMenuWrap(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "TranslateAcceleratorWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] TranslateAcceleratorWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UnregisterClassWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] UnregisterClassWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UnregisterExtensionForMIMETypeA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UnregisterExtensionForMIMETypeA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UnregisterExtensionForMIMETypeW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UnregisterExtensionForMIMETypeW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UnregisterMIMETypeForExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UnregisterMIMETypeForExtensionA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UnregisterMIMETypeForExtensionW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UnregisterMIMETypeForExtensionW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlApplySchemeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlApplySchemeA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlApplySchemeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlApplySchemeW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCanonicalizeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlCanonicalizeA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCanonicalizeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlCanonicalizeW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCombineA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] UrlCombineA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCombineW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] UrlCombineW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCompareA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] UrlCompareA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCompareW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] UrlCompareW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCrackW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlCrackW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCreateFromPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlCreateFromPathA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCreateFromPathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlCreateFromPathW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlEscapeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlEscapeA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlEscapeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlEscapeW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlFixupW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] UrlFixupW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlGetLocationA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UrlGetLocationA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlGetLocationW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UrlGetLocationW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlGetPartA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] UrlGetPartA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlGetPartW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] UrlGetPartW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlHashA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] UrlHashA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlHashW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] UrlHashW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlIsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] UrlIsA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlIsNoHistoryA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UrlIsNoHistoryA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlIsNoHistoryW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UrlIsNoHistoryW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlIsOpaqueA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UrlIsOpaqueA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlIsOpaqueW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UrlIsOpaqueW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlIsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] UrlIsW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlUnescapeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlUnescapeA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlUnescapeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlUnescapeW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "VerQueryValueWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] VerQueryValueWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "VkKeyScanWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] VkKeyScanWrapW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "WNetGetLastErrorWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] WNetGetLastErrorWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "WNetRestoreConnectionWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shlwapi] WNetRestoreConnectionWrapW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "WhichPlatform", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] WhichPlatform()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "WinHelpWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] WinHelpWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "WritePrivateProfileStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] WritePrivateProfileStringWrapW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "WritePrivateProfileStructWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shlwapi] WritePrivateProfileStructWrapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ZoneCheckUrlExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shlwapi] ZoneCheckUrlExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ZoneComputePaneSize", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] ZoneComputePaneSize(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "wnsprintfA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] wnsprintfA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "wvnsprintfA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] wvnsprintfA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "wvnsprintfW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shlwapi] wvnsprintfW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "wvsprintfWrapW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shlwapi] wvsprintfWrapW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
}

func registerShell32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16

	sharedHeapAlloc := hctx.HeapAlloc

	shell32, ok := hctx.SynthByName["shell32.dll"]
	if !ok {
		return
	}
	_ = shell32

	d.RegisterAutoStubHandler(shell32, "SHGetFolderPathW", func(ctx *ntapi.TrapContext) uint32 {
		// HRESULT SHGetFolderPathW(HWND hwnd, int nFolder, HANDLE hToken, DWORD dwFlags, LPWSTR pszPath)
		folder := ctx.Arg(1)
		buf := ctx.Arg(3)
		path := csidlToPath(int32(folder))
		if buf != 0 {
			for i, ch := range path {
				ctx.Mem.Write16(buf+uint64(i*2), uint16(ch))
			}
			ctx.Mem.Write16(buf+uint64(len(path)*2), 0)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DragAcceptFiles", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})

	// ShellAboutW: show the standard "About" dialog.
	// Real Win32 creates a modal dialog with app icon, name, version, and OS info.
	// We log the info and return TRUE (the dialog was "shown").
	d.RegisterAutoStubHandler(shell32, "ShellAboutW", func(ctx *ntapi.TrapContext) uint32 {
		// INT ShellAboutW(HWND hWnd, LPCWSTR szApp, LPCWSTR szOtherStuff, HICON hIcon)
		hwnd := ctx.Arg(0)
		szApp := ctx.Arg(1)
		szOther := ctx.Arg(2)
		appName := ""
		otherStuff := ""
		if szApp != 0 {
			appName = readGuestUTF16(szApp)
		}
		if szOther != 0 {
			otherStuff = readGuestUTF16(szOther)
		}
		ravelog.Logf("[shell] ShellAboutW: app=%q other=%q\n", appName, otherStuff)

		// Show modal dialog overlay
		hctx.DialogActive = true
		hctx.DialogTitle = "About " + appName
		hctx.DialogText = appName
		hctx.DialogText2 = otherStuff
		hctx.DialogHwnd = hwnd
		hctx.OpenMenuIdx = -1 // close any open menu dropdown

		// Trigger immediate repaint to show the dialog
		if hctx.WlWindow != nil && hctx.HasBaseFrame {
			hctx.RepaintBuiltin = true
			hctx.FrameReady = true
			hctx.CommitIfDone()
		}

		ctx.SetReturn(1) // TRUE = success
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetKnownFolderPath", func(ctx *ntapi.TrapContext) uint32 {
		// HRESULT SHGetKnownFolderPath(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken, PWSTR *ppszPath)
		rfid := ctx.Arg(0)
		ppszPath := ctx.Arg(3)
		path := `C:\Users\user\AppData\Roaming` // default fallback
		if rfid != 0 {
			guidStr := readGUIDString(ctx.Mem, rfid)
			knownFolders := map[string]string{
				"{374DE290-123F-4565-9164-39C4925E467B}": `C:\Users\user\Downloads`,
				"{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": `C:\Users\user\Documents`,
				"{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": `C:\Users\user\AppData\Roaming`,
				"{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": `C:\Users\user\AppData\Local`,
				"{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": `C:\Users\user\Desktop`,
				"{5E6C858F-0E22-4760-9AFE-EA3317B67173}": `C:\Users\user`,
				"{905E63B6-C1BF-494E-B29C-65B732D3D21A}": `C:\Program Files`,
				"{F38BF404-1D43-42F2-9305-67DE0B28FC23}": `C:\Windows`,
				"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": `C:\Windows\System32`,
				"{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": `C:\ProgramData`,
				"{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}": `C:\Windows\Fonts`,
				"{33E28130-4E1E-4676-835A-98395C3BC3BB}": `C:\Users\user\Pictures`,
				"{4BD8D571-6D19-48D3-BE97-422220080E43}": `C:\Users\user\Music`,
				"{18989B1D-99B5-455B-841C-AB7C74E4DDFC}": `C:\Users\user\Videos`,
			}
			if p, ok := knownFolders[guidStr]; ok {
				path = p
			}
		}
		ws := utf16Encode(path)
		bufSize := uint64(len(ws)+1) * 2
		addr := mem.Mmap(0, bufSize, mmu.PermRead|mmu.PermWrite)
		for i, w := range ws {
			mem.Write16(addr+uint64(i)*2, w)
		}
		mem.Write16(addr+uint64(len(ws))*2, 0)
		if ppszPath != 0 {
			ctx.Mem.Write64(ppszPath, addr)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateDirectoryExW", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(1)
		if pathPtr != 0 {
			path := winPathToVFS(readGuestUTF16(pathPtr))
			os.MkdirAll(path, 0755) // ignore errors
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateDirectoryExA", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(1)
		if pathPtr != 0 {
			path := winPathToVFS(readGuestString(pathPtr))
			os.MkdirAll(path, 0755)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFileOperationA", func(ctx *ntapi.TrapContext) uint32 {
		lpFileOp := ctx.Arg(0)
		if lpFileOp != 0 {
			ctx.Mem.Write32(lpFileOp+36, 0) // fAnyOperationsAborted = FALSE
		}
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DragQueryFileW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // 0 files in drop
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DragQueryPoint", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - point is not in client area
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DragFinish", func(ctx *ntapi.TrapContext) uint32 {
		return 0 // no-op
	})
	d.RegisterAutoStubHandler(shell32, "ShellExecuteW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(42) // >32 means success
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellExecuteA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(42) // >32 means success
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFileOperationW", func(ctx *ntapi.TrapContext) uint32 {
		// Clear fAnyOperationsAborted in SHFILEOPSTRUCT (offset 36 = 0x24)
		lpFileOp := ctx.Arg(0)
		if lpFileOp != 0 {
			ctx.Mem.Write32(lpFileOp+36, 0)
		}
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateItemFromParsingName", func(ctx *ntapi.TrapContext) uint32 {
		ppv := ctx.Arg(3)
		if ppv != 0 {
			ctx.Mem.Write64(ppv, 0)
		}
		ctx.SetReturn(0x80004001) // E_NOTIMPL
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSpecialFolderPathW", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SHGetSpecialFolderPathW(HWND hwnd, LPWSTR pszPath, int csidl, BOOL fCreate)
		pszPath := ctx.Arg(1)
		csidl := ctx.Arg(2)
		path := csidlToPath(int32(csidl))
		if pszPath != 0 {
			for i, ch := range path {
				ctx.Mem.Write16(pszPath+uint64(i*2), uint16(ch))
			}
			ctx.Mem.Write16(pszPath+uint64(len(path)*2), 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSpecialFolderPathA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(1)
		csidl := ctx.Arg(2)
		path := csidlToPath(int32(csidl))
		if pszPath != 0 {
			for i := 0; i < len(path); i++ {
				ctx.Mem.Write8(pszPath+uint64(i), path[i])
			}
			ctx.Mem.Write8(pszPath+uint64(len(path)), 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetFileInfoW", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD_PTR SHGetFileInfoW(LPCWSTR pszPath, DWORD dwFileAttributes,
		//   SHFILEINFOW *psfi, UINT cbFileInfo, UINT uFlags)
		psfi := ctx.Arg(2)
		cbFileInfo := ctx.Arg(3)
		if psfi != 0 && cbFileInfo >= 4 {
			// Zero the SHFILEINFOW struct (up to cbFileInfo bytes)
			for i := uint64(0); i < cbFileInfo && i < 692; i++ {
				ctx.Mem.Write8(psfi+i, 0)
			}
		}
		ctx.SetReturn(1) // non-zero = success
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetFileInfoA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		dwFileAttributes := uint32(ctx.Arg(1))
		psfi := ctx.Arg(2)
		cbFileInfo := ctx.Arg(3)
		uFlags := uint32(ctx.Arg(4))
		pathStr := readGuestString(pszPath)
		ravelog.Logf("[shell32] SHGetFileInfoA path=%q attr=0x%x flags=0x%x\n", pathStr, dwFileAttributes, uFlags)
		if psfi != 0 && cbFileInfo > 0 {
			for i := uint64(0); i < cbFileInfo && i < 352; i++ {
				mem.Write8(psfi+i, 0)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconExW", func(ctx *ntapi.TrapContext) uint32 {
		lpszFile := ctx.Arg(0)
		nIconIndex := int32(ctx.Arg(1))
		phiconLarge := ctx.Arg(2)
		phiconSmall := ctx.Arg(3)
		nIcons := uint32(ctx.Arg(4))
		fileName := readGuestUTF16(lpszFile)
		ravelog.Logf("[shell32] ExtractIconExW file=%q idx=%d large=0x%x small=0x%x n=%d\n", fileName, nIconIndex, phiconLarge, phiconSmall, nIcons)
		ctx.SetReturn(0) // 0 icons extracted
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconExA", func(ctx *ntapi.TrapContext) uint32 {
		lpszFile := ctx.Arg(0)
		nIconIndex := int32(ctx.Arg(1))
		phiconLarge := ctx.Arg(2)
		phiconSmall := ctx.Arg(3)
		nIcons := uint32(ctx.Arg(4))
		fileName := readGuestString(lpszFile)
		ravelog.Logf("[shell32] ExtractIconExA file=%q idx=%d large=0x%x small=0x%x n=%d\n", fileName, nIconIndex, phiconLarge, phiconSmall, nIcons)
		ctx.SetReturn(0)
		return 0
	})

	// ═══════════════════════════════════════════════════════════════
	// AUTO-GENERATED: Missing shell32 handlers from ReactOS spec
	// ═══════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(shell32, "Activate_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] Activate_RunDLL(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "AddCommasW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] AddCommasW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "AppCompat_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] AppCompat_RunDLLW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ArrangeWindows", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] ArrangeWindows(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CDefFolderMenu_Create", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] CDefFolderMenu_Create(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CDefFolderMenu_Create2", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] CDefFolderMenu_Create2(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CDefFolderMenu_MergeMenu", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] CDefFolderMenu_MergeMenu(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CIDLData_CreateFromIDArray", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] CIDLData_CreateFromIDArray(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CallCPLEntry16", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] CallCPLEntry16(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CheckDiskSpace", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] CheckDiskSpace()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CheckEscapesA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] CheckEscapesA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CheckEscapesW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] CheckEscapesW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CheckStagingArea", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] CheckStagingArea()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CheckWinIniForAssocs", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] CheckWinIniForAssocs()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Control_FillCache_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] Control_FillCache_RunDLL(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Control_FillCache_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] Control_FillCache_RunDLLA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Control_FillCache_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] Control_FillCache_RunDLLW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Control_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] Control_RunDLL(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Control_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] Control_RunDLLA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Control_RunDLLAsUserW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] Control_RunDLLAsUserW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Control_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] Control_RunDLLW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CopyStreamUI", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] CopyStreamUI(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_AutoScroll", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] DAD_AutoScroll(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_DragEnter", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] DAD_DragEnter(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_DragEnterEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] DAD_DragEnterEx(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_DragEnterEx2", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] DAD_DragEnterEx2(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_DragLeave", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] DAD_DragLeave()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_DragMove", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] DAD_DragMove(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_SetDragImage", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] DAD_SetDragImage(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_SetDragImageFromListView", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] DAD_SetDragImageFromListView(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_ShowDragImage", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] DAD_ShowDragImage(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DDECreatePostNotify", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] DDECreatePostNotify(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DllCanUnloadNow", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] DllCanUnloadNow()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DllGetClassObject", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] DllGetClassObject(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DllGetVersion", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] DllGetVersion(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DllInstall", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] DllInstall(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DllRegisterServer", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] DllRegisterServer()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DllUnregisterServer", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] DllUnregisterServer()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DoEnvironmentSubstA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] DoEnvironmentSubstA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DoEnvironmentSubstW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] DoEnvironmentSubstW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DragQueryFile", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] DragQueryFile(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DragQueryFileA", func(ctx *ntapi.TrapContext) uint32 {
		hDrop := ctx.Arg(0)
		iFile := ctx.Arg(1)
		lpszFile := ctx.Arg(2)
		cch := ctx.Arg(3)
		ravelog.Logf("[shell32] DragQueryFileA hDrop=0x%x idx=%d\n", hDrop, iFile)
		if iFile == 0xFFFFFFFF {
			ctx.SetReturn(0)
		} else {
			_ = lpszFile; _ = cch
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DragQueryFileAorW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] DragQueryFileAorW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DragQueryInfo", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] DragQueryInfo(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DriveType", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] DriveType(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DuplicateIcon", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] DuplicateIcon(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExitWindowsDialog", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ExitWindowsDialog(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractAssociatedIconA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] ExtractAssociatedIconA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractAssociatedIconExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] ExtractAssociatedIconExA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractAssociatedIconExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] ExtractAssociatedIconExW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractAssociatedIconW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] ExtractAssociatedIconW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] ExtractIconA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] ExtractIconEx(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconResInfoA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] ExtractIconResInfoA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconResInfoW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] ExtractIconResInfoW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] ExtractIconW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractVersionResource16W", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] ExtractVersionResource16W(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "FileIconInit", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] FileIconInit(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "FindExeDlgProc", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] FindExeDlgProc(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "FindExecutableA", func(ctx *ntapi.TrapContext) uint32 {
		lpFile := ctx.Arg(0)
		lpDirectory := ctx.Arg(1)
		lpResult := ctx.Arg(2)
		var file string
		if lpFile != 0 { file = readGuestUTF16(lpFile) }
		ravelog.Logf("[shell32] FindExecutableA file=%q\n", file)
		_ = lpDirectory; _ = lpResult
		ctx.SetReturn(31) // SE_ERR_NOASSOC
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "FindExecutableW", func(ctx *ntapi.TrapContext) uint32 {
		lpFile := ctx.Arg(0)
		lpDirectory := ctx.Arg(1)
		lpResult := ctx.Arg(2)
		var file string
		if lpFile != 0 { file = readGuestUTF16(lpFile) }
		ravelog.Logf("[shell32] FindExecutableW file=%q\n", file)
		_ = lpDirectory; _ = lpResult
		ctx.SetReturn(31) // SE_ERR_NOASSOC
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "FirstUserLogon", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] FirstUserLogon(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "FreeIconList", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] FreeIconList(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "GUIDFromStringA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] GUIDFromStringA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "GUIDFromStringW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] GUIDFromStringW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "GetFileDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] GetFileDescriptor(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "GetFileNameFromBrowse", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] GetFileNameFromBrowse(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILAppendID", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] ILAppendID(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILClone", func(ctx *ntapi.TrapContext) uint32 {
		pidl := ctx.Arg(0)
		ravelog.Logf("[shell32] ILClone pidl=0x%x\n", pidl)
		// Return a minimal clone
		newPidl := sharedHeapAlloc(4, true)
		ctx.Mem.Write16(newPidl, 0) // empty PIDL
		ctx.SetReturn(newPidl)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILCloneFirst", func(ctx *ntapi.TrapContext) uint32 {
		pidl := ctx.Arg(0)
		ravelog.Logf("[shell32] ILCloneFirst pidl=0x%x\n", pidl)
		// Return a minimal clone
		newPidl := sharedHeapAlloc(4, true)
		ctx.Mem.Write16(newPidl, 0) // empty PIDL
		ctx.SetReturn(newPidl)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILCombine", func(ctx *ntapi.TrapContext) uint32 {
		pidl1 := ctx.Arg(0)
		pidl2 := ctx.Arg(1)
		ravelog.Logf("[shell32] ILCombine pidl1=0x%x pidl2=0x%x\n", pidl1, pidl2)
		newPidl := sharedHeapAlloc(4, true)
		ctx.Mem.Write16(newPidl, 0)
		ctx.SetReturn(newPidl)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILCreateFromPath", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ILCreateFromPath(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILCreateFromPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ILCreateFromPathA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILCreateFromPathW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ILCreateFromPathW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILFindChild", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] ILFindChild(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILFindLastID", func(ctx *ntapi.TrapContext) uint32 {
		pidl := ctx.Arg(0)
		ravelog.Logf("[shell32] ILFindLastID pidl=0x%x\n", pidl)
		ctx.SetReturn(pidl) // return the pidl itself for empty PIDLs
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILFree", func(ctx *ntapi.TrapContext) uint32 {
		pidl := ctx.Arg(0)
		ravelog.Logf("[shell32] ILFree pidl=0x%x\n", pidl)
		ctx.SetReturn(0) // void
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILGetDisplayName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] ILGetDisplayName(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILGetDisplayNameEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] ILGetDisplayNameEx(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILGetNext", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ILGetNext(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILGetPseudoNameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] ILGetPseudoNameW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILGetSize", func(ctx *ntapi.TrapContext) uint32 {
		pidl := ctx.Arg(0)
		ravelog.Logf("[shell32] ILGetSize pidl=0x%x\n", pidl)
		ctx.SetReturn(2) // minimal PIDL size (just terminator)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILGlobalClone", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ILGlobalClone(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILGlobalFree", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ILGlobalFree(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILIsEqual", func(ctx *ntapi.TrapContext) uint32 {
		pidl1 := ctx.Arg(0)
		pidl2 := ctx.Arg(1)
		ravelog.Logf("[shell32] ILIsEqual pidl1=0x%x pidl2=0x%x\n", pidl1, pidl2)
		eq := uint64(0); if pidl1 == pidl2 { eq = 1 }
		ctx.SetReturn(eq)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILIsParent", func(ctx *ntapi.TrapContext) uint32 {
		pidlParent := ctx.Arg(0)
		pidlChild := ctx.Arg(1)
		fImmediate := ctx.Arg(2)
		ravelog.Logf("[shell32] ILIsParent parent=0x%x child=0x%x imm=%d\n", pidlParent, pidlChild, fImmediate)
		ctx.SetReturn(0) // FALSE
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILLoadFromStream", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] ILLoadFromStream(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILRemoveLastID", func(ctx *ntapi.TrapContext) uint32 {
		pidl := ctx.Arg(0)
		ravelog.Logf("[shell32] ILRemoveLastID pidl=0x%x\n", pidl)
		if pidl != 0 { ctx.Mem.Write16(pidl, 0) } // make it empty
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILSaveToStream", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] ILSaveToStream(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Int64ToString", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] Int64ToString(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "InternalExtractIconListA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] InternalExtractIconListA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "InternalExtractIconListW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] InternalExtractIconListW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "InvalidateDriveType", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] InvalidateDriveType(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "IsLFNDrive", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] IsLFNDrive(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "IsLFNDriveA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] IsLFNDriveA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "IsLFNDriveW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] IsLFNDriveW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "IsNetDrive", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] IsNetDrive(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "IsSuspendAllowed", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] IsSuspendAllowed()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "IsUserAnAdmin", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] IsUserAnAdmin()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "LargeIntegerToString", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] LargeIntegerToString(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "LinkWindow_RegisterClass", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] LinkWindow_RegisterClass()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "LinkWindow_UnregisterClass", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] LinkWindow_UnregisterClass(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "LogoffWindowsDialog", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] LogoffWindowsDialog(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "MakeShellURLFromPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] MakeShellURLFromPathA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "MakeShellURLFromPathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] MakeShellURLFromPathW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "NTSHChangeNotifyDeregister", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] NTSHChangeNotifyDeregister(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "NTSHChangeNotifyRegister", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] NTSHChangeNotifyRegister(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "OldReadCabinetState", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] OldReadCabinetState(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "OleStrToStrN", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] OleStrToStrN(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "OpenAs_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] OpenAs_RunDLL(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "OpenAs_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] OpenAs_RunDLLA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "OpenAs_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] OpenAs_RunDLLW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "OpenRegStream", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] OpenRegStream(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Options_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] Options_RunDLL(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Options_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] Options_RunDLLA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Options_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] Options_RunDLLW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ParseField", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] ParseField(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathAddBackslash", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathAddBackslash(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathAppend", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] PathAppend(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathBuildRoot", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] PathBuildRoot(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathCleanupSpec", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] PathCleanupSpec(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathCombine", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] PathCombine(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathFileExists", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathFileExists(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathFindExtension", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathFindExtension(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathFindFileName", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathFindFileName(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathFindOnPath", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] PathFindOnPath(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathGetArgs", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathGetArgs(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathGetDriveNumber", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathGetDriveNumber(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathGetExtension", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] PathGetExtension(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathGetShortPath", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathGetShortPath(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsDirectory", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsDirectory(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsEqualOrSubFolder", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] PathIsEqualOrSubFolder(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsExe", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsExe(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsRelative", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsRelative(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsRoot", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsRoot(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsSameRoot", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] PathIsSameRoot(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsSlowA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] PathIsSlowA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsSlowW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] PathIsSlowW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsTemporaryA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsTemporaryA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsTemporaryW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsTemporaryW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsUNC", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsUNC(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsURL", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsURL(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathMakeUniqueName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] PathMakeUniqueName(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathMatchSpec", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] PathMatchSpec(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathParseIconLocation", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathParseIconLocation(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathProcessCommand", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] PathProcessCommand(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathQualify", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathQualify(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathQuoteSpaces", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathQuoteSpaces(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathRemoveArgs", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathRemoveArgs(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathRemoveBlanks", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathRemoveBlanks(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathRemoveExtension", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathRemoveExtension(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathRemoveFileSpec", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathRemoveFileSpec(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathResolve", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] PathResolve(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathSetDlgItemPath", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] PathSetDlgItemPath(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathStripPath", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathStripPath(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathStripToRoot", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathStripToRoot(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathUnquoteSpaces", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathUnquoteSpaces(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathYetAnotherMakeUniqueName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] PathYetAnotherMakeUniqueName(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PickIconDlg", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] PickIconDlg(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PifMgr_CloseProperties", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] PifMgr_CloseProperties(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PifMgr_GetProperties", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] PifMgr_GetProperties(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PifMgr_OpenProperties", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] PifMgr_OpenProperties(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PifMgr_SetProperties", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] PifMgr_SetProperties(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Printer_LoadIconsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] Printer_LoadIconsW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PrintersGetCommand_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] PrintersGetCommand_RunDLL(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PrintersGetCommand_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] PrintersGetCommand_RunDLLA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PrintersGetCommand_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] PrintersGetCommand_RunDLLW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Printers_AddPrinterPropPages", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] Printers_AddPrinterPropPages(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Printers_GetPidl", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] Printers_GetPidl(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Printers_RegisterWindowW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] Printers_RegisterWindowW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Printers_UnregisterWindow", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] Printers_UnregisterWindow(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RLBuildListOfPaths", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] RLBuildListOfPaths()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ReadCabinetState", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] ReadCabinetState(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RealDriveType", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] RealDriveType(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RealDriveTypeFlags", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] RealDriveTypeFlags(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RealShellExecuteA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] RealShellExecuteA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RealShellExecuteExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] RealShellExecuteExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RealShellExecuteExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] RealShellExecuteExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RealShellExecuteW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] RealShellExecuteW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RegenerateUserEnvironment", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] RegenerateUserEnvironment(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RegisterShellHook", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] RegisterShellHook(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RestartDialog", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] RestartDialog(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RestartDialogEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] RestartDialogEx(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RunDll_CallEntry16", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] RunDll_CallEntry16(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RunFileDlg", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] RunFileDlg(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHAbortInvokeCommand", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHAbortInvokeCommand()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHAddFromPropSheetExtArray", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHAddFromPropSheetExtArray(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHAddToRecentDocs", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHAddToRecentDocs(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHAlloc", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHAlloc(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHAllocShared", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHAllocShared(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHAppBarMessage", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHAppBarMessage(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHBindToParent", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		a1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHBindToParent(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0x80004005) // E_FAIL
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHBrowseForFolder", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHBrowseForFolder(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHBrowseForFolderA", func(ctx *ntapi.TrapContext) uint32 {
		lpbi := ctx.Arg(0)
		ravelog.Logf("[shell32] SHBrowseForFolderA info=0x%x\n", lpbi)
		ctx.SetReturn(0) // NULL = user cancelled
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHBrowseForFolderW", func(ctx *ntapi.TrapContext) uint32 {
		lpbi := ctx.Arg(0)
		ravelog.Logf("[shell32] SHBrowseForFolderW info=0x%x\n", lpbi)
		ctx.SetReturn(0) // NULL = user cancelled
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCLSIDFromString", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHCLSIDFromString(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotification_Lock", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHChangeNotification_Lock(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotification_Unlock", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHChangeNotification_Unlock(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotify", func(ctx *ntapi.TrapContext) uint32 {
		wEventId := ctx.Arg(0)
		uFlags := ctx.Arg(1)
		dwItem1 := ctx.Arg(2)
		dwItem2 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHChangeNotify event=0x%x flags=0x%x\n", wEventId, uFlags)
		_ = dwItem1; _ = dwItem2
		ctx.SetReturn(0) // void
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotifyDeregister", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHChangeNotifyDeregister(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotifyReceive", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHChangeNotifyReceive(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotifyRegister", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] SHChangeNotifyRegister(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotifySuspendResume", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHChangeNotifySuspendResume(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotifyUpdateEntryList", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHChangeNotifyUpdateEntryList(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeRegistrationReceive", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHChangeRegistrationReceive(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCloneSpecialIDList", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHCloneSpecialIDList(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCoCreateInstance", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] SHCoCreateInstance(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCopyMonikerToTemp", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHCopyMonikerToTemp(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateDefClassObject", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] SHCreateDefClassObject(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateDesktop", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHCreateDesktop(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateDirectory", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHCreateDirectory(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateFileDataObject", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] SHCreateFileDataObject(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateFileExtractIconW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHCreateFileExtractIconW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateLinks", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] SHCreateLinks(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateProcessAsUserW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHCreateProcessAsUserW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreatePropSheetExtArray", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHCreatePropSheetExtArray(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreatePropSheetExtArrayEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHCreatePropSheetExtArrayEx(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreatePropertyBag", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHCreatePropertyBag(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateQueryCancelAutoPlayMoniker", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHCreateQueryCancelAutoPlayMoniker(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateSessionKey", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHCreateSessionKey(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateShellFolderView", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHCreateShellFolderView(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateShellFolderViewEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHCreateShellFolderViewEx(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateShellItem", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHCreateShellItem(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateStdEnumFmtEtc", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHCreateStdEnumFmtEtc(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHDefExtractIconA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] SHDefExtractIconA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHDefExtractIconW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] SHDefExtractIconW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHDesktopMessageLoop", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHDesktopMessageLoop(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHDestroyPropSheetExtArray", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHDestroyPropSheetExtArray(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHDllGetClassObject", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHDllGetClassObject(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHDoDragDrop", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] SHDoDragDrop(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHEmptyRecycleBinA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHEmptyRecycleBinA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHEmptyRecycleBinW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHEmptyRecycleBinW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHEnumerateUnreadMailAccountsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHEnumerateUnreadMailAccountsW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHExtractIconsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] SHExtractIconsW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFileOperation", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHFileOperation(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFindComputer", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHFindComputer(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFindFiles", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHFindFiles(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFind_InitMenuPopup", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHFind_InitMenuPopup(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFlushClipboard", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHFlushClipboard()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFlushSFCache", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHFlushSFCache()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFormatDrive", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHFormatDrive(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFree", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHFree(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFreeNameMappings", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHFreeNameMappings(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFreeShared", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHFreeShared(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFreeUnusedLibraries", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHFreeUnusedLibraries()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetAppCompatFlags", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHGetAppCompatFlags(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetAttributesFromDataObject", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetAttributesFromDataObject(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetComputerDisplayNameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetComputerDisplayNameW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetDataFromIDListA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] SHGetDataFromIDListA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetDataFromIDListW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] SHGetDataFromIDListW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetDesktopFolder", func(ctx *ntapi.TrapContext) uint32 {
		ppshf := ctx.Arg(0)
		ravelog.Logf("[shell32] SHGetDesktopFolder out=0x%x\n", ppshf)
		if ppshf != 0 { ctx.Mem.Write64(ppshf, 0) }
		ctx.SetReturn(0x80004005) // E_FAIL - no COM support yet
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetDiskFreeSpaceA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetDiskFreeSpaceA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetDiskFreeSpaceExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetDiskFreeSpaceExA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetDiskFreeSpaceExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetDiskFreeSpaceExW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetFileInfo", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] SHGetFileInfo(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetFolderLocation", func(ctx *ntapi.TrapContext) uint32 {
		hwndOwner := ctx.Arg(0)
		nFolder := ctx.Arg(1)
		hToken := ctx.Arg(2)
		dwReserved := ctx.Arg(3)
		ppidl := ctx.Arg(4)
		_ = hwndOwner; _ = hToken; _ = dwReserved
		ravelog.Logf("[shell32] SHGetFolderLocation folder=0x%x\n", nFolder)
		if ppidl != 0 {
			pidl := sharedHeapAlloc(4, true)
			ctx.Mem.Write16(pidl, 0)
			ctx.Mem.Write64(ppidl, pidl)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetFolderPathA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nFolder := ctx.Arg(1)
		hToken := ctx.Arg(2)
		dwFlags := ctx.Arg(3)
		pszPath := ctx.Arg(4)
		_ = hwnd; _ = hToken; _ = dwFlags
		ravelog.Logf("[shell32] SHGetFolderPathA folder=0x%x path=0x%x\n", nFolder, pszPath)
		path := "C:\\Users\\User"
		switch nFolder & 0xFF {
		case 0x001A: path = "C:\\Users\\User\\AppData\\Roaming"
		case 0x001C: path = "C:\\Users\\User\\AppData\\Local"
		case 0x0005: path = "C:\\Users\\User\\Documents"
		case 0x0024: path = "C:\\Windows"
		case 0x0025: path = "C:\\Windows\\system32"
		case 0x0026: path = "C:\\Program Files"
		case 0x0000: path = "C:\\Users\\User\\Desktop"
		}
		if pszPath != 0 {
			for i := 0; i < len(path); i++ {
				ctx.Mem.Write8(pszPath+uint64(i), path[i])
			}
			ctx.Mem.Write8(pszPath+uint64(len(path)), 0)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetFolderPathAndSubDirA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] SHGetFolderPathAndSubDirA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetFolderPathAndSubDirW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] SHGetFolderPathAndSubDirW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetIconOverlayIndexA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHGetIconOverlayIndexA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetIconOverlayIndexW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHGetIconOverlayIndexW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetImageList", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHGetImageList(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetInstanceExplorer", func(ctx *ntapi.TrapContext) uint32 {
		ppunk := ctx.Arg(0)
		ravelog.Logf("[shell32] SHGetInstanceExplorer out=0x%x\n", ppunk)
		if ppunk != 0 { ctx.Mem.Write64(ppunk, 0) }
		ctx.SetReturn(0x80004005) // E_FAIL
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetMalloc", func(ctx *ntapi.TrapContext) uint32 {
		ppMalloc := ctx.Arg(0)
		ravelog.Logf("[shell32] SHGetMalloc out=0x%x\n", ppMalloc)
		if ppMalloc != 0 { ctx.Mem.Write64(ppMalloc, 0) }
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetNetResource", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetNetResource(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetNewLinkInfo", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] SHGetNewLinkInfo(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetNewLinkInfoA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] SHGetNewLinkInfoA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetNewLinkInfoW", func(ctx *ntapi.TrapContext) uint32 {
		pszLinkTo := ctx.Arg(0)
		pszDir := ctx.Arg(1)
		pszName := ctx.Arg(2)
		pfMustCopy := ctx.Arg(3)
		uFlags := ctx.Arg(4)
		var linkTo string
		if pszLinkTo != 0 { linkTo = readGuestUTF16(pszLinkTo) }
		ravelog.Logf("[shell32] SHGetNewLinkInfoW linkTo=%q\n", linkTo)
		_ = pszDir; _ = pszName; _ = uFlags
		if pfMustCopy != 0 { ctx.Mem.Write32(pfMustCopy, 0) }
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetPathFromIDList", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHGetPathFromIDList(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetPathFromIDListA", func(ctx *ntapi.TrapContext) uint32 {
		pidl := ctx.Arg(0)
		pszPath := ctx.Arg(1)
		ravelog.Logf("[shell32] SHGetPathFromIDListA pidl=0x%x path=0x%x\n", pidl, pszPath)
		defaultPath := "C:\\Users\\User\\Desktop"
		if pszPath != 0 {
			for i := 0; i < len(defaultPath); i++ {
				ctx.Mem.Write8(pszPath+uint64(i), defaultPath[i])
			}
			ctx.Mem.Write8(pszPath+uint64(len(defaultPath)), 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetPathFromIDListW", func(ctx *ntapi.TrapContext) uint32 {
		pidl := ctx.Arg(0)
		pszPath := ctx.Arg(1)
		ravelog.Logf("[shell32] SHGetPathFromIDListW pidl=0x%x path=0x%x\n", pidl, pszPath)
		// Return a default path since we don't have real PIDLs
		defaultPath := "C:\\Users\\User\\Desktop"
		if pszPath != 0 {
			for i, ch := range defaultPath {
				ctx.Mem.Write16(pszPath+uint64(i*2), uint16(ch))
			}
			ctx.Mem.Write16(pszPath+uint64(len(defaultPath)*2), 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetProcessDword", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHGetProcessDword(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetRealIDL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHGetRealIDL(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSetFolderCustomSettingsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHGetSetFolderCustomSettingsA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSetFolderCustomSettingsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHGetSetFolderCustomSettingsW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSetSettings", func(ctx *ntapi.TrapContext) uint32 {
		lpss := ctx.Arg(0)
		dwMask := ctx.Arg(1)
		bSet := ctx.Arg(2)
		ravelog.Logf("[shell32] SHGetSetSettings flags=0x%x mask=0x%x set=%d\n", lpss, dwMask, bSet)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSettings", func(ctx *ntapi.TrapContext) uint32 {
		lpsfs := ctx.Arg(0)
		dwMask := ctx.Arg(1)
		ravelog.Logf("[shell32] SHGetSettings flags=0x%x mask=0x%x\n", lpsfs, dwMask)
		if lpsfs != 0 { ctx.Mem.Write32(lpsfs, 0) }
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetShellFolderViewCB", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHGetShellFolderViewCB(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSpecialFolderLocation", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		csidl := ctx.Arg(1)
		ppidl := ctx.Arg(2)
		_ = hwnd
		ravelog.Logf("[shell32] SHGetSpecialFolderLocation csidl=0x%x out=0x%x\n", csidl, ppidl)
		// Return a minimal PIDL (2 bytes: size=0 = terminator)
		if ppidl != 0 {
			pidl := sharedHeapAlloc(4, true)
			ctx.Mem.Write16(pidl, 0) // empty PIDL terminator
			ctx.Mem.Write64(ppidl, pidl)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSpecialFolderPath", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetSpecialFolderPath(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetUnreadMailCountW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] SHGetUnreadMailCountW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetUserDisplayName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHGetUserDisplayName(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetUserPicturePathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHGetUserPicturePathW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetUserSessionId", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHGetUserSessionId(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGlobalDefect", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHGlobalDefect(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHHandleDiskFull", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHHandleDiskFull(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHHandleUpdateImage", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHHandleUpdateImage(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHHelpShortcuts_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHHelpShortcuts_RunDLL(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHHelpShortcuts_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHHelpShortcuts_RunDLLA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHHelpShortcuts_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHHelpShortcuts_RunDLLW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHILCreateFromPath", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHILCreateFromPath(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHInvokePrinterCommandA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] SHInvokePrinterCommandA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHInvokePrinterCommandW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] SHInvokePrinterCommandW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHInvokePrivilegedFunctionW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHInvokePrivilegedFunctionW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHIsBadInterfacePtr", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHIsBadInterfacePtr(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHIsFileAvailableOffline", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHIsFileAvailableOffline(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHIsTempDisplayMode", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHIsTempDisplayMode()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLimitInputCombo", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHLimitInputCombo(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLimitInputEdit", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHLimitInputEdit(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLoadInProc", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHLoadInProc(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLoadNonloadedIconOverlayIdentifiers", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHLoadNonloadedIconOverlayIdentifiers()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLoadOLE", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHLoadOLE(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLockShared", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHLockShared(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLogILFromFSIL", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHLogILFromFSIL(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLookupIconIndexA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHLookupIconIndexA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLookupIconIndexW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHLookupIconIndexW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHMapIDListToImageListIndexAsync", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] SHMapIDListToImageListIndexAsync(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHMapPIDLToSystemImageListIndex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHMapPIDLToSystemImageListIndex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHMultiFileProperties", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHMultiFileProperties(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHNetConnectionDialog", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHNetConnectionDialog(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHObjectProperties", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHObjectProperties(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHOpenEffectiveToken", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHOpenEffectiveToken(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHOpenFolderAndSelectItems", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHOpenFolderAndSelectItems(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHOpenPropSheetA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] SHOpenPropSheetA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHOpenPropSheetW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] SHOpenPropSheetW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHOutOfMemoryMessageBox", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHOutOfMemoryMessageBox(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHParseDarwinIDFromCacheW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHParseDarwinIDFromCacheW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHParseDisplayName", func(ctx *ntapi.TrapContext) uint32 {
		pszName := ctx.Arg(0)
		pbc := ctx.Arg(1)
		ppidl := ctx.Arg(2)
		sfgaoIn := ctx.Arg(3)
		psfgaoOut := ctx.Arg(4)
		var name string
		if pszName != 0 { name = readGuestUTF16(pszName) }
		ravelog.Logf("[shell32] SHParseDisplayName name=%q\n", name)
		_ = pbc; _ = sfgaoIn
		if ppidl != 0 {
			pidl := sharedHeapAlloc(4, true)
			ctx.Mem.Write16(pidl, 0) // empty PIDL
			ctx.Mem.Write64(ppidl, pidl)
		}
		if psfgaoOut != 0 { ctx.Mem.Write32(psfgaoOut, 0) }
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHPathPrepareForWriteA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHPathPrepareForWriteA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHPathPrepareForWriteW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHPathPrepareForWriteW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHPropStgCreate", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] SHPropStgCreate(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHPropStgReadMultiple", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] SHPropStgReadMultiple(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHPropStgWriteMultiple", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] SHPropStgWriteMultiple(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHQueryRecycleBinA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHQueryRecycleBinA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHQueryRecycleBinW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHQueryRecycleBinW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHReValidateDarwinCache", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHReValidateDarwinCache()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHRegisterDragDrop", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHRegisterDragDrop(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHReplaceFromPropSheetExtArray", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHReplaceFromPropSheetExtArray(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHRestricted", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHRestricted(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHRevokeDragDrop", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHRevokeDragDrop(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHRunControlPanel", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHRunControlPanel(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSetFolderPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHSetFolderPathA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSetFolderPathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHSetFolderPathW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSetInstanceExplorer", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHSetInstanceExplorer(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSetLocalizedName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHSetLocalizedName(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSetShellWindowEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHSetShellWindowEx(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSetUserPicturePathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHSetUserPicturePathW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSettingsChanged", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHSettingsChanged(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHShellFolderView_Message", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHShellFolderView_Message(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHShouldShowWizards", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHShouldShowWizards(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSimpleIDListFromPath", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHSimpleIDListFromPath(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSimulateDropOnClsid", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHSimulateDropOnClsid(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHStartNetConnectionDialog", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHStartNetConnectionDialog(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHStartNetConnectionDialogA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHStartNetConnectionDialogA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHStartNetConnectionDialogW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHStartNetConnectionDialogW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHTestTokenMembership", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHTestTokenMembership(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHTestTokenPrivilegeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHTestTokenPrivilegeW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHUnlockShared", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHUnlockShared(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHUpdateImageA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHUpdateImageA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHUpdateImageW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHUpdateImageW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHUpdateRecycleBinIcon", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHUpdateRecycleBinIcon()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHValidateUNC", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHValidateUNC(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHWaitForFileToOpen", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SHWaitForFileToOpen(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHWaitOp_Operate", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SHWaitOp_Operate(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHWinHelp", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] SHWinHelp(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SetAppStartingCursor", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SetAppStartingCursor(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheChangeDirA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheChangeDirA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheChangeDirExA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheChangeDirExA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheChangeDirExW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheChangeDirExW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheChangeDirW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheChangeDirW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheConvertPathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SheConvertPathW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheFullPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SheFullPathA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheFullPathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SheFullPathW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheGetCurDrive", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SheGetCurDrive()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheGetDirA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SheGetDirA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheGetDirExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] SheGetDirExW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheGetDirW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SheGetDirW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheGetPathOffsetW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheGetPathOffsetW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheRemoveQuotesA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheRemoveQuotesA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheRemoveQuotesW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheRemoveQuotesW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheSetCurDrive", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheSetCurDrive(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheShortenPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SheShortenPathA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheShortenPathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] SheShortenPathW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellAboutA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		szApp := ctx.Arg(1)
		szOtherStuff := ctx.Arg(2)
		hIcon := ctx.Arg(3)
		var app string
		if szApp != 0 { app = readGuestUTF16(szApp) }
		ravelog.Logf("[shell32] ShellAboutA app=%q\n", app)
		_ = hwnd; _ = szOtherStuff; _ = hIcon
		ctx.SetReturn(1) // TRUE - dialog shown
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellDDEInit", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ShellDDEInit(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellExec_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] ShellExec_RunDLL(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellExec_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] ShellExec_RunDLLA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellExec_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] ShellExec_RunDLLW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellExecuteEx", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ShellExecuteEx(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellHookProc", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] ShellHookProc(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellMessageBoxA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[shell32] ShellMessageBoxA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellMessageBoxW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] ShellMessageBoxW()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Shell_GetCachedImageIndex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] Shell_GetCachedImageIndex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Shell_GetImageLists", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] Shell_GetImageLists(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Shell_MergeMenus", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] Shell_MergeMenus(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Shell_NotifyIcon", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] Shell_NotifyIcon(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Shell_NotifyIconA", func(ctx *ntapi.TrapContext) uint32 {
		dwMessage := ctx.Arg(0)
		lpData := ctx.Arg(1)
		ravelog.Logf("[shell32] Shell_NotifyIconA msg=0x%x data=0x%x\n", dwMessage, lpData)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Shell_NotifyIconW", func(ctx *ntapi.TrapContext) uint32 {
		dwMessage := ctx.Arg(0)
		lpData := ctx.Arg(1)
		ravelog.Logf("[shell32] Shell_NotifyIconW msg=0x%x data=0x%x\n", dwMessage, lpData)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShortSizeFormatW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] ShortSizeFormatW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SignalFileOpen", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SignalFileOpen(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrChrA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] StrChrA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrChrIA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] StrChrIA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrChrIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] StrChrIW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrChrW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] StrChrW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrCmpNA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrCmpNA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrCmpNIA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrCmpNIA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrCmpNIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrCmpNIW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrCmpNW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrCmpNW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrCpyNW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrCpyNW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrNCmpA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrNCmpA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrNCmpIA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrNCmpIA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrNCmpIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrNCmpIW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrNCmpW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrNCmpW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrNCpyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrNCpyW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRChrA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrRChrA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRChrIA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrRChrIA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRChrIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrRChrIW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRChrW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrRChrW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRStrA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrRStrA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRStrIA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrRStrIA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRStrIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrRStrIW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRStrW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[shell32] StrRStrW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRetToStrN", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] StrRetToStrN(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrStrA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] StrStrA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrStrIA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] StrStrIA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrStrIW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] StrStrIW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrStrW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] StrStrW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrToOleStr", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] StrToOleStr(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrToOleStrN", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[shell32] StrToOleStrN(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "WOWShellExecute", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[shell32] WOWShellExecute(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Win32CreateDirectory", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[shell32] Win32CreateDirectory(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Win32DeleteFile", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] Win32DeleteFile(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Win32RemoveDirectory", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] Win32RemoveDirectory(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "WriteCabinetState", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[shell32] WriteCabinetState(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
}

func registerShcoreHandlers2(hctx *HandlerCtx) {
	d := hctx.Disp
	imagePath := hctx.ImagePath
	mem := hctx.Mem
	readGuestUTF16 := hctx.ReadGuestUTF16

	shcore, ok := hctx.SynthByName["shcore.dll"]
	if !ok {
		return
	}
	_ = shcore

	d.RegisterAutoStubHandler(shcore, "CommandLineToArgvW", func(ctx *ntapi.TrapContext) uint32 {
		// LPWSTR* CommandLineToArgvW(LPCWSTR lpCmdLine, int *pNumArgs)
		lpCmdLine := ctx.Arg(0)
		pNumArgs := ctx.Arg(1)

		cmdLine := ""
		if lpCmdLine != 0 {
			cmdLine = readGuestUTF16(lpCmdLine)
		}

		args := parseCommandLine(cmdLine)
		if len(args) == 0 {
			args = []string{imagePath}
		}

		// Layout: [N+1 pointers (NULL-terminated)] [string data]
		ptrAreaSize := uint64(len(args)+1) * 8
		strAreaSize := uint64(0)
		for _, a := range args {
			strAreaSize += (uint64(len([]rune(a))) + 1) * 2
		}
		totalSize := ptrAreaSize + strAreaSize
		if totalSize < 4096 {
			totalSize = 4096
		}

		page := mem.Mmap(0, totalSize, mmu.PermRead|mmu.PermWrite)
		strOff := page + ptrAreaSize
		for i, arg := range args {
			mem.Write64(page+uint64(i)*8, strOff)
			for _, r := range arg {
				mem.Write16(strOff, uint16(r))
				strOff += 2
			}
			mem.Write16(strOff, 0)
			strOff += 2
		}
		mem.Write64(page+uint64(len(args))*8, 0) // NULL terminator

		if pNumArgs != 0 {
			mem.Write32(pNumArgs, uint32(len(args)))
		}
		ctx.SetReturn(page)
		return 0
	})
	d.RegisterAutoStubHandler(shcore, "GetDpiForMonitor", func(ctx *ntapi.TrapContext) uint32 {
		dpiX := ctx.Arg(2)
		dpiY := ctx.Arg(3)
		if dpiX != 0 {
			mem.Write32(dpiX, 96)
		}
		if dpiY != 0 {
			mem.Write32(dpiY, 96)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	var dpiAwareness uint32
	d.RegisterAutoStubHandler(shcore, "SetProcessDpiAwareness", func(ctx *ntapi.TrapContext) uint32 {
		// HRESULT SetProcessDpiAwareness(PROCESS_DPI_AWARENESS value)
		// ReactOS/Wine: dll/win32/shcore/main.c
		newVal := uint32(ctx.Arg(0))
		if dpiAwareness != 0 && newVal != dpiAwareness {
			ctx.SetReturn(0x80070005) // E_ACCESSDENIED - already set
			return 0
		}
		dpiAwareness = newVal
		ctx.SetReturn(0) // S_OK
		return 0
	})
}
