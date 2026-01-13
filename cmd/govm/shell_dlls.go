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
}

func registerShell32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16

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
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconExW", func(ctx *ntapi.TrapContext) uint32 {
		// UINT ExtractIconExW(LPCWSTR lpszFile, int nIconIndex,
		//   HICON *phiconLarge, HICON *phiconSmall, UINT nIcons)
		ctx.SetReturn(0) // 0 icons extracted
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconExA", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(shcore, "SetProcessDpiAwareness", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // S_OK
		return 0
	})
}
