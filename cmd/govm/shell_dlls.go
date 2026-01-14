package main

import (
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

var shellEnvPattern = regexp.MustCompile(`%([^%]+)%`)

var (
	FOLDERID_Desktop        = GUID{0xB4BFCC3A, 0xDB2C, 0x424C, [8]byte{0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41}}
	FOLDERID_Documents      = GUID{0xFDD39AD0, 0x238F, 0x46AF, [8]byte{0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7}}
	FOLDERID_Downloads      = GUID{0x374DE290, 0x123F, 0x4565, [8]byte{0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B}}
	FOLDERID_Music          = GUID{0x4BD8D571, 0x6D19, 0x48D3, [8]byte{0xBE, 0x97, 0x42, 0x22, 0x20, 0x08, 0x0E, 0x43}}
	FOLDERID_Pictures       = GUID{0x33E28130, 0x4E1E, 0x4676, [8]byte{0x83, 0x5A, 0x98, 0x39, 0x5C, 0x3B, 0xC3, 0xBB}}
	FOLDERID_Videos         = GUID{0x18989B1D, 0x99B5, 0x455B, [8]byte{0x84, 0x1C, 0xAB, 0x7C, 0x74, 0xE4, 0xDD, 0xFC}}
	FOLDERID_LocalAppData   = GUID{0xF1B32785, 0x6FBA, 0x4FCF, [8]byte{0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91}}
	FOLDERID_RoamingAppData = GUID{0x3EB685DB, 0x65F9, 0x4CF6, [8]byte{0xA0, 0x3A, 0xE3, 0xEF, 0x65, 0x72, 0x9F, 0x3D}}
	FOLDERID_ProgramData    = GUID{0x62AB5D82, 0xFDC1, 0x4DC3, [8]byte{0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97}}
	FOLDERID_Windows        = GUID{0xF38BF404, 0x1D43, 0x42F2, [8]byte{0x93, 0x05, 0x67, 0xDE, 0x0B, 0x28, 0xFC, 0x23}}
	FOLDERID_System         = GUID{0x1AC14E77, 0x02E7, 0x4E5D, [8]byte{0xB7, 0x44, 0x2E, 0xB1, 0xAE, 0x51, 0x98, 0xB7}}
	FOLDERID_ProgramFiles   = GUID{0x905E63B6, 0xC1BF, 0x494E, [8]byte{0xB2, 0x9C, 0x65, 0xB7, 0x32, 0xD3, 0xD2, 0x1A}}
	FOLDERID_Fonts          = GUID{0xFD228CB7, 0xAE11, 0x4AE3, [8]byte{0x86, 0x4C, 0x16, 0xF3, 0x91, 0x0A, 0xB8, 0xFE}}
	FOLDERID_Temp           = GUID{0x54EED2E0, 0xE7CA, 0x4F7A, [8]byte{0xB1, 0xD7, 0xE4, 0x3B, 0xF4, 0xDF, 0xA6, 0x00}}
	FOLDERID_Profile        = GUID{0x5E6C858F, 0x0E22, 0x4760, [8]byte{0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73}}
)

func shellHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "/home/user"
	}
	return home
}

func shellUserName() string {
	base := filepath.Base(shellHomeDir())
	if base == "." || base == "/" || base == "" {
		return "user"
	}
	return base
}

func linuxToWinPath(linuxPath string) string {
	if linuxPath == "" {
		return `C:\`
	}
	clean := filepath.Clean(linuxPath)
	home := filepath.Clean(shellHomeDir())
	user := shellUserName()
	switch {
	case clean == "/":
		return `C:\`
	case clean == home:
		return `C:\Users\` + user
	case strings.HasPrefix(clean, home+"/"):
		rel := strings.TrimPrefix(clean, home+"/")
		if rel == "" {
			return `C:\Users\` + user
		}
		return `C:\Users\` + user + `\` + strings.ReplaceAll(rel, "/", `\`)
	}
	p := strings.ReplaceAll(clean, "/", `\`)
	if strings.HasPrefix(p, `\`) {
		return `C:` + p
	}
	return `C:\` + p
}

func winToLinuxPath(winPath string) string {
	p := strings.ReplaceAll(strings.TrimSpace(winPath), `\`, "/")
	if len(p) >= 2 && p[1] == ':' {
		p = p[2:]
	}
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	lower := strings.ToLower(p)
	userLower := strings.ToLower(shellUserName())
	switch {
	case strings.HasPrefix(lower, "/users/"+userLower):
		prefixLen := len("/Users/") + len(shellUserName())
		rel := p[prefixLen:]
		if rel == "" {
			return shellHomeDir()
		}
		return filepath.Clean(shellHomeDir() + rel)
	case strings.HasPrefix(lower, "/windows/system32"):
		return filepath.Clean("/usr/lib" + p[len("/Windows/System32"):])
	case strings.HasPrefix(lower, "/windows"):
		return filepath.Clean("/usr" + p[len("/Windows"):])
	case strings.HasPrefix(lower, "/program files"):
		return filepath.Clean("/opt" + p[len("/Program Files"):])
	case strings.HasPrefix(lower, "/programdata"):
		return filepath.Clean("/var/lib" + p[len("/ProgramData"):])
	default:
		return filepath.Clean(p)
	}
}

func shellCSIDLPaths() map[int]string {
	home := shellHomeDir()
	return map[int]string{
		0x0000: filepath.Join(home, "Desktop"),
		0x0005: filepath.Join(home, "Documents"),
		0x0006: filepath.Join(home, "Favorites"),
		0x0008: filepath.Join(home, ".local", "share", "Recent"),
		0x0009: filepath.Join(home, ".local", "share", "SendTo"),
		0x000B: filepath.Join(home, ".config", "Start Menu"),
		0x000D: filepath.Join(home, "Music"),
		0x000E: filepath.Join(home, "Videos"),
		0x0014: filepath.Join(home, ".local", "share", "fonts"),
		0x001A: filepath.Join(home, ".config"),
		0x001C: filepath.Join(home, ".local", "share"),
		0x001D: os.TempDir(),
		0x0023: "/var/lib",
		0x0024: "/usr",
		0x0025: "/usr/lib",
		0x0026: "/opt",
		0x0027: filepath.Join(home, "Pictures"),
		0x0028: home,
		0x0029: "/usr/lib",
		0x002A: "/opt",
		0x002B: "/opt/common",
	}
}

func shellKnownFolderPaths() map[GUID]string {
	home := shellHomeDir()
	return map[GUID]string{
		FOLDERID_Desktop:        filepath.Join(home, "Desktop"),
		FOLDERID_Documents:      filepath.Join(home, "Documents"),
		FOLDERID_Downloads:      filepath.Join(home, "Downloads"),
		FOLDERID_Music:          filepath.Join(home, "Music"),
		FOLDERID_Pictures:       filepath.Join(home, "Pictures"),
		FOLDERID_Videos:         filepath.Join(home, "Videos"),
		FOLDERID_LocalAppData:   filepath.Join(home, ".local", "share"),
		FOLDERID_RoamingAppData: filepath.Join(home, ".config"),
		FOLDERID_ProgramData:    "/var/lib",
		FOLDERID_Windows:        "/usr",
		FOLDERID_System:         "/usr/lib",
		FOLDERID_ProgramFiles:   "/opt",
		FOLDERID_Fonts:          "/usr/share/fonts",
		FOLDERID_Temp:           os.TempDir(),
		FOLDERID_Profile:        home,
	}
}

// csidlToPath maps a CSIDL folder ID to its Windows path backed by the host FS.
func csidlToPath(csidl int32) string {
	if p, ok := shellCSIDLPaths()[int(csidl)&0xFF]; ok {
		return linuxToWinPath(p)
	}
	return linuxToWinPath(shellHomeDir())
}

func knownFolderPath(id GUID) string {
	if p, ok := shellKnownFolderPaths()[id]; ok {
		return linuxToWinPath(p)
	}
	return linuxToWinPath(shellHomeDir())
}

func expandShellEnvironmentStrings(src string) string {
	vars := map[string]string{
		"APPDATA":       linuxToWinPath(filepath.Join(shellHomeDir(), ".config")),
		"LOCALAPPDATA":  linuxToWinPath(filepath.Join(shellHomeDir(), ".local", "share")),
		"TEMP":          linuxToWinPath(os.TempDir()),
		"TMP":           linuxToWinPath(os.TempDir()),
		"USERPROFILE":   linuxToWinPath(shellHomeDir()),
		"WINDIR":        linuxToWinPath("/usr"),
		"SYSTEMROOT":    linuxToWinPath("/usr"),
		"SYSTEMDRIVE":   `C:`,
		"PROGRAMFILES":  linuxToWinPath("/opt"),
		"COMMONAPPDATA": linuxToWinPath("/var/lib"),
		"PROGRAMDATA":   linuxToWinPath("/var/lib"),
		"USERNAME":      shellUserName(),
		"HOMEPATH":      `\\Users\\` + shellUserName(),
		"HOMEDRIVE":     `C:`,
	}
	return shellEnvPattern.ReplaceAllStringFunc(src, func(match string) string {
		key := strings.ToUpper(strings.Trim(match, "%"))
		if val, ok := vars[key]; ok {
			return val
		}
		if val, ok := os.LookupEnv(key); ok {
			return val
		}
		return match
	})
}

func writeWideString(mem *mmu.MMU, dst uint64, s string, maxChars int) int {
	if dst == 0 || maxChars <= 0 {
		return 0
	}
	ws := utf16Encode(s)
	if len(ws) >= maxChars {
		ws = ws[:maxChars-1]
	}
	for i, w := range ws {
		mem.Write16(dst+uint64(i)*2, w)
	}
	mem.Write16(dst+uint64(len(ws))*2, 0)
	return len(ws)
}

func writeAnsiString(mem *mmu.MMU, dst uint64, s string, maxChars int) int {
	if dst == 0 || maxChars <= 0 {
		return 0
	}
	bs := []byte(s)
	if len(bs) >= maxChars {
		bs = bs[:maxChars-1]
	}
	for i, b := range bs {
		mem.Write8(dst+uint64(i), b)
	}
	mem.Write8(dst+uint64(len(bs)), 0)
	return len(bs)
}

func isAbsoluteWinPath(p string) bool {
	if len(p) >= 2 && p[1] == ':' {
		return true
	}
	return strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `/`) || strings.HasPrefix(p, `\`)
}

func canonicalizeWinPath(p string) string {
	if p == "" {
		return ""
	}
	norm := strings.ReplaceAll(p, `\`, "/")
	prefix := ""
	body := norm
	if len(norm) >= 2 && norm[1] == ':' {
		prefix = norm[:2]
		body = norm[2:]
	}
	clean := path.Clean(body)
	if clean == "." {
		clean = ""
	}
	if prefix != "" {
		if clean == "" || clean == "/" {
			return prefix + `\`
		}
		if !strings.HasPrefix(clean, "/") {
			clean = "/" + clean
		}
		return prefix + strings.ReplaceAll(clean, "/", `\`)
	}
	return strings.ReplaceAll(clean, "/", `\`)
}

func allocPIDLFromPath(mem *mmu.MMU, alloc func(uint64, bool) uint64, winPath string) uint64 {
	if alloc == nil {
		return 0
	}
	ws := utf16Encode(winPath)
	itemSize := uint16(2 + len(ws)*2 + 2)
	total := uint64(itemSize) + 2
	pidl := alloc(total, true)
	if pidl == 0 {
		return 0
	}
	mem.Write16(pidl, itemSize)
	for i, w := range ws {
		mem.Write16(pidl+2+uint64(i)*2, w)
	}
	mem.Write16(pidl+2+uint64(len(ws))*2, 0)
	mem.Write16(pidl+uint64(itemSize), 0)
	return pidl
}

func pidlPathFromMemory(mem *mmu.MMU, pidl uint64) string {
	if pidl == 0 {
		return ""
	}
	cb, _ := mem.Read16(pidl)
	if cb < 4 {
		return ""
	}
	var sb strings.Builder
	for off := uint64(2); off+1 < uint64(cb); off += 2 {
		w, _ := mem.Read16(pidl + off)
		if w == 0 {
			break
		}
		sb.WriteRune(rune(w))
	}
	return sb.String()
}

func parseMultiStringW(mem *mmu.MMU, addr uint64) []string {
	var out []string
	if addr == 0 {
		return out
	}
	cur := addr
	for {
		var sb strings.Builder
		for {
			w, _ := mem.Read16(cur)
			cur += 2
			if w == 0 {
				break
			}
			sb.WriteRune(rune(w))
		}
		if sb.Len() == 0 {
			break
		}
		out = append(out, sb.String())
	}
	return out
}

func parseMultiStringA(mem *mmu.MMU, addr uint64) []string {
	var out []string
	if addr == 0 {
		return out
	}
	cur := addr
	for {
		var buf []byte
		for {
			b, _ := mem.Read8(cur)
			cur++
			if b == 0 {
				break
			}
			buf = append(buf, b)
		}
		if len(buf) == 0 {
			break
		}
		out = append(out, string(buf))
	}
	return out
}

func copyHostPath(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return filepath.Walk(src, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(src, path)
			if err != nil {
				return err
			}
			target := dst
			if rel != "." {
				target = filepath.Join(dst, rel)
			}
			if info != nil && info.IsDir() {
				return os.MkdirAll(target, 0o755)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			in, err := os.Open(path)
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, in); err != nil {
				out.Close()
				return err
			}
			return out.Close()
		})
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func shFileOperationHost(mem *mmu.MMU, fileOp uint64, wide bool) error {
	if fileOp == 0 {
		return nil
	}
	wFunc, _ := mem.Read32(fileOp + 8)
	pFrom, _ := mem.Read64(fileOp + 16)
	pTo, _ := mem.Read64(fileOp + 24)
	var fromList, toList []string
	if wide {
		fromList = parseMultiStringW(mem, pFrom)
		toList = parseMultiStringW(mem, pTo)
	} else {
		fromList = parseMultiStringA(mem, pFrom)
		toList = parseMultiStringA(mem, pTo)
	}
	dstWin := ""
	if len(toList) > 0 {
		dstWin = toList[0]
	}
	for _, srcWin := range fromList {
		src := winToLinuxPath(srcWin)
		switch wFunc {
		case 1:
			target := winToLinuxPath(dstWin)
			if len(fromList) > 1 || (target != "" && func() bool { info, err := os.Stat(target); return err == nil && info.IsDir() }()) {
				target = filepath.Join(target, filepath.Base(src))
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Rename(src, target); err != nil {
				return err
			}
		case 2:
			target := winToLinuxPath(dstWin)
			if len(fromList) > 1 || (target != "" && func() bool { info, err := os.Stat(target); return err == nil && info.IsDir() }()) {
				target = filepath.Join(target, filepath.Base(src))
			}
			if err := copyHostPath(src, target); err != nil {
				return err
			}
		case 3:
			if err := os.RemoveAll(src); err != nil {
				return err
			}
		case 4:
			target := winToLinuxPath(dstWin)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Rename(src, target); err != nil {
				return err
			}
		}
	}
	mem.Write32(fileOp+36, 0)
	return nil
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
	sharedHeapAlloc := hctx.HeapAlloc
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] AppendMenuWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocCreate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] AssocCreate p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocGetPerceivedType", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] AssocGetPerceivedType p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocIsDangerous", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] AssocIsDangerous p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocQueryKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] AssocQueryKeyA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocQueryKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] AssocQueryKeyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocQueryStringA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] AssocQueryStringA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocQueryStringByKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] AssocQueryStringByKeyA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "AssocQueryStringByKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] AssocQueryStringByKeyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CLSIDFromProgIDWrap", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] CLSIDFromProgIDWrap p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CLSIDFromStringWrap", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] CLSIDFromStringWrap p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CallMsgFilterWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] CallMsgFilterWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CallWindowProcWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] CallWindowProcWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharLowerBuffWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] CharLowerBuffWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharLowerWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CharLowerWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharNextWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CharNextWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharPrevWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] CharPrevWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharToOemWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CharToOemWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharUpperBuffWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] CharUpperBuffWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CharUpperWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CharUpperWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ChrCmpIA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] ChrCmpIA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ChrCmpIW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] ChrCmpIW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CompareStringAltW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] CompareStringAltW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CompareStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] CompareStringWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ConnectToConnectionPoint", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] ConnectToConnectionPoint p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CopyAcceleratorTableWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] CopyAcceleratorTableWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CopyFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] CopyFileWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateAcceleratorTableWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] CreateAcceleratorTableWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateColorSpaceWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CreateColorSpaceWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateDCWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] CreateDCWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateDialogIndirectParamWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] CreateDialogIndirectParamWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateDialogParamWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] CreateDialogParamWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateDirectoryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] CreateDirectoryWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateEventWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] CreateEventWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] CreateFileWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateFontIndirectWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CreateFontIndirectWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateFontWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] CreateFontWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateICWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] CreateICWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateMetaFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] CreateMetaFileWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateMutexWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] CreateMutexWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateProcessWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] CreateProcessWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateSemaphoreWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] CreateSemaphoreWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "CreateWindowExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] CreateWindowExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DdeCreateStringHandleWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] DdeCreateStringHandleWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DdeInitializeWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] DdeInitializeWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DdeQueryStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] DdeQueryStringWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DefWindowProcWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] DefWindowProcWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DelayLoadFailureHook", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] DelayLoadFailureHook p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DeleteFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] DeleteFileWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DeleteMenuWrap", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] DeleteMenuWrap p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DestroyMenuWrap", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] DestroyMenuWrap p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DialogBoxIndirectParamWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] DialogBoxIndirectParamWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DialogBoxParamWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] DialogBoxParamWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DispatchMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] DispatchMessageWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DllGetVersion", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] DllGetVersion p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DoesStringRoundTripA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] DoesStringRoundTripA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DoesStringRoundTripW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] DoesStringRoundTripW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DragQueryFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] DragQueryFileWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DrawTextExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] DrawTextExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "DrawTextWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] DrawTextWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "EndDialogWrap", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] EndDialogWrap p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "EnumFontFamiliesExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] EnumFontFamiliesExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "EnumFontFamiliesWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] EnumFontFamiliesWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "EnumResourceNamesWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] EnumResourceNamesWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ExpandEnvironmentStringsWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] ExpandEnvironmentStringsWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ExtTextOutWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] ExtTextOutWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ExtractIconExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] ExtractIconExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ExtractIconWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] ExtractIconWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FDSA_DeleteItem", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] FDSA_DeleteItem p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FDSA_Destroy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] FDSA_Destroy p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FDSA_Initialize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] FDSA_Initialize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FDSA_InsertItem", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] FDSA_InsertItem p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FindFirstFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] FindFirstFileWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FindNextFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] FindNextFileWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FindResourceWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] FindResourceWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FindWindowExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] FindWindowExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FindWindowWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] FindWindowWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FixSlashesAndColonW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] FixSlashesAndColonW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "FormatMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] FormatMessageWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GUIDFromStringA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GUIDFromStringA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GUIDFromStringW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GUIDFromStringW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetAcceptLanguagesA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetAcceptLanguagesA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetAcceptLanguagesW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetAcceptLanguagesW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetCharWidth32WrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetCharWidth32WrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetCharacterPlacementWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] GetCharacterPlacementWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetClassInfoExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetClassInfoExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetClassInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetClassInfoWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetClassLongWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetClassLongWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetClassNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetClassNameWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetClipboardFormatNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetClipboardFormatNameWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetCurrentDirectoryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetCurrentDirectoryWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetDateFormatWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] GetDateFormatWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetDlgItemTextWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetDlgItemTextWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetEnvironmentVariableWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetEnvironmentVariableWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetFileAttributesWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GetFileAttributesWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetFileVersionInfoSizeWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetFileVersionInfoSizeWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetFileVersionInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetFileVersionInfoWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetFullPathNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetFullPathNameWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetLocaleInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetLocaleInfoWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetLongPathNameWrapA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetLongPathNameWrapA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetLongPathNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetLongPathNameWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetMIMETypeSubKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetMIMETypeSubKeyA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetMIMETypeSubKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetMIMETypeSubKeyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetMenuItemInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetMenuItemInfoWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetMenuPosFromID", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetMenuPosFromID p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetMenuStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] GetMenuStringWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetMessageWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetModuleFileNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetModuleFileNameWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetModuleHandleWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GetModuleHandleWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetNumberFormatWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] GetNumberFormatWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetObjectWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetObjectWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetOpenFileNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GetOpenFileNameWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetPerfTime", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] GetPerfTime()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetPrivateProfileIntWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetPrivateProfileIntWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetPrivateProfileStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] GetPrivateProfileStringWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetPrivateProfileStructWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] GetPrivateProfileStructWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetProfileStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] GetProfileStringWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetPropWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetPropWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetSaveFileNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GetSaveFileNameWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetShellSecurityDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetShellSecurityDescriptor p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetShortPathNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetShortPathNameWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetStringType3ExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetStringType3ExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetStringTypeExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] GetStringTypeExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetSystemDirectoryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetSystemDirectoryWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetTempFileNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetTempFileNameWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetTempPathWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetTempPathWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetTextExtentPoint32WrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] GetTextExtentPoint32WrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetTextFaceWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetTextFaceWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetTextMetricsWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetTextMetricsWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetTimeFormatWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] GetTimeFormatWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetUIVersion", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] GetUIVersion()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetUserNameWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetUserNameWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetWindowLongWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetWindowLongWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetWindowTextLengthWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GetWindowTextLengthWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetWindowTextWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] GetWindowTextWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GetWindowsDirectoryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GetWindowsDirectoryWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GlobalAddAtomWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GlobalAddAtomWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "GlobalFindAtomWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] GlobalFindAtomWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "HashData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] HashData p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IConnectionPoint_InvokeWithCancel", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] IConnectionPoint_InvokeWithCancel p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IConnectionPoint_OnChanged", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] IConnectionPoint_OnChanged p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IConnectionPoint_SimpleInvoke", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] IConnectionPoint_SimpleInvoke p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IContextMenu_Invoke", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] IContextMenu_Invoke p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IShellFolder_CompareIDs", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] IShellFolder_CompareIDs p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IShellFolder_EnumObjects", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] IShellFolder_EnumObjects p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IShellFolder_GetDisplayNameOf", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] IShellFolder_GetDisplayNameOf p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IShellFolder_ParseDisplayName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] IShellFolder_ParseDisplayName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IStream_Read", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] IStream_Read p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IStream_Reset", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IStream_Reset p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IStream_Size", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] IStream_Size p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IStream_Write", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] IStream_Write p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_AtomicRelease", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IUnknown_AtomicRelease p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_CPContainerInvokeParam", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] IUnknown_CPContainerInvokeParam p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_CPContainerOnChanged", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_CPContainerOnChanged p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_EnableModeless", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_EnableModeless p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_Exec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] IUnknown_Exec p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_GetClassID", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_GetClassID p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_GetSite", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] IUnknown_GetSite p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_GetWindow", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_GetWindow p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_HandleIRestrict", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] IUnknown_HandleIRestrict p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_HasFocusIO", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IUnknown_HasFocusIO p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_OnFocusChangeIS", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] IUnknown_OnFocusChangeIS p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_OnFocusOCS", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_OnFocusOCS p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_ProfferService", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] IUnknown_ProfferService p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_QueryService", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] IUnknown_QueryService p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_QueryServiceExec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] IUnknown_QueryServiceExec p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_QueryServiceForWebBrowserApp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] IUnknown_QueryServiceForWebBrowserApp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_QueryServicePropertyBag", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] IUnknown_QueryServicePropertyBag p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_QueryStatus", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] IUnknown_QueryStatus p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_Set", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_Set p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_SetOwner", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_SetOwner p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_SetSite", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_SetSite p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_TranslateAcceleratorIO", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] IUnknown_TranslateAcceleratorIO p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_TranslateAcceleratorOCS", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] IUnknown_TranslateAcceleratorOCS p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IUnknown_UIActivateIO", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] IUnknown_UIActivateIO p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "InsertMenuItemWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] InsertMenuItemWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "InsertMenuWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] InsertMenuWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IntlStrEqWorkerA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] IntlStrEqWorkerA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IntlStrEqWorkerW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] IntlStrEqWorkerW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsBadStringPtrWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] IsBadStringPtrWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharAlphaNumericWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharAlphaNumericWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharAlphaWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharAlphaWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharBlankW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharBlankW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharCntrlW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharCntrlW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharDigitW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharDigitW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharLowerWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharLowerWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharPunctW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharPunctW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharSpaceA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharSpaceA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharSpaceW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharSpaceW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharUpperWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharUpperWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsCharXDigitW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsCharXDigitW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsDialogMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] IsDialogMessageWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsInternetESCEnabled", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] IsInternetESCEnabled()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsOS", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] IsOS p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "IsQSForward", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] IsQSForward p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadAcceleratorsWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] LoadAcceleratorsWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadBitmapWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] LoadBitmapWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadCursorWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] LoadCursorWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadIconWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] LoadIconWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadImageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] LoadImageWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadLibraryExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] LoadLibraryExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadLibraryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] LoadLibraryWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadMenuWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] LoadMenuWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "LoadStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] LoadStringWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MIME_GetExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] MIME_GetExtensionA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MIME_GetExtensionW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] MIME_GetExtensionW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLBuildResURLA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] MLBuildResURLA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLBuildResURLW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] MLBuildResURLW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLClearMLHInstance", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] MLClearMLHInstance p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLFreeLibrary", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] MLFreeLibrary p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLGetUILanguage", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] MLGetUILanguage()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLIsMLHInstance", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] MLIsMLHInstance p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLLoadLibraryA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] MLLoadLibraryA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLLoadLibraryW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] MLLoadLibraryW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MLSetMLHInstance", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] MLSetMLHInstance p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MayExecForward", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] MayExecForward p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MayQSForward", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] MayQSForward p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MessageBoxIndirectWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] MessageBoxIndirectWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MessageBoxWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] MessageBoxWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ModifyMenuWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] ModifyMenuWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "MoveFileWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] MoveFileWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "OemToCharWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] OemToCharWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "OpenEventWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] OpenEventWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "OutputDebugStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] OutputDebugStringWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PageSetupDlgWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PageSetupDlgWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ParseURLA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] ParseURLA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ParseURLW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] ParseURLW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathAddBackslashA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathAddBackslashA path=0x%x\n", pszPath)
		if pszPath != 0 {
			// Find end of string
			i := uint64(0)
			for {
				b, _ := ctx.Mem.Read8(pszPath + i)
				if b == 0 {
					break
				}
				i++
			}
			if i > 0 {
				last, _ := ctx.Mem.Read8(pszPath + i - 1)
				if last != '\\' {
					ctx.Mem.Write8(pszPath+i, '\\')
					ctx.Mem.Write8(pszPath+i+1, 0)
					i++
				}
			}
			ctx.SetReturn(pszPath + i) // return pointer to NUL
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathAddBackslashW", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathAddBackslashW path=0x%x\n", pszPath)
		if pszPath != 0 {
			i := uint64(0)
			for {
				ch, _ := ctx.Mem.Read16(pszPath + i*2)
				if ch == 0 {
					break
				}
				i++
			}
			if i > 0 {
				last, _ := ctx.Mem.Read16(pszPath + (i-1)*2)
				if last != '\\' {
					ctx.Mem.Write16(pszPath+i*2, '\\')
					ctx.Mem.Write16(pszPath+(i+1)*2, 0)
					i++
				}
			}
			ctx.SetReturn(pszPath + i*2)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathAddExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathAddExtensionA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathAppendA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		pszMore := ctx.Arg(1)
		var base, more string
		if pszPath != 0 {
			base = readGuestUTF16(pszPath)
		}
		if pszMore != 0 {
			more = readGuestUTF16(pszMore)
		}
		ravelog.Logf("[shlwapi] PathAppendA base=%q more=%q\n", base, more)
		result := base
		if len(result) > 0 && result[len(result)-1] != '\\' {
			result += "\\"
		}
		result += more
		if pszPath != 0 {
			for i, ch := range result {
				if i >= 259 {
					break
				}
				ctx.Mem.Write16(pszPath+uint64(i*2), uint16(ch))
			}
			ctx.Mem.Write16(pszPath+uint64(len(result)*2), 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathBuildRootA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathBuildRootA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathBuildRootW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathBuildRootW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCanonicalizeA", func(ctx *ntapi.TrapContext) uint32 {
		pszBuf := ctx.Arg(0)
		pszPath := ctx.Arg(1)
		var path string
		if pszPath != 0 {
			path = readGuestUTF16(pszPath)
		}
		ravelog.Logf("[shlwapi] PathCanonicalizeA path=%q\n", path)
		// Simple canonicalization: just copy (full impl would resolve . and ..)
		if pszBuf != 0 {
			for i, ch := range path {
				if i >= 259 {
					break
				}
				ctx.Mem.Write16(pszBuf+uint64(i*2), uint16(ch))
			}
			ctx.Mem.Write16(pszBuf+uint64(len(path)*2), 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCanonicalizeW", func(ctx *ntapi.TrapContext) uint32 {
		canon := canonicalizeWinPath(readGuestUTF16(ctx.Arg(1)))
		writeWideString(ctx.Mem, ctx.Arg(0), canon, 260)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCombineA", func(ctx *ntapi.TrapContext) uint32 {
		pszDest := ctx.Arg(0)
		pszDir := ctx.Arg(1)
		pszFile := ctx.Arg(2)
		var dir, file string
		if pszDir != 0 {
			dir = readGuestString(pszDir)
		}
		if pszFile != 0 {
			file = readGuestString(pszFile)
		}
		ravelog.Logf("[shlwapi] PathCombineA dir=%q file=%q\n", dir, file)
		result := dir
		if len(result) > 0 && result[len(result)-1] != '\\' {
			result += "\\"
		}
		result += file
		if pszDest != 0 {
			for i := 0; i < len(result) && i < 259; i++ {
				ctx.Mem.Write8(pszDest+uint64(i), result[i])
			}
			ctx.Mem.Write8(pszDest+uint64(len(result)), 0)
		}
		ctx.SetReturn(pszDest)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCommonPrefixA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathCommonPrefixA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCommonPrefixW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathCommonPrefixW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCompactPathA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathCompactPathA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCompactPathExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] PathCompactPathExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCompactPathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathCompactPathW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCreateFromUrlA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] PathCreateFromUrlA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathCreateFromUrlW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] PathCreateFromUrlW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFileExistsAndAttributesA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathFileExistsAndAttributesA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFileExistsAndAttributesW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathFileExistsAndAttributesW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFileExistsDefExtA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathFileExistsDefExtA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFileExistsDefExtAndAttributesW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathFileExistsDefExtAndAttributesW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFileExistsDefExtW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathFileExistsDefExtW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathFindExtensionA path=0x%x\n", pszPath)
		if pszPath == 0 {
			ctx.SetReturn(0)
			return 0
		}
		extPos := uint64(0)
		i := uint64(0)
		for {
			b, _ := ctx.Mem.Read8(pszPath + i)
			if b == 0 {
				break
			}
			if b == '.' {
				extPos = i
			}
			if b == '\\' || b == '/' {
				extPos = 0
			}
			i++
		}
		if extPos == 0 {
			extPos = i
		} // point to NUL if no extension
		ctx.SetReturn(pszPath + extPos)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathFindFileNameA path=0x%x\n", pszPath)
		if pszPath == 0 {
			ctx.SetReturn(0)
			return 0
		}
		last := pszPath
		i := uint64(0)
		for {
			b, _ := ctx.Mem.Read8(pszPath + i)
			if b == 0 {
				break
			}
			if b == '\\' || b == '/' {
				last = pszPath + i + 1
			}
			i++
		}
		ctx.SetReturn(last)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindNextComponentA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathFindNextComponentA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindNextComponentW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathFindNextComponentW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindOnPathA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathFindOnPathA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindOnPathExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathFindOnPathExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindOnPathExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathFindOnPathExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindOnPathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathFindOnPathW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindSuffixArrayA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathFindSuffixArrayA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathFindSuffixArrayW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathFindSuffixArrayW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathGetArgsA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathGetArgsA path=0x%x\n", pszPath)
		if pszPath == 0 {
			ctx.SetReturn(0)
			return 0
		}
		i := uint64(0)
		for {
			b, _ := ctx.Mem.Read8(pszPath + i)
			if b == 0 {
				ctx.SetReturn(pszPath + i)
				return 0
			}
			if b == ' ' {
				ctx.SetReturn(pszPath + i + 1)
				return 0
			}
			i++
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathGetArgsW", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathGetArgsW path=0x%x\n", pszPath)
		if pszPath == 0 {
			ctx.SetReturn(0)
			return 0
		}
		i := uint64(0)
		for {
			ch, _ := ctx.Mem.Read16(pszPath + i*2)
			if ch == 0 {
				ctx.SetReturn(pszPath + i*2)
				return 0
			}
			if ch == ' ' {
				ctx.SetReturn(pszPath + (i+1)*2)
				return 0
			}
			i++
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathGetCharTypeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathGetCharTypeA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathGetCharTypeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathGetCharTypeW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathGetDriveNumberA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathGetDriveNumberA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsContentTypeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsContentTypeA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsContentTypeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsContentTypeW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsDirectoryEmptyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsDirectoryEmptyA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsFileSpecA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		var path string
		if pszPath != 0 {
			path = readGuestUTF16(pszPath)
		}
		ravelog.Logf("[shlwapi] PathIsFileSpecA path=%q\n", path)
		if strings.ContainsAny(path, "\\/") {
			ctx.SetReturn(0) // has path separators
		} else {
			ctx.SetReturn(1) // just a filename
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsFileSpecW", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		var path string
		if pszPath != 0 {
			path = readGuestUTF16(pszPath)
		}
		ravelog.Logf("[shlwapi] PathIsFileSpecW path=%q\n", path)
		if strings.ContainsAny(path, "\\/") {
			ctx.SetReturn(0) // has path separators
		} else {
			ctx.SetReturn(1) // just a filename
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsLFNFileSpecA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsLFNFileSpecA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsLFNFileSpecW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsLFNFileSpecW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsNetworkPathA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsNetworkPathA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsPrefixA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsPrefixA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsPrefixW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsPrefixW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsRelativeA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsRelativeA path=0x%x\n", pszPath)
		if pszPath == 0 {
			ctx.SetReturn(1)
			return 0
		}
		b0, _ := ctx.Mem.Read8(pszPath)
		b1, _ := ctx.Mem.Read8(pszPath + 1)
		if (b0 >= 'A' && b0 <= 'Z' || b0 >= 'a' && b0 <= 'z') && b1 == ':' {
			ctx.SetReturn(0) // absolute
		} else if b0 == '\\' && b1 == '\\' {
			ctx.SetReturn(0) // UNC
		} else {
			ctx.SetReturn(1) // relative
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsRootA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		var path string
		if pszPath != 0 {
			path = readGuestUTF16(pszPath)
		}
		ravelog.Logf("[shlwapi] PathIsRootA path=%q\n", path)
		if path == "C:\\" || path == "C:" || path == "\\" {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsRootW", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		var path string
		if pszPath != 0 {
			path = readGuestUTF16(pszPath)
		}
		ravelog.Logf("[shlwapi] PathIsRootW path=%q\n", path)
		if path == "C:\\" || path == "C:" || path == "\\" {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsSameRootA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsSameRootA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsSameRootW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsSameRootW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsSystemFolderA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsSystemFolderA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsSystemFolderW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsSystemFolderW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsUNCA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		var path string
		if pszPath != 0 {
			path = readGuestUTF16(pszPath)
		}
		ravelog.Logf("[shlwapi] PathIsUNCA path=%q\n", path)
		if len(path) >= 2 && path[0] == '\\' && path[1] == '\\' {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsUNCServerA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsUNCServerA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsUNCServerShareA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsUNCServerShareA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsUNCServerShareW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsUNCServerShareW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsUNCServerW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathIsUNCServerW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsUNCW", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		var path string
		if pszPath != 0 {
			path = readGuestUTF16(pszPath)
		}
		ravelog.Logf("[shlwapi] PathIsUNCW path=%q\n", path)
		if len(path) >= 2 && path[0] == '\\' && path[1] == '\\' {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsValidCharA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsValidCharA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathIsValidCharW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathIsValidCharW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathMakePrettyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathMakePrettyA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathMakePrettyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathMakePrettyW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathMakeSystemFolderA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathMakeSystemFolderA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathMakeSystemFolderW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathMakeSystemFolderW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathMatchSpecA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathMatchSpecA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathParseIconLocationA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathParseIconLocationA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathParseIconLocationW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathParseIconLocationW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathQuoteSpacesA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathQuoteSpacesA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathQuoteSpacesW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathQuoteSpacesW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRelativePathToA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] PathRelativePathToA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRelativePathToW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] PathRelativePathToW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveArgsA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveArgsA path=0x%x\n", pszPath)
		if pszPath != 0 {
			i := uint64(0)
			for {
				b, _ := ctx.Mem.Read8(pszPath + i)
				if b == 0 {
					break
				}
				if b == ' ' {
					ctx.Mem.Write8(pszPath+i, 0)
					break
				}
				i++
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveArgsW", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveArgsW path=0x%x\n", pszPath)
		if pszPath != 0 {
			i := uint64(0)
			for {
				ch, _ := ctx.Mem.Read16(pszPath + i*2)
				if ch == 0 {
					break
				}
				if ch == ' ' {
					ctx.Mem.Write16(pszPath+i*2, 0)
					break
				}
				i++
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveBackslashA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveBackslashA path=0x%x\n", pszPath)
		if pszPath != 0 {
			i := uint64(0)
			for {
				b, _ := ctx.Mem.Read8(pszPath + i)
				if b == 0 {
					break
				}
				i++
			}
			if i > 0 {
				last, _ := ctx.Mem.Read8(pszPath + i - 1)
				if last == '\\' {
					ctx.Mem.Write8(pszPath+i-1, 0)
					i--
				}
			}
			ctx.SetReturn(pszPath + i)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveBackslashW", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveBackslashW path=0x%x\n", pszPath)
		if pszPath != 0 {
			i := uint64(0)
			for {
				ch, _ := ctx.Mem.Read16(pszPath + i*2)
				if ch == 0 {
					break
				}
				i++
			}
			if i > 0 {
				last, _ := ctx.Mem.Read16(pszPath + (i-1)*2)
				if last == '\\' {
					ctx.Mem.Write16(pszPath+(i-1)*2, 0)
					i--
				}
			}
			ctx.SetReturn(pszPath + i*2)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveBlanksA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveBlanksA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveBlanksW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveBlanksW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveExtensionA path=0x%x\n", pszPath)
		if pszPath != 0 {
			extPos := uint64(0)
			i := uint64(0)
			for {
				b, _ := ctx.Mem.Read8(pszPath + i)
				if b == 0 {
					break
				}
				if b == '.' {
					extPos = i
				}
				if b == '\\' || b == '/' {
					extPos = 0
				}
				i++
			}
			if extPos != 0 {
				ctx.Mem.Write8(pszPath+extPos, 0)
			}
		}
		ctx.SetReturn(0) // void
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRemoveFileSpecA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathRemoveFileSpecA path=0x%x\n", pszPath)
		if pszPath != 0 {
			lastSep := uint64(0)
			i := uint64(0)
			for {
				b, _ := ctx.Mem.Read8(pszPath + i)
				if b == 0 {
					break
				}
				if b == '\\' || b == '/' {
					lastSep = i
				}
				i++
			}
			if lastSep != 0 {
				ctx.Mem.Write8(pszPath+lastSep, 0)
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRenameExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathRenameExtensionA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathRenameExtensionW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] PathRenameExtensionW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSearchAndQualifyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathSearchAndQualifyA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSearchAndQualifyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathSearchAndQualifyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSetDlgItemPathA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathSetDlgItemPathA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSetDlgItemPathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathSetDlgItemPathW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSkipLeadingSlashesA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathSkipLeadingSlashesA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSkipRootA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathSkipRootA path=0x%x\n", pszPath)
		if pszPath == 0 {
			ctx.SetReturn(0)
			return 0
		}
		b0, _ := ctx.Mem.Read8(pszPath)
		b1, _ := ctx.Mem.Read8(pszPath + 1)
		if (b0 >= 'A' && b0 <= 'Z' || b0 >= 'a' && b0 <= 'z') && b1 == ':' {
			b2, _ := ctx.Mem.Read8(pszPath + 2)
			if b2 == '\\' || b2 == '/' {
				ctx.SetReturn(pszPath + 3)
			} else {
				ctx.SetReturn(pszPath + 2)
			}
		} else {
			ctx.SetReturn(pszPath)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathSkipRootW", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathSkipRootW path=0x%x\n", pszPath)
		if pszPath == 0 {
			ctx.SetReturn(0)
			return 0
		}
		c0, _ := ctx.Mem.Read16(pszPath)
		c1, _ := ctx.Mem.Read16(pszPath + 2)
		if (c0 >= 'A' && c0 <= 'Z' || c0 >= 'a' && c0 <= 'z') && c1 == ':' {
			c2, _ := ctx.Mem.Read16(pszPath + 4)
			if c2 == '\\' || c2 == '/' {
				ctx.SetReturn(pszPath + 6)
			} else {
				ctx.SetReturn(pszPath + 4)
			}
		} else {
			ctx.SetReturn(pszPath)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathStripPathA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathStripPathA path=0x%x\n", pszPath)
		if pszPath != 0 {
			lastSep := uint64(0)
			i := uint64(0)
			for {
				b, _ := ctx.Mem.Read8(pszPath + i)
				if b == 0 {
					break
				}
				if b == '\\' || b == '/' {
					lastSep = i + 1
				}
				i++
			}
			if lastSep > 0 {
				j := uint64(0)
				for {
					b, _ := ctx.Mem.Read8(pszPath + lastSep + j)
					ctx.Mem.Write8(pszPath+j, b)
					if b == 0 {
						break
					}
					j++
				}
			}
		}
		ctx.SetReturn(0) // void
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathStripToRootA", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathStripToRootA path=0x%x\n", pszPath)
		if pszPath != 0 {
			// Write "C:\" as root
			ctx.Mem.Write16(pszPath, uint16('C'))
			ctx.Mem.Write16(pszPath+2, uint16(':'))
			ctx.Mem.Write16(pszPath+4, uint16('\\'))
			ctx.Mem.Write16(pszPath+6, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUnExpandEnvStringsA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathUnExpandEnvStringsA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUnExpandEnvStringsW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PathUnExpandEnvStringsW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUndecorateA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathUndecorateA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUndecorateW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathUndecorateW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUnmakeSystemFolderA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathUnmakeSystemFolderA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PathUnmakeSystemFolderW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PathUnmakeSystemFolderW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PeekMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] PeekMessageWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PlaySoundWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] PlaySoundWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PostMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] PostMessageWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PostThreadMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] PostThreadMessageWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "PrintDlgWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] PrintDlgWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "QISearch", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] QISearch p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegCreateKeyExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] RegCreateKeyExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegCreateKeyWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] RegCreateKeyWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegDeleteKeyWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegDeleteKeyWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegDeleteValueWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegDeleteValueWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegEnumKeyExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] RegEnumKeyExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegEnumKeyWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] RegEnumKeyWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegEnumValueWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] RegEnumValueWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegOpenKeyExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] RegOpenKeyExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegOpenKeyWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] RegOpenKeyWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegQueryInfoKeyWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] RegQueryInfoKeyWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegQueryValueExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] RegQueryValueExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegQueryValueWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] RegQueryValueWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegSetValueExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] RegSetValueExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegSetValueWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] RegSetValueWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterClassExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] RegisterClassExWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterClassWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] RegisterClassWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterClipboardFormatWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] RegisterClipboardFormatWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterDefaultAcceptHeaders", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegisterDefaultAcceptHeaders p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterExtensionForMIMETypeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegisterExtensionForMIMETypeA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterExtensionForMIMETypeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegisterExtensionForMIMETypeW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterMIMETypeForExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegisterMIMETypeForExtensionA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterMIMETypeForExtensionW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] RegisterMIMETypeForExtensionW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RegisterWindowMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] RegisterWindowMessageWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RemoveDirectoryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] RemoveDirectoryWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RemovePropWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] RemovePropWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RunIndirectRegCommand", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] RunIndirectRegCommand p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "RunRegCommand", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] RunRegCommand p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAboutInfoA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHAboutInfoA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAboutInfoW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHAboutInfoW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAddDataBlock", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHAddDataBlock p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAllocShared", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHAllocShared p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAnsiToAnsi", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHAnsiToAnsi p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAnsiToUnicode", func(ctx *ntapi.TrapContext) uint32 {
		pszSrc := ctx.Arg(0)
		pwszDst := ctx.Arg(1)
		cwchBuf := int(ctx.Arg(2))
		if pszSrc != 0 && pwszDst != 0 {
			i := 0
			for i < cwchBuf-1 {
				b, _ := ctx.Mem.Read8(pszSrc + uint64(i))
				if b == 0 {
					break
				}
				ctx.Mem.Write16(pwszDst+uint64(i*2), uint16(b))
				i++
			}
			ctx.Mem.Write16(pwszDst+uint64(i*2), 0)
			ctx.SetReturn(uint64(i + 1))
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAnsiToUnicodeCP", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHAnsiToUnicodeCP p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAreIconsEqual", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHAreIconsEqual p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHAutoComplete", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHAutoComplete p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHBoolSystemParametersInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHBoolSystemParametersInfo p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHBrowseForFolderWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHBrowseForFolderWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHChangeNotifyWrap", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHChangeNotifyWrap p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCheckMenuItem", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHCheckMenuItem p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCoCreateInstanceAC", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHCoCreateInstanceAC p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCopyKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHCopyKeyA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCopyKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHCopyKeyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateMemStream", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHCreateMemStream p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreatePropertyBagOnMemory", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHCreatePropertyBagOnMemory p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreatePropertyBagOnProfileSection", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHCreatePropertyBagOnProfileSection p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreatePropertyBagOnRegKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHCreatePropertyBagOnRegKey p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateShellPalette", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHCreateShellPalette p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateStreamOnFileA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHCreateStreamOnFileA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateStreamOnFileEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHCreateStreamOnFileEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateStreamOnFileW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHCreateStreamOnFileW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateStreamWrapper", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHCreateStreamWrapper p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateThread", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHCreateThread p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateThreadRef", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHCreateThreadRef p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateWorkerWindowA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHCreateWorkerWindowA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHCreateWorkerWindowW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHCreateWorkerWindowW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDefExtractIconWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHDefExtractIconWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDefWindowProc", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHDefWindowProc p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteEmptyKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHDeleteEmptyKeyA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteEmptyKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHDeleteEmptyKeyW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteKeyA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pszSubKey := ctx.Arg(1)
		var sub string
		if pszSubKey != 0 {
			sub = readGuestUTF16(pszSubKey)
		}
		ravelog.Logf("[shlwapi] SHDeleteKeyA hkey=0x%x sub=%q\n", hKey, sub)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteKeyW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pszSubKey := ctx.Arg(1)
		var sub string
		if pszSubKey != 0 {
			sub = readGuestUTF16(pszSubKey)
		}
		ravelog.Logf("[shlwapi] SHDeleteKeyW hkey=0x%x sub=%q\n", hKey, sub)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteOrphanKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHDeleteOrphanKeyA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteOrphanKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHDeleteOrphanKeyW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteValueA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHDeleteValueA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHDeleteValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHDeleteValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHEnableMenuItem", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHEnableMenuItem p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHEnumKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHEnumKeyExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHEnumKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHEnumKeyExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHEnumValueA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHEnumValueA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHEnumValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHEnumValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHExpandEnvironmentStringsA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHExpandEnvironmentStringsA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHExpandEnvironmentStringsForUserA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHExpandEnvironmentStringsForUserA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHExpandEnvironmentStringsForUserW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHExpandEnvironmentStringsForUserW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHExpandEnvironmentStringsW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHExpandEnvironmentStringsW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFileOperationWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHFileOperationWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFillRectClr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHFillRectClr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFindDataBlock", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHFindDataBlock p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFlushSFCacheWrap", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] SHFlushSFCacheWrap()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFormatDateTimeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHFormatDateTimeA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFormatDateTimeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHFormatDateTimeW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHForwardContextMenuMsg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHForwardContextMenuMsg p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFreeDataBlockList", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHFreeDataBlockList p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHFreeShared", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHFreeShared p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetAppCompatFlags", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGetAppCompatFlags p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetCurColorRes", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] SHGetCurColorRes()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetFileInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHGetFileInfoWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetIniStringUTF7W", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHGetIniStringUTF7W p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetIniStringW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHGetIniStringW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetInverseCMAP", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGetInverseCMAP p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetMachineInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGetMachineInfo p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetMenuFromID", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGetMenuFromID p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetNewLinkInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHGetNewLinkInfoWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetObjectCompatFlags", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGetObjectCompatFlags p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetPathFromIDListWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGetPathFromIDListWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetPerScreenResName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHGetPerScreenResName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetRestriction", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHGetRestriction p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetShellKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHGetShellKey p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetSystemWindowsDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGetSystemWindowsDirectoryA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetSystemWindowsDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGetSystemWindowsDirectoryW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetThreadRef", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGetThreadRef p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetValueA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pszSubKey := ctx.Arg(1)
		pszValue := ctx.Arg(2)
		pdwType := ctx.Arg(3)
		pvData := ctx.Arg(4)
		pcbData := ctx.Arg(5)
		var sub, val string
		if pszSubKey != 0 {
			sub = readGuestUTF16(pszSubKey)
		}
		if pszValue != 0 {
			val = readGuestUTF16(pszValue)
		}
		ravelog.Logf("[shlwapi] SHGetValueA hkey=0x%x sub=%q val=%q\n", hKey, sub, val)
		_ = pdwType
		_ = pvData
		_ = pcbData
		ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetValueGoodBootA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHGetValueGoodBootA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetValueGoodBootW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHGetValueGoodBootW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetValueW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pszSubKey := ctx.Arg(1)
		pszValue := ctx.Arg(2)
		pdwType := ctx.Arg(3)
		pvData := ctx.Arg(4)
		pcbData := ctx.Arg(5)
		var sub, val string
		if pszSubKey != 0 {
			sub = readGuestUTF16(pszSubKey)
		}
		if pszValue != 0 {
			val = readGuestUTF16(pszValue)
		}
		ravelog.Logf("[shlwapi] SHGetValueW hkey=0x%x sub=%q val=%q\n", hKey, sub, val)
		_ = pdwType
		_ = pvData
		_ = pcbData
		ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetViewStatePropertyBag", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHGetViewStatePropertyBag p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetWebFolderFilePathA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHGetWebFolderFilePathA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGetWebFolderFilePathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHGetWebFolderFilePathW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGlobalCounterCreate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGlobalCounterCreate p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGlobalCounterCreateNamedA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGlobalCounterCreateNamedA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGlobalCounterCreateNamedW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHGlobalCounterCreateNamedW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGlobalCounterDecrement", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGlobalCounterDecrement p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGlobalCounterGetValue", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGlobalCounterGetValue p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHGlobalCounterIncrement", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGlobalCounterIncrement p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHInterlockedCompareExchange", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHInterlockedCompareExchange p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHInvokeCommand", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHInvokeCommand p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHInvokeCommandOnContextMenu", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHInvokeCommandOnContextMenu p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHInvokeDefaultCommand", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHInvokeDefaultCommand p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHIsChildOrSelf", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHIsChildOrSelf p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHIsEmptyStream", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHIsEmptyStream p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHIsExpandableFolder", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHIsExpandableFolder p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHIsLowMemoryMachine", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHIsLowMemoryMachine p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHIsSameObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHIsSameObject p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLoadFromPropertyBag", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHLoadFromPropertyBag p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLoadIndirectString", func(ctx *ntapi.TrapContext) uint32 {
		pszSource := ctx.Arg(0)
		pszOutBuf := ctx.Arg(1)
		cchOutBuf := ctx.Arg(2)
		ppvReserved := ctx.Arg(3)
		var src string
		if pszSource != 0 {
			src = readGuestUTF16(pszSource)
		}
		ravelog.Logf("[shlwapi] SHLoadIndirectString src=%q\n", src)
		_ = ppvReserved
		// Copy source to output as-is
		if pszOutBuf != 0 && cchOutBuf > 0 {
			for i, ch := range src {
				if uint64(i) >= cchOutBuf-1 {
					break
				}
				ctx.Mem.Write16(pszOutBuf+uint64(i*2), uint16(ch))
			}
			ctx.Mem.Write16(pszOutBuf+uint64(len(src)*2), 0)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLoadMenuPopup", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHLoadMenuPopup p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLoadRegUIStringA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHLoadRegUIStringA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLoadRegUIStringW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHLoadRegUIStringW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLockShared", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHLockShared p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHLockSharedEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHLockSharedEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHMapHandle", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHMapHandle p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHMenuIndexFromID", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHMenuIndexFromID p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHMessageBoxCheckA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHMessageBoxCheckA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHMessageBoxCheckExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHMessageBoxCheckExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHMessageBoxCheckExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHMessageBoxCheckExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHMessageBoxCheckW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHMessageBoxCheckW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHOpenRegStream2A", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pszSubKey := ctx.Arg(1)
		var sub string
		if pszSubKey != 0 {
			sub = readGuestUTF16(pszSubKey)
		}
		ravelog.Logf("[shlwapi] SHOpenRegStream2A hkey=0x%x sub=%q\n", hKey, sub)
		ctx.SetReturn(0) // NULL IStream
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHOpenRegStream2W", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pszSubKey := ctx.Arg(1)
		var sub string
		if pszSubKey != 0 {
			sub = readGuestUTF16(pszSubKey)
		}
		ravelog.Logf("[shlwapi] SHOpenRegStream2W hkey=0x%x sub=%q\n", hKey, sub)
		ctx.SetReturn(0) // NULL IStream
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHOpenRegStreamA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pszSubKey := ctx.Arg(1)
		var sub string
		if pszSubKey != 0 {
			sub = readGuestUTF16(pszSubKey)
		}
		ravelog.Logf("[shlwapi] SHOpenRegStreamA hkey=0x%x sub=%q\n", hKey, sub)
		ctx.SetReturn(0) // NULL IStream
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHOpenRegStreamW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pszSubKey := ctx.Arg(1)
		var sub string
		if pszSubKey != 0 {
			sub = readGuestUTF16(pszSubKey)
		}
		ravelog.Logf("[shlwapi] SHOpenRegStreamW hkey=0x%x sub=%q\n", hKey, sub)
		ctx.SetReturn(0) // NULL IStream
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPackDispParams", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPackDispParams p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPackDispParamsV", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHPackDispParamsV p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPinDllOfCLSID", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHPinDllOfCLSID p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropagateMessage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHPropagateMessage p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_Delete", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHPropertyBag_Delete p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadBOOL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadBOOL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadBOOLOld", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadBOOLOld p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadBSTR", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadBSTR p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadDWORD", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadDWORD p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadGUID", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadGUID p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadInt", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadInt p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadLONG", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadLONG p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadPOINTL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadPOINTL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadPOINTS", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadPOINTS p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadRECTL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadRECTL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadSHORT", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadSHORT p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadStream", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadStream p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_ReadType", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHPropertyBag_ReadType p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteBOOL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteBOOL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteDWORD", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteDWORD p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteGUID", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteGUID p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteInt", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteInt p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteLONG", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteLONG p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WritePOINTL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WritePOINTL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WritePOINTS", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WritePOINTS p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteRECTL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteRECTL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteSHORT", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteSHORT p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHPropertyBag_WriteStream", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHPropertyBag_WriteStream p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHQueryInfoKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHQueryInfoKeyA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHQueryInfoKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHQueryInfoKeyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHQueryValueExA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pszValue := ctx.Arg(1)
		pdwReserved := ctx.Arg(2)
		pdwType := ctx.Arg(3)
		pvData := ctx.Arg(4)
		pcbData := ctx.Arg(5)
		var val string
		if pszValue != 0 {
			val = readGuestUTF16(pszValue)
		}
		ravelog.Logf("[shlwapi] SHQueryValueExA hkey=0x%x val=%q\n", hKey, val)
		_ = pdwReserved
		_ = pdwType
		_ = pvData
		_ = pcbData
		ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHQueryValueExW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pszValue := ctx.Arg(1)
		pdwReserved := ctx.Arg(2)
		pdwType := ctx.Arg(3)
		pvData := ctx.Arg(4)
		pcbData := ctx.Arg(5)
		var val string
		if pszValue != 0 {
			val = readGuestUTF16(pszValue)
		}
		ravelog.Logf("[shlwapi] SHQueryValueExW hkey=0x%x val=%q\n", hKey, val)
		_ = pdwReserved
		_ = pdwType
		_ = pvData
		_ = pcbData
		ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHQueueUserWorkItem", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHQueueUserWorkItem p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHReadDataBlockList", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHReadDataBlockList p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegCloseUSKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHRegCloseUSKey p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegCreateUSKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegCreateUSKeyA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegCreateUSKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegCreateUSKeyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegDeleteEmptyUSKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHRegDeleteEmptyUSKeyA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegDeleteEmptyUSKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHRegDeleteEmptyUSKeyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegDeleteUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHRegDeleteUSValueA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegDeleteUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHRegDeleteUSValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegDuplicateHKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHRegDuplicateHKey p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegEnumUSKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegEnumUSKeyA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegEnumUSKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegEnumUSKeyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegEnumUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegEnumUSValueA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegEnumUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegEnumUSValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetBoolUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHRegGetBoolUSValueA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetBoolUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHRegGetBoolUSValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetCLSIDKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegGetCLSIDKeyA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetCLSIDKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegGetCLSIDKeyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetIntW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHRegGetIntW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetPathA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegGetPathA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetPathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegGetPathW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegGetUSValueA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegGetUSValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetValueA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegGetValueA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegGetValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegGetValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegOpenUSKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegOpenUSKeyA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegOpenUSKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegOpenUSKeyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegQueryInfoUSKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegQueryInfoUSKeyA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegQueryInfoUSKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegQueryInfoUSKeyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegQueryUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegQueryUSValueA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegQueryUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegQueryUSValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegSetPathA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegSetPathA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegSetPathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHRegSetPathW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegSetUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegSetUSValueA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegSetUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegSetUSValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegWriteUSValueA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegWriteUSValueA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegWriteUSValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHRegWriteUSValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegisterClassA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHRegisterClassA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegisterClassW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHRegisterClassW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRegisterValidateTemplate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHRegisterValidateTemplate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHReleaseThreadRef", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] SHReleaseThreadRef()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRemoveAllSubMenus", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHRemoveAllSubMenus p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRemoveDataBlock", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHRemoveDataBlock p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRemoveDefaultDialogFont", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHRemoveDefaultDialogFont p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRestrictionLookup", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHRestrictionLookup p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHRunIndirectRegClientCommand", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHRunIndirectRegClientCommand p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSearchMapInt", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHSearchMapInt p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSendMessageBroadcastA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHSendMessageBroadcastA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSendMessageBroadcastW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHSendMessageBroadcastW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetDefaultDialogFont", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHSetDefaultDialogFont p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetIniStringUTF7W", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHSetIniStringUTF7W p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetIniStringW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHSetIniStringW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetParentHwnd", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHSetParentHwnd p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetThreadRef", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHSetThreadRef p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetTimerQueueTimer", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SHSetTimerQueueTimer p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetValueA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pszSubKey := ctx.Arg(1)
		pszValue := ctx.Arg(2)
		dwType := ctx.Arg(3)
		pvData := ctx.Arg(4)
		cbData := ctx.Arg(5)
		var sub, val string
		if pszSubKey != 0 {
			sub = readGuestUTF16(pszSubKey)
		}
		if pszValue != 0 {
			val = readGuestUTF16(pszValue)
		}
		ravelog.Logf("[shlwapi] SHSetValueA hkey=0x%x sub=%q val=%q type=%d\n", hKey, sub, val, dwType)
		_ = pvData
		_ = cbData
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetValueW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pszSubKey := ctx.Arg(1)
		pszValue := ctx.Arg(2)
		dwType := ctx.Arg(3)
		pvData := ctx.Arg(4)
		cbData := ctx.Arg(5)
		var sub, val string
		if pszSubKey != 0 {
			sub = readGuestUTF16(pszSubKey)
		}
		if pszValue != 0 {
			val = readGuestUTF16(pszValue)
		}
		ravelog.Logf("[shlwapi] SHSetValueW hkey=0x%x sub=%q val=%q type=%d\n", hKey, sub, val, dwType)
		_ = pvData
		_ = cbData
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSetWindowBits", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHSetWindowBits p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSimulateDrop", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHSimulateDrop p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHSkipJunction", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHSkipJunction p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHStrDupA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHStrDupA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHStrDupW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHStrDupW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHStringFromGUIDA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHStringFromGUIDA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHStringFromGUIDW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHStringFromGUIDW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHStripMneumonicA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHStripMneumonicA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHStripMneumonicW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHStripMneumonicW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHTruncateString", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHTruncateString p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHUnicodeToAnsi", func(ctx *ntapi.TrapContext) uint32 {
		pwszSrc := ctx.Arg(0)
		pszDst := ctx.Arg(1)
		cwchBuf := int(ctx.Arg(2))
		if pwszSrc != 0 && pszDst != 0 {
			i := 0
			for i < cwchBuf-1 {
				ch, _ := ctx.Mem.Read16(pwszSrc + uint64(i*2))
				if ch == 0 {
					break
				}
				ctx.Mem.Write8(pszDst+uint64(i), uint8(ch))
				i++
			}
			ctx.Mem.Write8(pszDst+uint64(i), 0)
			ctx.SetReturn(uint64(i + 1))
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHUnicodeToAnsiCP", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHUnicodeToAnsiCP p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHUnicodeToUnicode", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHUnicodeToUnicode p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHUnlockShared", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHUnlockShared p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHUnregisterClassesA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHUnregisterClassesA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHUnregisterClassesW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHUnregisterClassesW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHVerbExistsNA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHVerbExistsNA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHWaitForSendMessageThread", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHWaitForSendMessageThread p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHWeakQueryInterface", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SHWeakQueryInterface p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHWeakReleaseInterface", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHWeakReleaseInterface p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHWinHelpOnDemandA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHWinHelpOnDemandA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHWinHelpOnDemandW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SHWinHelpOnDemandW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SHWriteDataBlockList", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHWriteDataBlockList p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SKAllocValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SKAllocValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SKDeleteValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SKDeleteValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SKGetValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SKGetValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SKSetValueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SKSetValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SearchPathWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SearchPathWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SendDlgItemMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] SendDlgItemMessageWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SendMessageTimeoutWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] SendMessageTimeoutWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SendMessageWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SendMessageWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetCurrentDirectoryWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SetCurrentDirectoryWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetDlgItemTextWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SetDlgItemTextWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetFileAttributesWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SetFileAttributesWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetMenuItemInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SetMenuItemInfoWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetPropWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SetPropWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetWindowLongWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SetWindowLongWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetWindowTextWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SetWindowTextWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SetWindowsHookExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SetWindowsHookExWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ShellExecuteExWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] ShellExecuteExWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ShellMessageBoxWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] ShellMessageBoxWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StartDocWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StartDocWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StopWatchA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] StopWatchA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] StopWatchW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StopWatch_MarkFrameStart", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] StopWatch_MarkFrameStart p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StopWatch_MarkJavaStop", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StopWatch_MarkJavaStop p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StopWatch_SetMsgLastLocation", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] StopWatch_SetMsgLastLocation p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StopWatch_TimerHandler", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] StopWatch_TimerHandler p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCSpnA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCSpnA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCSpnIA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCSpnIA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCSpnIW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCSpnIW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCSpnW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCSpnW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCatBuffA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCatBuffA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCatBuffW", func(ctx *ntapi.TrapContext) uint32 {
		pszDest := ctx.Arg(0)
		pszSrc := ctx.Arg(1)
		cchDestBufSize := int(ctx.Arg(2))
		if pszDest == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Find end of dest
		i := 0
		for {
			ch, _ := ctx.Mem.Read16(pszDest + uint64(i*2))
			if ch == 0 {
				break
			}
			i++
		}
		// Append src
		if pszSrc != 0 {
			j := 0
			for i+j < cchDestBufSize-1 {
				ch, _ := ctx.Mem.Read16(pszSrc + uint64(j*2))
				if ch == 0 {
					break
				}
				ctx.Mem.Write16(pszDest+uint64((i+j)*2), ch)
				j++
			}
			ctx.Mem.Write16(pszDest+uint64((i+j)*2), 0)
		}
		ctx.SetReturn(pszDest)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCatW", func(ctx *ntapi.TrapContext) uint32 {
		psz1 := ctx.Arg(0)
		psz2 := ctx.Arg(1)
		if psz1 == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Find end of psz1
		i := uint64(0)
		for {
			ch, _ := ctx.Mem.Read16(psz1 + i*2)
			if ch == 0 {
				break
			}
			i++
		}
		// Copy psz2
		if psz2 != 0 {
			j := uint64(0)
			for {
				ch, _ := ctx.Mem.Read16(psz2 + j*2)
				ctx.Mem.Write16(psz1+(i+j)*2, ch)
				if ch == 0 {
					break
				}
				j++
			}
		}
		ctx.SetReturn(psz1)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrChrA", func(ctx *ntapi.TrapContext) uint32 {
		pszStart := ctx.Arg(0)
		wMatch := ctx.Arg(1)
		if pszStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		i := uint64(0)
		for {
			b, _ := ctx.Mem.Read8(pszStart + i)
			if b == 0 {
				ctx.SetReturn(0)
				return 0
			}
			if uint64(b) == wMatch {
				ctx.SetReturn(pszStart + i)
				return 0
			}
			i++
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrChrIA", func(ctx *ntapi.TrapContext) uint32 {
		pszStart := ctx.Arg(0)
		wMatch := ctx.Arg(1) & 0xFF
		if wMatch >= 'A' && wMatch <= 'Z' {
			wMatch += 32
		}
		if pszStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		i := uint64(0)
		for {
			b, _ := ctx.Mem.Read8(pszStart + i)
			if b == 0 {
				ctx.SetReturn(0)
				return 0
			}
			low := uint64(b)
			if low >= 'A' && low <= 'Z' {
				low += 32
			}
			if low == wMatch {
				ctx.SetReturn(pszStart + i)
				return 0
			}
			i++
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrChrIW", func(ctx *ntapi.TrapContext) uint32 {
		pszStart := ctx.Arg(0)
		wMatch := ctx.Arg(1) & 0xFFFF
		if wMatch >= 'A' && wMatch <= 'Z' {
			wMatch += 32
		}
		if pszStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		i := uint64(0)
		for {
			ch, _ := ctx.Mem.Read16(pszStart + i*2)
			if ch == 0 {
				ctx.SetReturn(0)
				return 0
			}
			low := uint64(ch)
			if low >= 'A' && low <= 'Z' {
				low += 32
			}
			if low == wMatch {
				ctx.SetReturn(pszStart + i*2)
				return 0
			}
			i++
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrChrNW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrChrNW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrChrW", func(ctx *ntapi.TrapContext) uint32 {
		pszStart := ctx.Arg(0)
		wMatch := ctx.Arg(1)
		if pszStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		i := uint64(0)
		for {
			ch, _ := ctx.Mem.Read16(pszStart + i*2)
			if ch == 0 {
				ctx.SetReturn(0)
				return 0
			}
			if uint64(ch) == wMatch {
				ctx.SetReturn(pszStart + i*2)
				return 0
			}
			i++
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpCA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCmpCA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpCW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCmpCW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpICA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCmpICA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpICW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCmpICW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpIW", func(ctx *ntapi.TrapContext) uint32 {
		psz1 := ctx.Arg(0)
		psz2 := ctx.Arg(1)
		s1, s2 := "", ""
		if psz1 != 0 {
			s1 = readGuestUTF16(psz1)
		}
		if psz2 != 0 {
			s2 = readGuestUTF16(psz2)
		}
		result := strings.Compare(strings.ToLower(s1), strings.ToLower(s2))
		ctx.SetReturn(uint64(int64(result)))
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpLogicalW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrCmpLogicalW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNA", func(ctx *ntapi.TrapContext) uint32 {
		psz1 := ctx.Arg(0)
		psz2 := ctx.Arg(1)
		nChar := int(ctx.Arg(2))
		s1, s2 := "", ""
		if psz1 != 0 {
			s1 = readGuestString(psz1)
		}
		if psz2 != 0 {
			s2 = readGuestString(psz2)
		}
		if len(s1) > nChar {
			s1 = s1[:nChar]
		}
		if len(s2) > nChar {
			s2 = s2[:nChar]
		}
		result := strings.Compare(s1, s2)
		ctx.SetReturn(uint64(int64(result)))
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNCA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCmpNCA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNCW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCmpNCW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNIA", func(ctx *ntapi.TrapContext) uint32 {
		psz1 := ctx.Arg(0)
		psz2 := ctx.Arg(1)
		nChar := int(ctx.Arg(2))
		s1, s2 := "", ""
		if psz1 != 0 {
			s1 = readGuestString(psz1)
		}
		if psz2 != 0 {
			s2 = readGuestString(psz2)
		}
		if len(s1) > nChar {
			s1 = s1[:nChar]
		}
		if len(s2) > nChar {
			s2 = s2[:nChar]
		}
		result := strings.Compare(strings.ToLower(s1), strings.ToLower(s2))
		ctx.SetReturn(uint64(int64(result)))
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNICA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCmpNICA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNICW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCmpNICW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNIW", func(ctx *ntapi.TrapContext) uint32 {
		psz1 := ctx.Arg(0)
		psz2 := ctx.Arg(1)
		nChar := int(ctx.Arg(2))
		s1, s2 := "", ""
		if psz1 != 0 {
			s1 = readGuestUTF16(psz1)
		}
		if psz2 != 0 {
			s2 = readGuestUTF16(psz2)
		}
		if len(s1) > nChar {
			s1 = s1[:nChar]
		}
		if len(s2) > nChar {
			s2 = s2[:nChar]
		}
		result := strings.Compare(strings.ToLower(s1), strings.ToLower(s2))
		ctx.SetReturn(uint64(int64(result)))
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpNW", func(ctx *ntapi.TrapContext) uint32 {
		psz1 := ctx.Arg(0)
		psz2 := ctx.Arg(1)
		nChar := int(ctx.Arg(2))
		s1, s2 := "", ""
		if psz1 != 0 {
			s1 = readGuestUTF16(psz1)
		}
		if psz2 != 0 {
			s2 = readGuestUTF16(psz2)
		}
		if len(s1) > nChar {
			s1 = s1[:nChar]
		}
		if len(s2) > nChar {
			s2 = s2[:nChar]
		}
		result := strings.Compare(s1, s2)
		ctx.SetReturn(uint64(int64(result)))
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCmpW", func(ctx *ntapi.TrapContext) uint32 {
		psz1 := ctx.Arg(0)
		psz2 := ctx.Arg(1)
		s1, s2 := "", ""
		if psz1 != 0 {
			s1 = readGuestUTF16(psz1)
		}
		if psz2 != 0 {
			s2 = readGuestUTF16(psz2)
		}
		result := strings.Compare(s1, s2)
		ctx.SetReturn(uint64(int64(result)))
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCpyNW", func(ctx *ntapi.TrapContext) uint32 {
		pszDst := ctx.Arg(0)
		pszSrc := ctx.Arg(1)
		cchMax := int(ctx.Arg(2))
		if pszDst != 0 && pszSrc != 0 && cchMax > 0 {
			for i := 0; i < cchMax-1; i++ {
				ch, _ := ctx.Mem.Read16(pszSrc + uint64(i*2))
				ctx.Mem.Write16(pszDst+uint64(i*2), ch)
				if ch == 0 {
					break
				}
			}
			ctx.Mem.Write16(pszDst+uint64((cchMax-1)*2), 0)
		}
		ctx.SetReturn(pszDst)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCpyNXA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCpyNXA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCpyNXW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrCpyNXW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrCpyW", func(ctx *ntapi.TrapContext) uint32 {
		pszDst := ctx.Arg(0)
		pszSrc := ctx.Arg(1)
		if pszDst != 0 && pszSrc != 0 {
			i := uint64(0)
			for {
				ch, _ := ctx.Mem.Read16(pszSrc + i*2)
				ctx.Mem.Write16(pszDst+i*2, ch)
				if ch == 0 {
					break
				}
				i++
			}
		}
		ctx.SetReturn(pszDst)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrDupA", func(ctx *ntapi.TrapContext) uint32 {
		pszSrc := ctx.Arg(0)
		if pszSrc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		i := uint64(0)
		for {
			b, _ := ctx.Mem.Read8(pszSrc + i)
			if b == 0 {
				break
			}
			i++
		}
		buf := sharedHeapAlloc(i+1, true)
		for j := uint64(0); j <= i; j++ {
			b, _ := ctx.Mem.Read8(pszSrc + j)
			ctx.Mem.Write8(buf+j, b)
		}
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrDupW", func(ctx *ntapi.TrapContext) uint32 {
		pszSrc := ctx.Arg(0)
		if pszSrc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		i := uint64(0)
		for {
			ch, _ := ctx.Mem.Read16(pszSrc + i*2)
			if ch == 0 {
				break
			}
			i++
		}
		buf := sharedHeapAlloc((i+1)*2, true)
		for j := uint64(0); j <= i; j++ {
			ch, _ := ctx.Mem.Read16(pszSrc + j*2)
			ctx.Mem.Write16(buf+j*2, ch)
		}
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFormatByteSize64A", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrFormatByteSize64A p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFormatByteSizeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrFormatByteSizeA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFormatByteSizeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrFormatByteSizeW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFormatKBSizeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrFormatKBSizeA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFormatKBSizeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrFormatKBSizeW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFromTimeIntervalA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] StrFromTimeIntervalA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrFromTimeIntervalW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] StrFromTimeIntervalW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrIsIntlEqualA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] StrIsIntlEqualA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrIsIntlEqualW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] StrIsIntlEqualW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrNCatA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrNCatA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrNCatW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrNCatW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrPBrkA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrPBrkA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrPBrkW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrPBrkW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRChrA", func(ctx *ntapi.TrapContext) uint32 {
		pszStart := ctx.Arg(0)
		pszEnd := ctx.Arg(1)
		wMatch := ctx.Arg(2)
		if pszStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		_ = pszEnd
		last := uint64(0)
		i := uint64(0)
		for {
			b, _ := ctx.Mem.Read8(pszStart + i)
			if b == 0 {
				break
			}
			if uint64(b) == wMatch {
				last = pszStart + i
			}
			i++
		}
		ctx.SetReturn(last)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRChrIA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRChrIA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRChrIW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRChrIW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRChrW", func(ctx *ntapi.TrapContext) uint32 {
		pszStart := ctx.Arg(0)
		pszEnd := ctx.Arg(1)
		wMatch := ctx.Arg(2)
		if pszStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		_ = pszEnd
		last := uint64(0)
		i := uint64(0)
		for {
			ch, _ := ctx.Mem.Read16(pszStart + i*2)
			if ch == 0 {
				break
			}
			if uint64(ch) == wMatch {
				last = pszStart + i*2
			}
			i++
		}
		ctx.SetReturn(last)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRStrIA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRStrIA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRStrIW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRStrIW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRetToBSTR", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRetToBSTR p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRetToBufA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] StrRetToBufA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRetToBufW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] StrRetToBufW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRetToStrA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRetToStrA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrRetToStrW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRetToStrW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrSpnA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrSpnA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrSpnW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrSpnW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrStrA", func(ctx *ntapi.TrapContext) uint32 {
		pszFirst := ctx.Arg(0)
		pszSrch := ctx.Arg(1)
		if pszFirst == 0 || pszSrch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s1 := readGuestString(pszFirst)
		s2 := readGuestString(pszSrch)
		idx := strings.Index(s1, s2)
		if idx >= 0 {
			ctx.SetReturn(pszFirst + uint64(idx))
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrStrIA", func(ctx *ntapi.TrapContext) uint32 {
		pszFirst := ctx.Arg(0)
		pszSrch := ctx.Arg(1)
		if pszFirst == 0 || pszSrch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s1 := readGuestString(pszFirst)
		s2 := readGuestString(pszSrch)
		idx := strings.Index(strings.ToLower(s1), strings.ToLower(s2))
		if idx >= 0 {
			ctx.SetReturn(pszFirst + uint64(idx))
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrStrIW", func(ctx *ntapi.TrapContext) uint32 {
		pszFirst := ctx.Arg(0)
		pszSrch := ctx.Arg(1)
		if pszFirst == 0 || pszSrch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s1 := readGuestUTF16(pszFirst)
		s2 := readGuestUTF16(pszSrch)
		idx := strings.Index(strings.ToLower(s1), strings.ToLower(s2))
		if idx >= 0 {
			ctx.SetReturn(pszFirst + uint64(idx*2))
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrStrNIW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrStrNIW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrStrNW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrStrNW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrStrW", func(ctx *ntapi.TrapContext) uint32 {
		pszFirst := ctx.Arg(0)
		pszSrch := ctx.Arg(1)
		if pszFirst == 0 || pszSrch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s1 := readGuestUTF16(pszFirst)
		s2 := readGuestUTF16(pszSrch)
		idx := strings.Index(s1, s2)
		if idx >= 0 {
			ctx.SetReturn(pszFirst + uint64(idx*2))
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrToInt64ExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrToInt64ExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrToInt64ExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrToInt64ExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrToIntA", func(ctx *ntapi.TrapContext) uint32 {
		pszSrc := ctx.Arg(0)
		var s string
		if pszSrc != 0 {
			s = readGuestString(pszSrc)
		}
		n := 0
		fmt.Sscanf(s, "%d", &n)
		ctx.SetReturn(uint64(int64(n)))
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrToIntExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrToIntExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrToIntExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrToIntExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrToIntW", func(ctx *ntapi.TrapContext) uint32 {
		pszSrc := ctx.Arg(0)
		var s string
		if pszSrc != 0 {
			s = readGuestUTF16(pszSrc)
		}
		n := 0
		fmt.Sscanf(s, "%d", &n)
		ctx.SetReturn(uint64(int64(n)))
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrTrimA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrTrimA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "StrTrimW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] StrTrimW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "SystemParametersInfoWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] SystemParametersInfoWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "TrackPopupMenuExWrap", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] TrackPopupMenuExWrap p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "TrackPopupMenuWrap", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] TrackPopupMenuWrap p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "TranslateAcceleratorWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] TranslateAcceleratorWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UnregisterClassWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] UnregisterClassWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UnregisterExtensionForMIMETypeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UnregisterExtensionForMIMETypeA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UnregisterExtensionForMIMETypeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UnregisterExtensionForMIMETypeW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UnregisterMIMETypeForExtensionA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UnregisterMIMETypeForExtensionA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UnregisterMIMETypeForExtensionW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UnregisterMIMETypeForExtensionW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlApplySchemeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlApplySchemeA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlApplySchemeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlApplySchemeW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCanonicalizeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlCanonicalizeA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCanonicalizeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlCanonicalizeW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCombineA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] UrlCombineA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCombineW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] UrlCombineW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCompareA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] UrlCompareA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCompareW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] UrlCompareW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCrackW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlCrackW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCreateFromPathA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlCreateFromPathA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlCreateFromPathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlCreateFromPathW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlEscapeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlEscapeA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlEscapeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlEscapeW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlFixupW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] UrlFixupW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlGetLocationA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UrlGetLocationA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlGetLocationW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UrlGetLocationW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlGetPartA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] UrlGetPartA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlGetPartW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] UrlGetPartW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlHashA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] UrlHashA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlHashW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] UrlHashW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlIsA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] UrlIsA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlIsNoHistoryA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UrlIsNoHistoryA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlIsNoHistoryW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UrlIsNoHistoryW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlIsOpaqueA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UrlIsOpaqueA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlIsOpaqueW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] UrlIsOpaqueW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlIsW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] UrlIsW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlUnescapeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlUnescapeA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "UrlUnescapeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] UrlUnescapeW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "VerQueryValueWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] VerQueryValueWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "VkKeyScanWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] VkKeyScanWrapW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "WNetGetLastErrorWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] WNetGetLastErrorWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "WNetRestoreConnectionWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] WNetRestoreConnectionWrapW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "WhichPlatform", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shlwapi] WhichPlatform()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "WinHelpWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] WinHelpWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "WritePrivateProfileStringWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] WritePrivateProfileStringWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "WritePrivateProfileStructWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shlwapi] WritePrivateProfileStructWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ZoneCheckUrlExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shlwapi] ZoneCheckUrlExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "ZoneComputePaneSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] ZoneComputePaneSize p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "wnsprintfA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] wnsprintfA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "wvnsprintfA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] wvnsprintfA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "wvnsprintfW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shlwapi] wvnsprintfW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shlwapi, "wvsprintfWrapW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] wvsprintfWrapW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
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
	cs := hctx.Com
	if cs == nil {
		cs = newCOMState(hctx)
		hctx.Com = cs
	}

	shell32, ok := hctx.SynthByName["shell32.dll"]
	if !ok {
		return
	}
	_ = shell32

	d.RegisterAutoStubHandler(shell32, "SHGetFolderPathW", func(ctx *ntapi.TrapContext) uint32 {
		writeWideString(ctx.Mem, ctx.Arg(4), csidlToPath(int32(ctx.Arg(1))), 260)
		ctx.SetReturn(S_OK)
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
		rfid := ctx.Arg(0)
		ppszPath := ctx.Arg(3)
		if ppszPath == 0 || rfid == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		path := knownFolderPath(readGUID(ctx.Mem, rfid))
		buf := cs.allocTaskMem(uint64((len(utf16Encode(path))+1)*2), true)
		if buf == 0 {
			ctx.SetReturn(E_OUTOFMEMORY)
			return 0
		}
		writeWideString(ctx.Mem, buf, path, len(utf16Encode(path))+1)
		ctx.Mem.Write64(ppszPath, buf)
		ctx.SetReturn(S_OK)
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
	d.RegisterAutoStubHandler(shell32, "CommandLineToArgvW", func(ctx *ntapi.TrapContext) uint32 {
		cmdLine := readGuestUTF16(ctx.Arg(0))
		pNumArgs := ctx.Arg(1)
		args := parseCommandLine(cmdLine)
		if len(args) == 0 {
			args = []string{hctx.ImagePath}
		}
		ptrAreaSize := uint64(len(args)+1) * 8
		strAreaSize := uint64(0)
		for _, a := range args {
			strAreaSize += uint64((len(utf16Encode(a)) + 1) * 2)
		}
		page := mem.Mmap(0, ptrAreaSize+strAreaSize, mmu.PermRead|mmu.PermWrite)
		strOff := page + ptrAreaSize
		for i, arg := range args {
			mem.Write64(page+uint64(i)*8, strOff)
			chars := writeWideString(mem, strOff, arg, len(utf16Encode(arg))+1)
			strOff += uint64(chars+1) * 2
		}
		mem.Write64(page+uint64(len(args))*8, 0)
		if pNumArgs != 0 {
			mem.Write32(pNumArgs, uint32(len(args)))
		}
		ctx.SetReturn(page)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFileOperationA", func(ctx *ntapi.TrapContext) uint32 {
		if err := shFileOperationHost(ctx.Mem, ctx.Arg(0), false); err != nil {
			ctx.SetReturn(1)
			return 0
		}
		ctx.SetReturn(0)
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
		op := strings.ToLower(readGuestUTF16(ctx.Arg(1)))
		file := readGuestUTF16(ctx.Arg(2))
		params := readGuestUTF16(ctx.Arg(3))
		dir := readGuestUTF16(ctx.Arg(4))
		if op == "" {
			op = "open"
		}
		target := file
		if !strings.Contains(target, "://") {
			target = winToLinuxPath(target)
		}
		if op != "open" {
			ctx.SetReturn(31)
			return 0
		}
		args := []string{target}
		if params != "" {
			args = append(args, parseCommandLine(params)...)
		}
		cmd := exec.Command("xdg-open", args...)
		if dir != "" {
			cmd.Dir = winToLinuxPath(dir)
		}
		if err := cmd.Start(); err != nil {
			ctx.SetReturn(31)
			return 0
		}
		ctx.SetReturn(33)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellExecuteA", func(ctx *ntapi.TrapContext) uint32 {
		op := strings.ToLower(readGuestString(ctx.Arg(1)))
		file := readGuestString(ctx.Arg(2))
		params := readGuestString(ctx.Arg(3))
		dir := readGuestString(ctx.Arg(4))
		if op == "" {
			op = "open"
		}
		target := file
		if !strings.Contains(target, "://") {
			target = winToLinuxPath(target)
		}
		if op != "open" {
			ctx.SetReturn(31)
			return 0
		}
		args := []string{target}
		if params != "" {
			args = append(args, parseCommandLine(params)...)
		}
		cmd := exec.Command("xdg-open", args...)
		if dir != "" {
			cmd.Dir = winToLinuxPath(dir)
		}
		if err := cmd.Start(); err != nil {
			ctx.SetReturn(31)
			return 0
		}
		ctx.SetReturn(33)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFileOperationW", func(ctx *ntapi.TrapContext) uint32 {
		if err := shFileOperationHost(ctx.Mem, ctx.Arg(0), true); err != nil {
			ctx.SetReturn(1)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateItemFromParsingName", func(ctx *ntapi.TrapContext) uint32 {
		pszPath := ctx.Arg(0)
		riid := ctx.Arg(2)
		ppv := ctx.Arg(3)
		if ppv == 0 || riid == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppv, 0)
		reqIID := readGUID(ctx.Mem, riid)
		if !guidEqual(reqIID, IID_IShellFolder) && !guidEqual(reqIID, IID_IUnknown) {
			ctx.SetReturn(E_NOINTERFACE)
			return 0
		}
		path := readGuestUTF16(pszPath)
		if path == "" {
			path = csidlToPath(0)
		}
		obj, err := cs.createShellFolderObject(path)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppv, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSpecialFolderPathW", func(ctx *ntapi.TrapContext) uint32 {
		path := csidlToPath(int32(ctx.Arg(2)))
		if ctx.Arg(3) != 0 {
			_ = os.MkdirAll(winToLinuxPath(path), 0o755)
		}
		writeWideString(ctx.Mem, ctx.Arg(1), path, 260)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSpecialFolderPathA", func(ctx *ntapi.TrapContext) uint32 {
		path := csidlToPath(int32(ctx.Arg(2)))
		if ctx.Arg(3) != 0 {
			_ = os.MkdirAll(winToLinuxPath(path), 0o755)
		}
		writeAnsiString(ctx.Mem, ctx.Arg(1), path, 260)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetFileInfoW", func(ctx *ntapi.TrapContext) uint32 {
		pathStr := readGuestUTF16(ctx.Arg(0))
		psfi := ctx.Arg(2)
		cbFileInfo := ctx.Arg(3)
		if psfi != 0 && cbFileInfo > 0 {
			for i := uint64(0); i < cbFileInfo && i < 696; i++ {
				ctx.Mem.Write8(psfi+i, 0)
			}
			linuxPath := winToLinuxPath(pathStr)
			info, err := os.Stat(linuxPath)
			displayName := pathStr
			if displayName == "" {
				displayName = csidlToPath(0)
			}
			typeName := "File"
			attrs := uint32(0x80)
			iconIdx := uint32(0)
			if err == nil {
				base := filepath.Base(linuxPath)
				if base != "." && base != "/" && base != "" {
					displayName = base
				}
				if info.IsDir() {
					typeName = "File Folder"
					attrs = 0x10
					iconIdx = 1
				} else if ext := strings.ToLower(filepath.Ext(linuxPath)); ext != "" {
					typeName = strings.ToUpper(strings.TrimPrefix(ext, ".")) + " File"
				}
			}
			ctx.Mem.Write32(psfi+8, iconIdx)
			ctx.Mem.Write32(psfi+12, attrs)
			writeWideString(ctx.Mem, psfi+16, displayName, 260)
			writeWideString(ctx.Mem, psfi+536, typeName, 80)
		}
		ctx.SetReturn(1)
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] Activate_RunDLL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "AddCommasW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] AddCommasW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "AppCompat_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] AppCompat_RunDLLW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ArrangeWindows", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] ArrangeWindows p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CDefFolderMenu_Create", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] CDefFolderMenu_Create p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CDefFolderMenu_Create2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] CDefFolderMenu_Create2 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CDefFolderMenu_MergeMenu", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] CDefFolderMenu_MergeMenu p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CIDLData_CreateFromIDArray", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] CIDLData_CreateFromIDArray p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CallCPLEntry16", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] CallCPLEntry16 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CheckDiskSpace", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] CheckDiskSpace()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CheckEscapesA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] CheckEscapesA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CheckEscapesW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] CheckEscapesW p0=0x%x, p1=0x%x\n", p0, p1)
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] Control_FillCache_RunDLL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Control_FillCache_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] Control_FillCache_RunDLLA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Control_FillCache_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] Control_FillCache_RunDLLW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Control_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] Control_RunDLL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Control_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] Control_RunDLLA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Control_RunDLLAsUserW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] Control_RunDLLAsUserW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Control_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] Control_RunDLLW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "CopyStreamUI", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] CopyStreamUI p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_AutoScroll", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] DAD_AutoScroll p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_DragEnter", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] DAD_DragEnter p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_DragEnterEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] DAD_DragEnterEx p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_DragEnterEx2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] DAD_DragEnterEx2 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_DragLeave", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] DAD_DragLeave()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_DragMove", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] DAD_DragMove p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_SetDragImage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] DAD_SetDragImage p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_SetDragImageFromListView", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] DAD_SetDragImageFromListView p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DAD_ShowDragImage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] DAD_ShowDragImage p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DDECreatePostNotify", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] DDECreatePostNotify p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DllCanUnloadNow", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] DllCanUnloadNow()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DllGetClassObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] DllGetClassObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DllGetVersion", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] DllGetVersion p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DllInstall", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] DllInstall p0=0x%x, p1=0x%x\n", p0, p1)
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] DoEnvironmentSubstA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DoEnvironmentSubstW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] DoEnvironmentSubstW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DragQueryFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] DragQueryFile p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
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
			_ = lpszFile
			_ = cch
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DragQueryFileAorW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] DragQueryFileAorW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DragQueryInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] DragQueryInfo p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DriveType", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] DriveType p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "DuplicateIcon", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] DuplicateIcon p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExitWindowsDialog", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ExitWindowsDialog p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractAssociatedIconA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] ExtractAssociatedIconA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractAssociatedIconExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] ExtractAssociatedIconExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractAssociatedIconExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] ExtractAssociatedIconExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractAssociatedIconW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] ExtractAssociatedIconW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] ExtractIconA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] ExtractIconEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconResInfoA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] ExtractIconResInfoA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconResInfoW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] ExtractIconResInfoW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractIconW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] ExtractIconW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ExtractVersionResource16W", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] ExtractVersionResource16W p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "FileIconInit", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] FileIconInit p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "FindExeDlgProc", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] FindExeDlgProc p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "FindExecutableA", func(ctx *ntapi.TrapContext) uint32 {
		lpFile := ctx.Arg(0)
		lpDirectory := ctx.Arg(1)
		lpResult := ctx.Arg(2)
		var file string
		if lpFile != 0 {
			file = readGuestUTF16(lpFile)
		}
		ravelog.Logf("[shell32] FindExecutableA file=%q\n", file)
		_ = lpDirectory
		_ = lpResult
		ctx.SetReturn(31) // SE_ERR_NOASSOC
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "FindExecutableW", func(ctx *ntapi.TrapContext) uint32 {
		lpFile := ctx.Arg(0)
		lpDirectory := ctx.Arg(1)
		lpResult := ctx.Arg(2)
		var file string
		if lpFile != 0 {
			file = readGuestUTF16(lpFile)
		}
		ravelog.Logf("[shell32] FindExecutableW file=%q\n", file)
		_ = lpDirectory
		_ = lpResult
		ctx.SetReturn(31) // SE_ERR_NOASSOC
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "FirstUserLogon", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] FirstUserLogon p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "FreeIconList", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] FreeIconList p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "GUIDFromStringA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GUIDFromStringA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "GUIDFromStringW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] GUIDFromStringW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "GetFileDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] GetFileDescriptor p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "GetFileNameFromBrowse", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] GetFileNameFromBrowse p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILAppendID", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] ILAppendID p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
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
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ILCreateFromPath p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILCreateFromPathA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ILCreateFromPathA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILCreateFromPathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ILCreateFromPathW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILFindChild", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] ILFindChild p0=0x%x, p1=0x%x\n", p0, p1)
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] ILGetDisplayName p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILGetDisplayNameEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] ILGetDisplayNameEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILGetNext", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ILGetNext p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILGetPseudoNameW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] ILGetPseudoNameW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
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
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ILGlobalClone p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILGlobalFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ILGlobalFree p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILIsEqual", func(ctx *ntapi.TrapContext) uint32 {
		pidl1 := ctx.Arg(0)
		pidl2 := ctx.Arg(1)
		ravelog.Logf("[shell32] ILIsEqual pidl1=0x%x pidl2=0x%x\n", pidl1, pidl2)
		eq := uint64(0)
		if pidl1 == pidl2 {
			eq = 1
		}
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] ILLoadFromStream p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILRemoveLastID", func(ctx *ntapi.TrapContext) uint32 {
		pidl := ctx.Arg(0)
		ravelog.Logf("[shell32] ILRemoveLastID pidl=0x%x\n", pidl)
		if pidl != 0 {
			ctx.Mem.Write16(pidl, 0)
		} // make it empty
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ILSaveToStream", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] ILSaveToStream p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Int64ToString", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] Int64ToString p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "InternalExtractIconListA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] InternalExtractIconListA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "InternalExtractIconListW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] InternalExtractIconListW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "InvalidateDriveType", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] InvalidateDriveType p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "IsLFNDrive", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] IsLFNDrive p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "IsLFNDriveA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] IsLFNDriveA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "IsLFNDriveW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] IsLFNDriveW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "IsNetDrive", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] IsNetDrive p0=0x%x\n", p0)
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] LargeIntegerToString p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "LinkWindow_RegisterClass", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] LinkWindow_RegisterClass()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "LinkWindow_UnregisterClass", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] LinkWindow_UnregisterClass p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "LogoffWindowsDialog", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] LogoffWindowsDialog p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "MakeShellURLFromPathA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] MakeShellURLFromPathA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "MakeShellURLFromPathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] MakeShellURLFromPathW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "NTSHChangeNotifyDeregister", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] NTSHChangeNotifyDeregister p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "NTSHChangeNotifyRegister", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] NTSHChangeNotifyRegister p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "OldReadCabinetState", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] OldReadCabinetState p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "OleStrToStrN", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] OleStrToStrN p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "OpenAs_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] OpenAs_RunDLL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "OpenAs_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] OpenAs_RunDLLA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "OpenAs_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] OpenAs_RunDLLW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "OpenRegStream", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] OpenRegStream p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Options_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] Options_RunDLL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Options_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] Options_RunDLLA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Options_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] Options_RunDLLW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ParseField", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] ParseField p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathAddBackslash", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathAddBackslash p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathAppend", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] PathAppend p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathBuildRoot", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] PathBuildRoot p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathCleanupSpec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] PathCleanupSpec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathCombine", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] PathCombine p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathFileExists", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathFileExists p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathFindExtension", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathFindExtension p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathFindFileName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathFindFileName p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathFindOnPath", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] PathFindOnPath p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathGetArgs", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathGetArgs p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathGetDriveNumber", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathGetDriveNumber p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathGetExtension", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] PathGetExtension p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathGetShortPath", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathGetShortPath p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsDirectory", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsDirectory p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsEqualOrSubFolder", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] PathIsEqualOrSubFolder p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsExe", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsExe p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsRelative", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsRelative p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsRoot", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsRoot p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsSameRoot", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] PathIsSameRoot p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsSlowA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] PathIsSlowA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsSlowW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] PathIsSlowW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsTemporaryA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsTemporaryA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsTemporaryW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsTemporaryW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsUNC", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsUNC p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathIsURL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathIsURL p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathMakeUniqueName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] PathMakeUniqueName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathMatchSpec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] PathMatchSpec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathParseIconLocation", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathParseIconLocation p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathProcessCommand", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] PathProcessCommand p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathQualify", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathQualify p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathQuoteSpaces", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathQuoteSpaces p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathRemoveArgs", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathRemoveArgs p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathRemoveBlanks", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathRemoveBlanks p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathRemoveExtension", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathRemoveExtension p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathRemoveFileSpec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathRemoveFileSpec p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathResolve", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] PathResolve p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathSetDlgItemPath", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] PathSetDlgItemPath p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathStripPath", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathStripPath p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathStripToRoot", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathStripToRoot p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathUnquoteSpaces", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] PathUnquoteSpaces p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PathYetAnotherMakeUniqueName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] PathYetAnotherMakeUniqueName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PickIconDlg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] PickIconDlg p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PifMgr_CloseProperties", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] PifMgr_CloseProperties p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PifMgr_GetProperties", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] PifMgr_GetProperties p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PifMgr_OpenProperties", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] PifMgr_OpenProperties p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PifMgr_SetProperties", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] PifMgr_SetProperties p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Printer_LoadIconsW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] Printer_LoadIconsW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PrintersGetCommand_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] PrintersGetCommand_RunDLL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PrintersGetCommand_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] PrintersGetCommand_RunDLLA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "PrintersGetCommand_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] PrintersGetCommand_RunDLLW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Printers_AddPrinterPropPages", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] Printers_AddPrinterPropPages p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Printers_GetPidl", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] Printers_GetPidl p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Printers_RegisterWindowW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] Printers_RegisterWindowW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Printers_UnregisterWindow", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] Printers_UnregisterWindow p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RLBuildListOfPaths", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] RLBuildListOfPaths()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ReadCabinetState", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] ReadCabinetState p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RealDriveType", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] RealDriveType p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RealDriveTypeFlags", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] RealDriveTypeFlags p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RealShellExecuteA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] RealShellExecuteA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(42)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RealShellExecuteExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] RealShellExecuteExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(42)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RealShellExecuteExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] RealShellExecuteExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(42)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RealShellExecuteW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] RealShellExecuteW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(42)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RegenerateUserEnvironment", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] RegenerateUserEnvironment p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RegisterShellHook", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] RegisterShellHook p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RestartDialog", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] RestartDialog p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RestartDialogEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] RestartDialogEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RunDll_CallEntry16", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] RunDll_CallEntry16 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "RunFileDlg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] RunFileDlg p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHAbortInvokeCommand", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHAbortInvokeCommand()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHAddFromPropSheetExtArray", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHAddFromPropSheetExtArray p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHAddToRecentDocs", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHAddToRecentDocs p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHAlloc", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHAlloc p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHAllocShared", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] SHAllocShared p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHAppBarMessage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHAppBarMessage p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHBindToParent", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHBindToParent p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHBrowseForFolder", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHBrowseForFolder p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHBrowseForFolderA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHBrowseForFolderW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCLSIDFromString", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHCLSIDFromString p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotification_Lock", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHChangeNotification_Lock p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotification_Unlock", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHChangeNotification_Unlock p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotify", func(ctx *ntapi.TrapContext) uint32 {
		wEventId := ctx.Arg(0)
		uFlags := ctx.Arg(1)
		dwItem1 := ctx.Arg(2)
		dwItem2 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHChangeNotify event=0x%x flags=0x%x\n", wEventId, uFlags)
		_ = dwItem1
		_ = dwItem2
		ctx.SetReturn(0) // void
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotifyDeregister", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHChangeNotifyDeregister p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotifyReceive", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHChangeNotifyReceive p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotifyRegister", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] SHChangeNotifyRegister p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotifySuspendResume", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHChangeNotifySuspendResume p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeNotifyUpdateEntryList", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHChangeNotifyUpdateEntryList p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHChangeRegistrationReceive", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHChangeRegistrationReceive p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCloneSpecialIDList", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHCloneSpecialIDList p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCoCreateInstance", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] SHCoCreateInstance p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCopyMonikerToTemp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHCopyMonikerToTemp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateDefClassObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] SHCreateDefClassObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateDesktop", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHCreateDesktop p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateDirectory", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHCreateDirectory p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateFileDataObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] SHCreateFileDataObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateFileExtractIconW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHCreateFileExtractIconW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateLinks", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] SHCreateLinks p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateProcessAsUserW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHCreateProcessAsUserW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreatePropSheetExtArray", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHCreatePropSheetExtArray p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreatePropSheetExtArrayEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHCreatePropSheetExtArrayEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreatePropertyBag", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHCreatePropertyBag p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateQueryCancelAutoPlayMoniker", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHCreateQueryCancelAutoPlayMoniker p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateSessionKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHCreateSessionKey p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateShellFolderView", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHCreateShellFolderView p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateShellFolderViewEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHCreateShellFolderViewEx p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateShellItem", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHCreateShellItem p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHCreateStdEnumFmtEtc", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHCreateStdEnumFmtEtc p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHDefExtractIconA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] SHDefExtractIconA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHDefExtractIconW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] SHDefExtractIconW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHDesktopMessageLoop", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHDesktopMessageLoop p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHDestroyPropSheetExtArray", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHDestroyPropSheetExtArray p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHDllGetClassObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHDllGetClassObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHDoDragDrop", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] SHDoDragDrop p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHEmptyRecycleBinA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHEmptyRecycleBinA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHEmptyRecycleBinW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHEmptyRecycleBinW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHEnumerateUnreadMailAccountsW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHEnumerateUnreadMailAccountsW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHExtractIconsW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] SHExtractIconsW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFileOperation", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHFileOperation p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFindComputer", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHFindComputer p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFindFiles", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHFindFiles p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFind_InitMenuPopup", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHFind_InitMenuPopup p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHFormatDrive p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHFree p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFreeNameMappings", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHFreeNameMappings p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFreeShared", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHFreeShared p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHFreeUnusedLibraries", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHFreeUnusedLibraries()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetAppCompatFlags", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHGetAppCompatFlags p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetAttributesFromDataObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetAttributesFromDataObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetComputerDisplayNameW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetComputerDisplayNameW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetDataFromIDListA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] SHGetDataFromIDListA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetDataFromIDListW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] SHGetDataFromIDListW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetDesktopFolder", func(ctx *ntapi.TrapContext) uint32 {
		ppshf := ctx.Arg(0)
		if ppshf == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppshf, 0)
		obj, err := cs.createShellFolderObject(csidlToPath(0))
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppshf, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetDiskFreeSpaceA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetDiskFreeSpaceA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetDiskFreeSpaceExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetDiskFreeSpaceExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetDiskFreeSpaceExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetDiskFreeSpaceExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetFileInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] SHGetFileInfo p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetFolderLocation", func(ctx *ntapi.TrapContext) uint32 {
		hwndOwner := ctx.Arg(0)
		nFolder := ctx.Arg(1)
		hToken := ctx.Arg(2)
		dwReserved := ctx.Arg(3)
		ppidl := ctx.Arg(4)
		_ = hwndOwner
		_ = hToken
		_ = dwReserved
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
		writeAnsiString(ctx.Mem, ctx.Arg(4), csidlToPath(int32(ctx.Arg(1))), 260)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetFolderPathAndSubDirA", func(ctx *ntapi.TrapContext) uint32 {
		base := csidlToPath(int32(ctx.Arg(1)))
		subDir := readGuestString(ctx.Arg(4))
		full := base
		if subDir != "" {
			full = canonicalizeWinPath(base + `\` + subDir)
		}
		writeAnsiString(ctx.Mem, ctx.Arg(5), full, 260)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetFolderPathAndSubDirW", func(ctx *ntapi.TrapContext) uint32 {
		base := csidlToPath(int32(ctx.Arg(1)))
		subDir := readGuestUTF16(ctx.Arg(4))
		full := base
		if subDir != "" {
			full = canonicalizeWinPath(base + `\` + subDir)
		}
		writeWideString(ctx.Mem, ctx.Arg(5), full, 260)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetIconOverlayIndexA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHGetIconOverlayIndexA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetIconOverlayIndexW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHGetIconOverlayIndexW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetImageList", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHGetImageList p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetInstanceExplorer", func(ctx *ntapi.TrapContext) uint32 {
		ppunk := ctx.Arg(0)
		ravelog.Logf("[shell32] SHGetInstanceExplorer out=0x%x\n", ppunk)
		if ppunk != 0 {
			ctx.Mem.Write64(ppunk, 0)
		}
		ctx.SetReturn(0x80004005) // E_FAIL
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetMalloc", func(ctx *ntapi.TrapContext) uint32 {
		ppMalloc := ctx.Arg(0)
		ravelog.Logf("[shell32] SHGetMalloc out=0x%x\n", ppMalloc)
		if ppMalloc != 0 {
			ctx.Mem.Write64(ppMalloc, 0)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetNetResource", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetNetResource p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetNewLinkInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] SHGetNewLinkInfo p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetNewLinkInfoA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] SHGetNewLinkInfoA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetNewLinkInfoW", func(ctx *ntapi.TrapContext) uint32 {
		pszLinkTo := ctx.Arg(0)
		pszDir := ctx.Arg(1)
		pszName := ctx.Arg(2)
		pfMustCopy := ctx.Arg(3)
		uFlags := ctx.Arg(4)
		var linkTo string
		if pszLinkTo != 0 {
			linkTo = readGuestUTF16(pszLinkTo)
		}
		ravelog.Logf("[shell32] SHGetNewLinkInfoW linkTo=%q\n", linkTo)
		_ = pszDir
		_ = pszName
		_ = uFlags
		if pfMustCopy != 0 {
			ctx.Mem.Write32(pfMustCopy, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetPathFromIDList", func(ctx *ntapi.TrapContext) uint32 {
		path := pidlPathFromMemory(ctx.Mem, ctx.Arg(0))
		if path == "" {
			ctx.SetReturn(0)
			return 0
		}
		writeAnsiString(ctx.Mem, ctx.Arg(1), path, 260)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetPathFromIDListA", func(ctx *ntapi.TrapContext) uint32 {
		path := pidlPathFromMemory(ctx.Mem, ctx.Arg(0))
		if path == "" {
			ctx.SetReturn(0)
			return 0
		}
		writeAnsiString(ctx.Mem, ctx.Arg(1), path, 260)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetPathFromIDListW", func(ctx *ntapi.TrapContext) uint32 {
		path := pidlPathFromMemory(ctx.Mem, ctx.Arg(0))
		if path == "" {
			ctx.SetReturn(0)
			return 0
		}
		writeWideString(ctx.Mem, ctx.Arg(1), path, 260)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetProcessDword", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHGetProcessDword p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetRealIDL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHGetRealIDL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSetFolderCustomSettingsA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHGetSetFolderCustomSettingsA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSetFolderCustomSettingsW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHGetSetFolderCustomSettingsW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
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
		if lpsfs != 0 {
			ctx.Mem.Write32(lpsfs, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetShellFolderViewCB", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHGetShellFolderViewCB p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSpecialFolderLocation", func(ctx *ntapi.TrapContext) uint32 {
		ppidl := ctx.Arg(2)
		if ppidl == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		pidl := allocPIDLFromPath(ctx.Mem, sharedHeapAlloc, csidlToPath(int32(ctx.Arg(1))))
		if pidl == 0 {
			ctx.SetReturn(E_OUTOFMEMORY)
			return 0
		}
		ctx.Mem.Write64(ppidl, pidl)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetSpecialFolderPath", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHGetSpecialFolderPath p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetUnreadMailCountW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] SHGetUnreadMailCountW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetUserDisplayName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHGetUserDisplayName p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetUserPicturePathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHGetUserPicturePathW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGetUserSessionId", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHGetUserSessionId p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHGlobalDefect", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHGlobalDefect p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHHandleDiskFull", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHHandleDiskFull p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHHandleUpdateImage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHHandleUpdateImage p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHHelpShortcuts_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHHelpShortcuts_RunDLL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHHelpShortcuts_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHHelpShortcuts_RunDLLA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHHelpShortcuts_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHHelpShortcuts_RunDLLW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHILCreateFromPath", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHILCreateFromPath p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHInvokePrinterCommandA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] SHInvokePrinterCommandA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHInvokePrinterCommandW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] SHInvokePrinterCommandW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHInvokePrivilegedFunctionW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHInvokePrivilegedFunctionW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHIsBadInterfacePtr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHIsBadInterfacePtr p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHIsFileAvailableOffline", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHIsFileAvailableOffline p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHIsTempDisplayMode", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHIsTempDisplayMode()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLimitInputCombo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHLimitInputCombo p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLimitInputEdit", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHLimitInputEdit p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLoadInProc", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHLoadInProc p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLoadNonloadedIconOverlayIdentifiers", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHLoadNonloadedIconOverlayIdentifiers()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLoadOLE", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHLoadOLE p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLockShared", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shlwapi] SHLockShared p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLogILFromFSIL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHLogILFromFSIL p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLookupIconIndexA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHLookupIconIndexA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHLookupIconIndexW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHLookupIconIndexW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHMapIDListToImageListIndexAsync", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] SHMapIDListToImageListIndexAsync p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHMapPIDLToSystemImageListIndex", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHMapPIDLToSystemImageListIndex p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHMultiFileProperties", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHMultiFileProperties p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHNetConnectionDialog", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHNetConnectionDialog p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHObjectProperties", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHObjectProperties p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHOpenEffectiveToken", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHOpenEffectiveToken p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHOpenFolderAndSelectItems", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHOpenFolderAndSelectItems p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHOpenPropSheetA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] SHOpenPropSheetA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHOpenPropSheetW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] SHOpenPropSheetW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHOutOfMemoryMessageBox", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHOutOfMemoryMessageBox p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHParseDarwinIDFromCacheW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHParseDarwinIDFromCacheW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHParseDisplayName", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestUTF16(ctx.Arg(0))
		if !isAbsoluteWinPath(name) {
			name = canonicalizeWinPath(csidlToPath(0) + `\` + name)
		}
		if ctx.Arg(2) != 0 {
			pidl := allocPIDLFromPath(ctx.Mem, sharedHeapAlloc, name)
			if pidl == 0 {
				ctx.SetReturn(E_OUTOFMEMORY)
				return 0
			}
			ctx.Mem.Write64(ctx.Arg(2), pidl)
		}
		if ctx.Arg(4) != 0 {
			attrs := uint32(0)
			if info, err := os.Stat(winToLinuxPath(name)); err == nil && info.IsDir() {
				attrs = 0x10
			}
			ctx.Mem.Write32(ctx.Arg(4), attrs)
		}
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHPathPrepareForWriteA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHPathPrepareForWriteA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHPathPrepareForWriteW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHPathPrepareForWriteW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHPropStgCreate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] SHPropStgCreate p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHPropStgReadMultiple", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] SHPropStgReadMultiple p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHPropStgWriteMultiple", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] SHPropStgWriteMultiple p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHQueryRecycleBinA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHQueryRecycleBinA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHQueryRecycleBinW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHQueryRecycleBinW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHReValidateDarwinCache", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHReValidateDarwinCache()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHRegisterDragDrop", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHRegisterDragDrop p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHReplaceFromPropSheetExtArray", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHReplaceFromPropSheetExtArray p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHRestricted", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHRestricted p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHRevokeDragDrop", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHRevokeDragDrop p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHRunControlPanel", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHRunControlPanel p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSetFolderPathA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHSetFolderPathA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSetFolderPathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHSetFolderPathW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSetInstanceExplorer", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHSetInstanceExplorer p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSetLocalizedName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHSetLocalizedName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSetShellWindowEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHSetShellWindowEx p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSetUserPicturePathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHSetUserPicturePathW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSettingsChanged", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHSettingsChanged p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHShellFolderView_Message", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHShellFolderView_Message p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHShouldShowWizards", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHShouldShowWizards p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSimpleIDListFromPath", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SHSimpleIDListFromPath p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHSimulateDropOnClsid", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHSimulateDropOnClsid p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHStartNetConnectionDialog", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHStartNetConnectionDialog p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHStartNetConnectionDialogA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHStartNetConnectionDialogA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHStartNetConnectionDialogW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHStartNetConnectionDialogW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHTestTokenMembership", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHTestTokenMembership p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHTestTokenPrivilegeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHTestTokenPrivilegeW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHUnlockShared", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shlwapi] SHUnlockShared p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHUpdateImageA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHUpdateImageA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHUpdateImageW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHUpdateImageW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHUpdateRecycleBinIcon", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SHUpdateRecycleBinIcon()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHValidateUNC", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHValidateUNC p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHWaitForFileToOpen", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SHWaitForFileToOpen p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHWaitOp_Operate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SHWaitOp_Operate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SHWinHelp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] SHWinHelp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SetAppStartingCursor", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SetAppStartingCursor p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheChangeDirA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheChangeDirA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheChangeDirExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheChangeDirExA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheChangeDirExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheChangeDirExW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheChangeDirW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheChangeDirW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheConvertPathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SheConvertPathW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheFullPathA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SheFullPathA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheFullPathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SheFullPathW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheGetCurDrive", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] SheGetCurDrive()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheGetDirA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SheGetDirA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheGetDirExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] SheGetDirExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheGetDirW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SheGetDirW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheGetPathOffsetW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheGetPathOffsetW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheRemoveQuotesA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheRemoveQuotesA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheRemoveQuotesW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheRemoveQuotesW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheSetCurDrive", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SheSetCurDrive p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheShortenPathA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SheShortenPathA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SheShortenPathW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] SheShortenPathW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellAboutA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		szApp := ctx.Arg(1)
		szOtherStuff := ctx.Arg(2)
		hIcon := ctx.Arg(3)
		var app string
		if szApp != 0 {
			app = readGuestUTF16(szApp)
		}
		ravelog.Logf("[shell32] ShellAboutA app=%q\n", app)
		_ = hwnd
		_ = szOtherStuff
		_ = hIcon
		ctx.SetReturn(1) // TRUE - dialog shown
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellDDEInit", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ShellDDEInit p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellExec_RunDLL", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] ShellExec_RunDLL p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellExec_RunDLLA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] ShellExec_RunDLLA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellExec_RunDLLW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] ShellExec_RunDLLW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellExecuteEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] ShellExecuteEx p0=0x%x\n", p0)
		ctx.SetReturn(42)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellHookProc", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] ShellHookProc p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellMessageBoxA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[shell32] ShellMessageBoxA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "ShellMessageBoxW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[shell32] ShellMessageBoxW()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Shell_GetCachedImageIndex", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] Shell_GetCachedImageIndex p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Shell_GetImageLists", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] Shell_GetImageLists p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Shell_MergeMenus", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] Shell_MergeMenus p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Shell_NotifyIcon", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] Shell_NotifyIcon p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] ShortSizeFormatW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "SignalFileOpen", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] SignalFileOpen p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrChrA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] StrChrA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrChrIA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] StrChrIA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrChrIW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] StrChrIW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrChrW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] StrChrW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrCmpNA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrCmpNA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrCmpNIA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrCmpNIA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrCmpNIW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrCmpNIW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrCmpNW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrCmpNW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrCpyNW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrCpyNW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrNCmpA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrNCmpA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrNCmpIA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrNCmpIA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrNCmpIW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrNCmpIW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrNCmpW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrNCmpW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrNCpyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrNCpyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRChrA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrRChrA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRChrIA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRChrIA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRChrIW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRChrIW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRChrW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrRChrW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRStrA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrRStrA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRStrIA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRStrIA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRStrIW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shlwapi] StrRStrIW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRStrW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[shell32] StrRStrW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrRetToStrN", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] StrRetToStrN p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrStrA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] StrStrA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrStrIA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] StrStrIA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrStrIW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] StrStrIW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrStrW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] StrStrW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrToOleStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] StrToOleStr p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "StrToOleStrN", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[shell32] StrToOleStrN p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "WOWShellExecute", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[shell32] WOWShellExecute p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Win32CreateDirectory", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[shell32] Win32CreateDirectory p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Win32DeleteFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] Win32DeleteFile p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "Win32RemoveDirectory", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] Win32RemoveDirectory p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(shell32, "WriteCabinetState", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[shell32] WriteCabinetState p0=0x%x\n", p0)
		ctx.SetReturn(1)
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
