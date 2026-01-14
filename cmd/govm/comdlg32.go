package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	ofnFileMustExist = 0x00001000
	sFalse           = 0x00000001
	eNotImpl         = 0x80004001
)

func registerComdlg32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16
	stdinReader := hctx.StdinReader

	comdlg32, ok := hctx.SynthByName["comdlg32.dll"]
	if !ok {
		return
	}

	readANSIWithLimit := func(addr uint64, maxBytes uint32) string {
		if addr == 0 || maxBytes == 0 {
			return ""
		}
		buf := make([]byte, 0, maxBytes)
		for i := uint32(0); i < maxBytes; i++ {
			b, err := mem.Read8(addr + uint64(i))
			if err != nil || b == 0 {
				break
			}
			buf = append(buf, b)
		}
		return string(buf)
	}

	writeANSIWithLimit := func(addr uint64, maxBytes uint32, s string) bool {
		if addr == 0 || maxBytes == 0 {
			return false
		}
		b := []byte(s)
		if uint32(len(b))+1 > maxBytes {
			if maxBytes == 0 {
				return false
			}
			b = b[:maxBytes-1]
		}
		for i, c := range b {
			mem.Write8(addr+uint64(i), c)
		}
		mem.Write8(addr+uint64(len(b)), 0)
		return true
	}

	writeUTF16WithLimit := func(addr uint64, maxChars uint32, s string) bool {
		if addr == 0 || maxChars == 0 {
			return false
		}
		ws := utf16Encode(s)
		if uint32(len(ws))+1 > maxChars {
			if maxChars == 0 {
				return false
			}
			ws = ws[:maxChars-1]
		}
		for i, w := range ws {
			mem.Write16(addr+uint64(i)*2, w)
		}
		mem.Write16(addr+uint64(len(ws))*2, 0)
		return true
	}

	readFilterW := func(addr uint64) []string {
		if addr == 0 {
			return nil
		}
		items := make([]string, 0, 8)
		cur := addr
		for len(items) < 32 {
			var chars []uint16
			for {
				w, err := mem.Read16(cur)
				if err != nil {
					return items
				}
				cur += 2
				if w == 0 {
					break
				}
				chars = append(chars, w)
			}
			if len(chars) == 0 {
				break
			}
			items = append(items, string(utf16Decode(chars)))
		}
		return items
	}

	readFilterA := func(addr uint64) []string {
		if addr == 0 {
			return nil
		}
		items := make([]string, 0, 8)
		cur := addr
		for len(items) < 32 {
			var bytes []byte
			for {
				b, err := mem.Read8(cur)
				if err != nil {
					return items
				}
				cur++
				if b == 0 {
					break
				}
				bytes = append(bytes, b)
			}
			if len(bytes) == 0 {
				break
			}
			items = append(items, string(bytes))
		}
		return items
	}

	promptPath := func(dialogTitle, kind, defaultPath, initialDir string, mustExist bool) (string, bool) {
		if stdinReader == nil {
			return "", false
		}
		reader := stdinReader
		if reader == nil {
			reader = bufio.NewReader(os.Stdin)
		}
		fmt.Fprintf(os.Stderr, "[comdlg32] %s (%s)\n", dialogTitle, kind)
		if initialDir != "" {
			fmt.Fprintf(os.Stderr, "[comdlg32] initial dir: %s\n", initialDir)
		}
		if defaultPath != "" {
			fmt.Fprintf(os.Stderr, "[comdlg32] default path: %s\n", defaultPath)
		}
		if mustExist {
			fmt.Fprintln(os.Stderr, "[comdlg32] file must exist")
		}
		fmt.Fprint(os.Stderr, "[comdlg32] Enter path (blank to cancel): ")
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			return "", false
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return "", false
		}
		return line, true
	}

	normalizePath := func(pathValue, initialDir, defExt string, forSave bool) string {
		pathValue = strings.TrimSpace(pathValue)
		if pathValue == "" {
			return ""
		}
		if !filepath.IsAbs(pathValue) {
			base := initialDir
			if base == "" {
				base = "."
			}
			pathValue = filepath.Join(base, pathValue)
		}
		pathValue = filepath.Clean(pathValue)
		if forSave && defExt != "" && filepath.Ext(pathValue) == "" {
			ext := defExt
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			pathValue += ext
		}
		return pathValue
	}

	writeOpenFileMetadata := func(ofnPtr uint64, result string, fileTitlePtr uint64, maxFileTitle uint32, ansi bool) {
		base := filepath.Base(result)
		fileOffset := uint16(0)
		if idx := strings.LastIndexAny(result, `/\`); idx >= 0 {
			fileOffset = uint16(idx + 1)
		}
		fileExt := uint16(0)
		if dot := strings.LastIndex(base, "."); dot >= 0 {
			fileExt = uint16(int(fileOffset) + dot + 1)
		}
		mem.Write16(ofnPtr+100, fileOffset)
		mem.Write16(ofnPtr+102, fileExt)
		if fileTitlePtr != 0 && maxFileTitle > 0 {
			if ansi {
				writeANSIWithLimit(fileTitlePtr, maxFileTitle, base)
			} else {
				writeUTF16WithLimit(fileTitlePtr, maxFileTitle, base)
			}
		}
	}

	handleFileDialogW := func(ctx *ntapi.TrapContext, saving bool) {
		pOFN := ctx.Arg(0)
		if pOFN == 0 {
			ctx.SetReturn(0)
			return
		}

		lpstrFilter, _ := mem.Read64(pOFN + 24)
		nFilterIndex, _ := mem.Read32(pOFN + 44)
		lpstrFile, _ := mem.Read64(pOFN + 48)
		nMaxFile, _ := mem.Read32(pOFN + 56)
		lpstrFileTitle, _ := mem.Read64(pOFN + 64)
		nMaxFileTitle, _ := mem.Read32(pOFN + 72)
		lpstrInitialDir, _ := mem.Read64(pOFN + 80)
		lpstrTitle, _ := mem.Read64(pOFN + 88)
		flags, _ := mem.Read32(pOFN + 96)
		lpstrDefExt, _ := mem.Read64(pOFN + 104)

		initialDir := ""
		if lpstrInitialDir != 0 {
			initialDir = readGuestUTF16(lpstrInitialDir)
		}
		title := "Open File"
		if saving {
			title = "Save File"
		}
		if lpstrTitle != 0 {
			if s := readGuestUTF16(lpstrTitle); s != "" {
				title = s
			}
		}
		defExt := ""
		if lpstrDefExt != 0 {
			defExt = readGuestUTF16(lpstrDefExt)
		}
		currentPath := readGuestUTF16(lpstrFile)
		filterPairs := readFilterW(lpstrFilter)
		if len(filterPairs) > 0 {
			ravelog.Logf("[comdlg32] %sW filters=%v index=%d\n", title, filterPairs, nFilterIndex)
		}

		result := normalizePath(currentPath, initialDir, defExt, saving)
		if result == "" {
			prompted, ok := promptPath(title, map[bool]string{true: "save", false: "open"}[saving], currentPath, initialDir, !saving && (flags&ofnFileMustExist) != 0)
			if !ok {
				ctx.SetReturn(0)
				return
			}
			result = normalizePath(prompted, initialDir, defExt, saving)
		}
		if result == "" {
			ctx.SetReturn(0)
			return
		}
		if !saving && (flags&ofnFileMustExist) != 0 {
			if _, err := os.Stat(result); err != nil {
				ravelog.Logf("[comdlg32] %sW rejecting missing file %q: %v\n", title, result, err)
				ctx.SetReturn(0)
				return
			}
		}

		if !writeUTF16WithLimit(lpstrFile, nMaxFile, result) {
			ctx.SetReturn(0)
			return
		}
		writeOpenFileMetadata(pOFN, result, lpstrFileTitle, nMaxFileTitle, false)
		ravelog.Logf("[comdlg32] %sW selected %q\n", title, result)
		ctx.SetReturn(1)
	}

	handleFileDialogA := func(ctx *ntapi.TrapContext, saving bool) {
		pOFN := ctx.Arg(0)
		if pOFN == 0 {
			ctx.SetReturn(0)
			return
		}

		lpstrFilter, _ := mem.Read64(pOFN + 24)
		nFilterIndex, _ := mem.Read32(pOFN + 44)
		lpstrFile, _ := mem.Read64(pOFN + 48)
		nMaxFile, _ := mem.Read32(pOFN + 56)
		lpstrFileTitle, _ := mem.Read64(pOFN + 64)
		nMaxFileTitle, _ := mem.Read32(pOFN + 72)
		lpstrInitialDir, _ := mem.Read64(pOFN + 80)
		lpstrTitle, _ := mem.Read64(pOFN + 88)
		flags, _ := mem.Read32(pOFN + 96)
		lpstrDefExt, _ := mem.Read64(pOFN + 104)

		initialDir := ""
		if lpstrInitialDir != 0 {
			initialDir = readGuestString(lpstrInitialDir)
		}
		title := "Open File"
		if saving {
			title = "Save File"
		}
		if lpstrTitle != 0 {
			if s := readGuestString(lpstrTitle); s != "" {
				title = s
			}
		}
		defExt := ""
		if lpstrDefExt != 0 {
			defExt = readGuestString(lpstrDefExt)
		}
		currentPath := readANSIWithLimit(lpstrFile, nMaxFile)
		filterPairs := readFilterA(lpstrFilter)
		if len(filterPairs) > 0 {
			ravelog.Logf("[comdlg32] %sA filters=%v index=%d\n", title, filterPairs, nFilterIndex)
		}

		result := normalizePath(currentPath, initialDir, defExt, saving)
		if result == "" {
			prompted, ok := promptPath(title, map[bool]string{true: "save", false: "open"}[saving], currentPath, initialDir, !saving && (flags&ofnFileMustExist) != 0)
			if !ok {
				ctx.SetReturn(0)
				return
			}
			result = normalizePath(prompted, initialDir, defExt, saving)
		}
		if result == "" {
			ctx.SetReturn(0)
			return
		}
		if !saving && (flags&ofnFileMustExist) != 0 {
			if _, err := os.Stat(result); err != nil {
				ravelog.Logf("[comdlg32] %sA rejecting missing file %q: %v\n", title, result, err)
				ctx.SetReturn(0)
				return
			}
		}

		if !writeANSIWithLimit(lpstrFile, nMaxFile, result) {
			ctx.SetReturn(0)
			return
		}
		writeOpenFileMetadata(pOFN, result, lpstrFileTitle, nMaxFileTitle, true)
		ravelog.Logf("[comdlg32] %sA selected %q\n", title, result)
		ctx.SetReturn(1)
	}

	d.RegisterAutoStubHandler(comdlg32, "GetFileTitleW", func(ctx *ntapi.TrapContext) uint32 {
		src := readGuestUTF16(ctx.Arg(0))
		dst := ctx.Arg(1)
		cch := uint32(ctx.Arg(2))
		if dst != 0 && cch > 0 {
			writeUTF16WithLimit(dst, cch, filepath.Base(src))
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "GetFileTitleA", func(ctx *ntapi.TrapContext) uint32 {
		src := readGuestString(ctx.Arg(0))
		dst := ctx.Arg(1)
		cch := uint32(ctx.Arg(2))
		if dst != 0 && cch > 0 {
			writeANSIWithLimit(dst, cch, filepath.Base(src))
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "GetOpenFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		handleFileDialogW(ctx, false)
		return 0
	})
	d.RegisterAutoStubHandler(comdlg32, "GetSaveFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		handleFileDialogW(ctx, true)
		return 0
	})
	d.RegisterAutoStubHandler(comdlg32, "GetOpenFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		handleFileDialogA(ctx, false)
		return 0
	})
	d.RegisterAutoStubHandler(comdlg32, "GetSaveFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		handleFileDialogA(ctx, true)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "ChooseColorW", func(ctx *ntapi.TrapContext) uint32 {
		lpcc := ctx.Arg(0)
		if lpcc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rgb, _ := mem.Read32(lpcc + 24)
		lpCustColors, _ := mem.Read64(lpcc + 32)
		flags, _ := mem.Read32(lpcc + 40)
		ravelog.Logf("[comdlg32] ChooseColorW default=0x%08x cust=0x%x flags=0x%x\n", rgb, lpCustColors, flags)
		mem.Write32(lpcc+24, rgb)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "ChooseColorA", func(ctx *ntapi.TrapContext) uint32 {
		lpcc := ctx.Arg(0)
		if lpcc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rgb, _ := mem.Read32(lpcc + 24)
		lpCustColors, _ := mem.Read64(lpcc + 32)
		flags, _ := mem.Read32(lpcc + 40)
		ravelog.Logf("[comdlg32] ChooseColorA default=0x%08x cust=0x%x flags=0x%x\n", rgb, lpCustColors, flags)
		mem.Write32(lpcc+24, rgb)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "ChooseFontW", func(ctx *ntapi.TrapContext) uint32 {
		lpcf := ctx.Arg(0)
		if lpcf == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lpLogFont, _ := mem.Read64(lpcf + 24)
		pointSize, _ := mem.Read32(lpcf + 32)
		flags, _ := mem.Read32(lpcf + 36)
		rgbColors, _ := mem.Read32(lpcf + 40)
		ravelog.Logf("[comdlg32] ChooseFontW logfont=0x%x pointSize=%d flags=0x%x color=0x%08x\n", lpLogFont, pointSize, flags, rgbColors)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "ChooseFontA", func(ctx *ntapi.TrapContext) uint32 {
		lpcf := ctx.Arg(0)
		if lpcf == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lpLogFont, _ := mem.Read64(lpcf + 24)
		pointSize, _ := mem.Read32(lpcf + 32)
		flags, _ := mem.Read32(lpcf + 36)
		rgbColors, _ := mem.Read32(lpcf + 40)
		ravelog.Logf("[comdlg32] ChooseFontA logfont=0x%x pointSize=%d flags=0x%x color=0x%08x\n", lpLogFont, pointSize, flags, rgbColors)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "PrintDlgW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[comdlg32] PrintDlgW cancelled: no printer backend\n")
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "PrintDlgA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[comdlg32] PrintDlgA cancelled: no printer backend\n")
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "PrintDlgExW", func(ctx *ntapi.TrapContext) uint32 {
		pPD := ctx.Arg(0)
		if pPD != 0 {
			mem.Write32(pPD+72, 0) // dwResultAction = PD_RESULT_CANCEL for current struct assumption
		}
		ctx.SetReturn(eNotImpl)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "PrintDlgExA", func(ctx *ntapi.TrapContext) uint32 {
		pPD := ctx.Arg(0)
		if pPD != 0 {
			mem.Write32(pPD+72, 0)
		}
		ctx.SetReturn(eNotImpl)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "PageSetupDlgW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "PageSetupDlgA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "FindTextW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[comdlg32] FindTextW unsupported modeless dialog\n")
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "FindTextA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[comdlg32] FindTextA unsupported modeless dialog\n")
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "ReplaceTextW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[comdlg32] ReplaceTextW unsupported modeless dialog\n")
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "ReplaceTextA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[comdlg32] ReplaceTextA unsupported modeless dialog\n")
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "CommDlgExtendedError", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	_ = sFalse
}
