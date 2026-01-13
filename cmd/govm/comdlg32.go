package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerComdlg32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16

	comdlg32, ok := hctx.SynthByName["comdlg32.dll"]
	if !ok {
		return
	}
	_ = comdlg32

	d.RegisterAutoStubHandler(comdlg32, "GetFileTitleW", func(ctx *ntapi.TrapContext) uint32 {
		lpBuffer := ctx.Arg(1)
		cbBuf := ctx.Arg(2)
		if lpBuffer != 0 && cbBuf > 0 {
			mem.Write16(lpBuffer, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	// PrintDlgW: print dialog - return FALSE (user cancelled / not supported)
	d.RegisterAutoStubHandler(comdlg32, "PrintDlgW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - user cancelled
		return 0
	})
	// ChooseColorW: color picker dialog - return FALSE (user cancelled)
	d.RegisterAutoStubHandler(comdlg32, "ChooseColorW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - user cancelled
		return 0
	})

	// GetOpenFileNameW / GetSaveFileNameW - use alacritty+fzf for file picking
	// OPENFILENAMEW struct offsets (Win64):
	//   +0  lStructSize(4)  +8  hwndOwner(8)  +16 hInstance(8)
	//   +24 lpstrFilter(8)  +32 lpstrCustomFilter(8)  +40 nMaxCustFilter(4)  +44 nFilterIndex(4)
	//   +48 lpstrFile(8)    +56 nMaxFile(4)   +64 lpstrFileTitle(8)  +72 nMaxFileTitle(4)
	//   +80 lpstrInitialDir(8)  +88 lpstrTitle(8)  +96 Flags(4)
	//   +100 nFileOffset(2)  +102 nFileExtension(2)  +104 lpstrDefExt(8)
	showFileDialog := func(ctx *ntapi.TrapContext, saving bool) {
		pOFN := ctx.Arg(0)
		if pOFN == 0 {
			ctx.SetReturn(0)
			return
		}

		lpstrFile, _ := ctx.Mem.Read64(pOFN + 48)
		nMaxFile, _ := ctx.Mem.Read32(pOFN + 56)
		lpstrInitDir, _ := ctx.Mem.Read64(pOFN + 80)
		lpstrTitle, _ := ctx.Mem.Read64(pOFN + 88)
		lpstrFilter, _ := ctx.Mem.Read64(pOFN + 24)
		_ = lpstrFilter

		initDir := "."
		if lpstrInitDir != 0 {
			initDir = readGuestUTF16(lpstrInitDir)
		}
		dialogTitle := "Open File"
		if saving {
			dialogTitle = "Save As"
		}
		if lpstrTitle != 0 {
			if t := readGuestUTF16(lpstrTitle); t != "" {
				dialogTitle = t
			}
		}

		// Write result to a temp file
		tmpFile := os.TempDir() + "/raven_filepick.txt"
		os.Remove(tmpFile)

		var cmd *exec.Cmd
		if saving {
			// For save: use a simple bash read prompt in alacritty
			script := `cd ` + shellescape(initDir) + ` && read -e -p "Save as: " -i "" fn && echo "$fn" > ` + shellescape(tmpFile)
			cmd = exec.Command("alacritty", "--title", dialogTitle, "-e", "bash", "-c", script)
		} else {
			// For open: use fzf for file selection
			script := `cd ` + shellescape(initDir) + ` && find . -type f 2>/dev/null | sed 's|^./||' | sort | fzf --prompt="` + dialogTitle + `> " --height=80% > ` + shellescape(tmpFile)
			cmd = exec.Command("alacritty", "--title", dialogTitle, "-e", "bash", "-c", script)
		}

		// Run synchronously - blocks until dialog closes
		if err := cmd.Run(); err != nil {
			ravelog.Logf("[comdlg32] %s: alacritty exit: %v\n", dialogTitle, err)
			ctx.SetReturn(0)
			return
		}

		data, err := os.ReadFile(tmpFile)
		os.Remove(tmpFile)
		if err != nil || len(data) == 0 {
			ctx.SetReturn(0)
			return
		}
		result := strings.TrimRight(string(data), "\r\n")
		if result == "" {
			ctx.SetReturn(0)
			return
		}

		// Make absolute
		if !filepath.IsAbs(result) {
			result = filepath.Join(initDir, result)
		}

		// Write UTF-16 result to lpstrFile
		if lpstrFile == 0 || nMaxFile == 0 {
			ctx.SetReturn(1)
			return
		}
		ws := utf16Encode(result)
		maxW := int(nMaxFile) - 1
		if len(ws) > maxW {
			ws = ws[:maxW]
		}
		for i, w := range ws {
			ctx.Mem.Write16(lpstrFile+uint64(i)*2, w)
		}
		ctx.Mem.Write16(lpstrFile+uint64(len(ws))*2, 0)

		// nFileOffset = offset of filename part (after last backslash/slash)
		slash := strings.LastIndexAny(result, `/\`)
		nFileOffset := uint16(slash + 1) // chars, 0-based
		// nFileExtension = offset of extension dot
		dot := strings.LastIndex(result, ".")
		nFileExt := uint16(0)
		if dot > slash {
			nFileExt = uint16(dot)
		}
		ctx.Mem.Write16(pOFN+100, nFileOffset)
		ctx.Mem.Write16(pOFN+102, nFileExt)

		ravelog.Logf("[comdlg32] %s → %q\n", dialogTitle, result)
		ctx.SetReturn(1)
	}
	d.RegisterAutoStubHandler(comdlg32, "GetOpenFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		showFileDialog(ctx, false)
		return 0
	})
	d.RegisterAutoStubHandler(comdlg32, "GetSaveFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		showFileDialog(ctx, true)
		return 0
	})
	// ANSI variants - same struct layout, strings are ANSI instead of UTF-16
	showFileDialogA := func(ctx *ntapi.TrapContext, saving bool) {
		pOFN := ctx.Arg(0)
		if pOFN == 0 {
			ctx.SetReturn(0)
			return
		}
		lpstrFileA, _ := ctx.Mem.Read64(pOFN + 48)
		nMaxFile, _ := ctx.Mem.Read32(pOFN + 56)
		lpstrInitDirA, _ := ctx.Mem.Read64(pOFN + 80)
		lpstrTitleA, _ := ctx.Mem.Read64(pOFN + 88)
		initDir := "."
		if lpstrInitDirA != 0 {
			if d2 := readGuestString(lpstrInitDirA); d2 != "" {
				initDir = d2
			}
		}
		dialogTitle := "Open File"
		if saving {
			dialogTitle = "Save As"
		}
		if lpstrTitleA != 0 {
			if t := readGuestString(lpstrTitleA); t != "" {
				dialogTitle = t
			}
		}
		tmpFile := os.TempDir() + "/raven_filepick.txt"
		os.Remove(tmpFile)
		var cmd *exec.Cmd
		if saving {
			script := `cd ` + shellescape(initDir) + ` && read -e -p "Save as: " -i "" fn && echo "$fn" > ` + shellescape(tmpFile)
			cmd = exec.Command("alacritty", "--title", dialogTitle, "-e", "bash", "-c", script)
		} else {
			script := `cd ` + shellescape(initDir) + ` && find . -type f 2>/dev/null | sed 's|^./||' | sort | fzf --prompt="` + dialogTitle + `> " --height=80% > ` + shellescape(tmpFile)
			cmd = exec.Command("alacritty", "--title", dialogTitle, "-e", "bash", "-c", script)
		}
		if err := cmd.Run(); err != nil {
			ctx.SetReturn(0)
			return
		}
		data, err := os.ReadFile(tmpFile)
		os.Remove(tmpFile)
		if err != nil || len(data) == 0 {
			ctx.SetReturn(0)
			return
		}
		result := strings.TrimRight(string(data), "\r\n")
		if result == "" {
			ctx.SetReturn(0)
			return
		}
		if !filepath.IsAbs(result) {
			result = filepath.Join(initDir, result)
		}
		if lpstrFileA == 0 || nMaxFile == 0 {
			ctx.SetReturn(1)
			return
		}
		b := append([]byte(result), 0)
		if uint32(len(b)) > nMaxFile {
			b = b[:nMaxFile]
		}
		for i, c := range b {
			mem.Write8(lpstrFileA+uint64(i), c)
		}
		slash := strings.LastIndexAny(result, `/\`)
		ctx.Mem.Write16(pOFN+100, uint16(slash+1))
		dot := strings.LastIndex(result, ".")
		if dot > slash {
			ctx.Mem.Write16(pOFN+102, uint16(dot))
		}
		ravelog.Logf("[comdlg32] %s(A) → %q\n", dialogTitle, result)
		ctx.SetReturn(1)
	}
	d.RegisterAutoStubHandler(comdlg32, "GetOpenFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		showFileDialogA(ctx, false)
		return 0
	})
	d.RegisterAutoStubHandler(comdlg32, "GetSaveFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		showFileDialogA(ctx, true)
		return 0
	})

	// ChooseFontW: font picker - return FALSE (user cancelled)
	d.RegisterAutoStubHandler(comdlg32, "ChooseFontW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - user cancelled
		return 0
	})
	d.RegisterAutoStubHandler(comdlg32, "ChooseFontA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - user cancelled
		return 0
	})
	// PrintDlgExW: extended print dialog - return S_FALSE (1) meaning user cancelled
	d.RegisterAutoStubHandler(comdlg32, "PrintDlgExW", func(ctx *ntapi.TrapContext) uint32 {
		// Set dwResultAction = PD_RESULT_CANCEL (0) in the PRINTDLGEX struct
		pPD := ctx.Arg(0)
		if pPD != 0 {
			// dwResultAction is at the end of PRINTDLGEX; offset varies but
			// for our purposes returning S_FALSE is sufficient to indicate cancel
		}
		ctx.SetReturn(1) // S_FALSE - user cancelled
		return 0
	})
	d.RegisterAutoStubHandler(comdlg32, "PrintDlgExA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // S_FALSE - user cancelled
		return 0
	})
	// PageSetupDlgW: page setup dialog - return FALSE (user cancelled)
	d.RegisterAutoStubHandler(comdlg32, "PageSetupDlgW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - user cancelled
		return 0
	})
	d.RegisterAutoStubHandler(comdlg32, "PageSetupDlgA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - user cancelled
		return 0
	})
	// CommDlgExtendedError: return 0 (no error) after cancelled dialogs
	d.RegisterAutoStubHandler(comdlg32, "CommDlgExtendedError", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // CDERR_OK - no error
		return 0
	})
	// FindTextW / ReplaceTextW: find/replace dialogs - return NULL
	d.RegisterAutoStubHandler(comdlg32, "FindTextW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // NULL - dialog not created
		return 0
	})
	d.RegisterAutoStubHandler(comdlg32, "ReplaceTextW", func(ctx *ntapi.TrapContext) uint32 {
		// HWND ReplaceTextW(LPFINDREPLACEW lpfr)
		// ReactOS: dll/win32/comdlg32/finddlg.c
		// Creates a modeless Find & Replace dialog. We can't fully implement
		// the dialog yet, but we log the request and return NULL (dialog not created).
		lpfr := ctx.Arg(0)
		if lpfr != 0 {
			ravelog.Logf("[comdlg32] ReplaceTextW called (lpfr=0x%X, not yet implemented)\n", lpfr)
		}
		ctx.SetReturn(0) // NULL - dialog not created
		return 0
	})
}
