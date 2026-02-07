//go:build guest_windows

package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	msiErrorSuccess            = 0
	msiErrorFileNotFound       = 2
	msiErrorOpenFailed         = 110
	msiErrorInsufficientBuffer = 122
	msiErrorNoMoreItems        = 259
	msiErrorUnknownProduct     = 1605
	msiErrorUnknownComponent   = 1607
	msiErrorFunctionFailed     = 1627
	msiInstallStateUnknown     = 0xFFFFFFFF
	msiSOK                     = 0
)

func registerMsiHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	readGuestUTF16 := hctx.ReadGuestUTF16

	msi, ok := hctx.SynthByName["msi.dll"]
	if !ok {
		return
	}

	setLastError := func(ctx *ntapi.TrapContext, code uint32) {
		if ctx.State != nil && ctx.State.TEBAddr != 0 {
			ctx.Mem.Write32(ctx.State.TEBAddr+ntapi.TebLastErrorValue, code)
		}
	}

	writeUTF16Result := func(ctx *ntapi.TrapContext, buf, pcch uint64, s string) uint32 {
		required := uint32(len(utf16Encode(s)) + 1)
		available := required
		if pcch != 0 {
			available, _ = ctx.Mem.Read32(pcch)
			ctx.Mem.Write32(pcch, required)
		}
		if buf == 0 {
			return msiErrorSuccess
		}
		if available < required {
			return msiErrorInsufficientBuffer
		}
		ws := utf16Encode(s)
		for i, w := range ws {
			ctx.Mem.Write16(buf+uint64(i)*2, w)
		}
		ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
		return msiErrorSuccess
	}

	dllGetVersion := func(ctx *ntapi.TrapContext) uint32 {
		pInfo := ctx.Arg(0)
		if pInfo != 0 {
			cbSize, _ := ctx.Mem.Read32(pInfo)
			if cbSize >= 20 {
				ctx.Mem.Write32(pInfo+4, 5)
				ctx.Mem.Write32(pInfo+8, 0)
				ctx.Mem.Write32(pInfo+12, 0)
				ctx.Mem.Write32(pInfo+16, 2)
			}
		}
		ctx.SetReturn(msiSOK)
		return 0
	}

	d.RegisterAutoStubHandler(msi, "MsiGetProductInfoW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorUnknownProduct)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiGetProductInfoExW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorUnknownProduct)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiEnumProductsW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorNoMoreItems)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiEnumProductsExW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorNoMoreItems)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiQueryProductStateW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiInstallStateUnknown)
		return 0
	})

	d.RegisterAutoStubHandler(msi, "MsiGetComponentPathW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiInstallStateUnknown)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiEnumComponentsW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorNoMoreItems)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiEnumComponentsExW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorNoMoreItems)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiEnumFeaturesW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorNoMoreItems)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiGetFeatureUsageW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorUnknownProduct)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiQueryFeatureStateW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiInstallStateUnknown)
		return 0
	})

	d.RegisterAutoStubHandler(msi, "MsiInstallProductW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorSuccess)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiConfigureProductW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorSuccess)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiReinstallProductW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorSuccess)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiConfigureFeatureW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorSuccess)
		return 0
	})

	d.RegisterAutoStubHandler(msi, "MsiOpenDatabaseW", func(ctx *ntapi.TrapContext) uint32 {
		phDatabase := ctx.Arg(2)
		if phDatabase != 0 {
			ctx.Mem.Write64(phDatabase, 0)
		}
		ctx.SetReturn(msiErrorOpenFailed)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiCloseHandle", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorSuccess)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiDatabaseOpenViewW", func(ctx *ntapi.TrapContext) uint32 {
		phView := ctx.Arg(2)
		if phView != 0 {
			ctx.Mem.Write64(phView, 0)
		}
		ctx.SetReturn(msiErrorFunctionFailed)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiViewExecute", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorFunctionFailed)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiViewFetch", func(ctx *ntapi.TrapContext) uint32 {
		phRecord := ctx.Arg(1)
		if phRecord != 0 {
			ctx.Mem.Write64(phRecord, 0)
		}
		ctx.SetReturn(msiErrorNoMoreItems)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiViewClose", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorFunctionFailed)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiRecordGetFieldCount", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiRecordGetStringW", func(ctx *ntapi.TrapContext) uint32 {
		szValueBuf := ctx.Arg(2)
		pcchValueBuf := ctx.Arg(3)
		if pcchValueBuf != 0 {
			ctx.Mem.Write32(pcchValueBuf, 0)
		}
		if szValueBuf != 0 {
			ctx.Mem.Write16(szValueBuf, 0)
		}
		ctx.SetReturn(msiErrorFunctionFailed)
		return 0
	})

	d.RegisterAutoStubHandler(msi, "MsiSourceListEnumSourcesW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorNoMoreItems)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiSourceListGetInfoW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorUnknownProduct)
		return 0
	})

	d.RegisterAutoStubHandler(msi, "MsiGetFileVersionW", func(ctx *ntapi.TrapContext) uint32 {
		szFilePath := readGuestUTF16(ctx.Arg(0))
		lpVersionBuf := ctx.Arg(1)
		pcchVersionBuf := ctx.Arg(2)
		lpLangBuf := ctx.Arg(3)
		pcchLangBuf := ctx.Arg(4)
		hostPath := winPathToVFS(szFilePath)

		version, lang, err := readMSIFileVersion(hostPath)
		if err != nil {
			ravelog.Logf("[msi] MsiGetFileVersionW path=%q err=%v\n", szFilePath, err)
			setLastError(ctx, msiErrorFileNotFound)
			ctx.SetReturn(msiErrorFileNotFound)
			return 0
		}

		if code := writeUTF16Result(ctx, lpVersionBuf, pcchVersionBuf, version); code != msiErrorSuccess {
			setLastError(ctx, code)
			ctx.SetReturn(uint64(code))
			return 0
		}
		if code := writeUTF16Result(ctx, lpLangBuf, pcchLangBuf, lang); code != msiErrorSuccess {
			setLastError(ctx, code)
			ctx.SetReturn(uint64(code))
			return 0
		}

		setLastError(ctx, msiErrorSuccess)
		ctx.SetReturn(msiErrorSuccess)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiGetShortcutTargetW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorFunctionFailed)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "MsiProvideComponentW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(msiErrorUnknownProduct)
		return 0
	})
	d.RegisterAutoStubHandler(msi, "DllGetVersion", dllGetVersion)

	_ = msiErrorUnknownComponent
}

func readMSIFileVersion(path string) (string, string, error) {
	versionData, langID, err := readPEVersionResource(path)
	if err != nil {
		return "", "", err
	}
	if len(versionData) < 6 {
		return "", "", fmt.Errorf("version resource too small")
	}

	pos := 6
	for pos+1 < len(versionData) {
		if binary.LittleEndian.Uint16(versionData[pos:pos+2]) == 0 {
			pos += 2
			break
		}
		pos += 2
	}
	pos = (pos + 3) &^ 3
	if pos+52 > len(versionData) {
		return "", "", fmt.Errorf("missing VS_FIXEDFILEINFO")
	}
	fixed := versionData[pos:]
	if binary.LittleEndian.Uint32(fixed[0:4]) != 0xFEEF04BD {
		return "", "", fmt.Errorf("invalid VS_FIXEDFILEINFO signature")
	}
	fileVersionMS := binary.LittleEndian.Uint32(fixed[8:12])
	fileVersionLS := binary.LittleEndian.Uint32(fixed[12:16])
	version := fmt.Sprintf("%d.%d.%d.%d",
		fileVersionMS>>16,
		fileVersionMS&0xFFFF,
		fileVersionLS>>16,
		fileVersionLS&0xFFFF,
	)
	lang := fmt.Sprintf("%04x", langID)
	return version, lang, nil
}

func readPEVersionResource(path string) ([]byte, uint16, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	pf, err := pe.NewFile(f)
	if err != nil {
		return nil, 0, err
	}
	defer pf.Close()

	var resRVA uint32
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) <= 2 {
			return nil, 0, fmt.Errorf("missing resource directory")
		}
		resRVA = oh.DataDirectory[2].VirtualAddress
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) <= 2 {
			return nil, 0, fmt.Errorf("missing resource directory")
		}
		resRVA = oh.DataDirectory[2].VirtualAddress
	default:
		return nil, 0, fmt.Errorf("unsupported PE optional header")
	}
	if resRVA == 0 {
		return nil, 0, fmt.Errorf("missing resource directory")
	}

	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}

	rvaToOffset := func(rva uint32) (uint32, bool) {
		for _, s := range pf.Sections {
			start := s.VirtualAddress
			size := s.Size
			if s.VirtualSize > size {
				size = s.VirtualSize
			}
			end := start + size
			if rva >= start && rva < end {
				return s.Offset + (rva - start), true
			}
		}
		return 0, false
	}

	resBase, ok := rvaToOffset(resRVA)
	if !ok {
		return nil, 0, fmt.Errorf("resource directory not mapped")
	}

	findEntryByID := func(dirOff uint32, id uint32) (uint32, uint32, bool) {
		if int(resBase+dirOff+16) > len(fileData) {
			return 0, 0, false
		}
		entryCount := binary.LittleEndian.Uint16(fileData[resBase+dirOff+12:resBase+dirOff+14]) +
			binary.LittleEndian.Uint16(fileData[resBase+dirOff+14:resBase+dirOff+16])
		entryOff := resBase + dirOff + 16
		for i := uint16(0); i < entryCount; i++ {
			off := entryOff + uint32(i)*8
			if int(off+8) > len(fileData) {
				return 0, 0, false
			}
			name := binary.LittleEndian.Uint32(fileData[off : off+4])
			if name&0x80000000 != 0 {
				continue
			}
			if name != id {
				continue
			}
			target := binary.LittleEndian.Uint32(fileData[off+4 : off+8])
			return target, name, true
		}
		return 0, 0, false
	}

	firstEntry := func(dirOff uint32) (uint32, uint32, bool) {
		if int(resBase+dirOff+16) > len(fileData) {
			return 0, 0, false
		}
		entryCount := binary.LittleEndian.Uint16(fileData[resBase+dirOff+12:resBase+dirOff+14]) +
			binary.LittleEndian.Uint16(fileData[resBase+dirOff+14:resBase+dirOff+16])
		if entryCount == 0 {
			return 0, 0, false
		}
		entryOff := resBase + dirOff + 16
		for i := uint16(0); i < entryCount; i++ {
			off := entryOff + uint32(i)*8
			if int(off+8) > len(fileData) {
				return 0, 0, false
			}
			name := binary.LittleEndian.Uint32(fileData[off : off+4])
			target := binary.LittleEndian.Uint32(fileData[off+4 : off+8])
			return target, name, true
		}
		return 0, 0, false
	}

	typeEntry, _, ok := findEntryByID(0, 16)
	if !ok || typeEntry&0x80000000 == 0 {
		return nil, 0, fmt.Errorf("RT_VERSION not found")
	}
	nameEntry, _, ok := findEntryByID(typeEntry&0x7FFFFFFF, 1)
	if !ok {
		nameEntry, _, ok = firstEntry(typeEntry & 0x7FFFFFFF)
	}
	if !ok || nameEntry&0x80000000 == 0 {
		return nil, 0, fmt.Errorf("version name entry not found")
	}
	langEntry, langName, ok := firstEntry(nameEntry & 0x7FFFFFFF)
	if !ok || langEntry&0x80000000 != 0 {
		return nil, 0, fmt.Errorf("version language entry not found")
	}

	dataEntryOff := resBase + (langEntry & 0x7FFFFFFF)
	if int(dataEntryOff+16) > len(fileData) {
		return nil, 0, fmt.Errorf("version data entry truncated")
	}
	dataRVA := binary.LittleEndian.Uint32(fileData[dataEntryOff : dataEntryOff+4])
	dataSize := binary.LittleEndian.Uint32(fileData[dataEntryOff+4 : dataEntryOff+8])
	dataOff, ok := rvaToOffset(dataRVA)
	if !ok {
		return nil, 0, fmt.Errorf("version data not mapped")
	}
	if int(dataOff+dataSize) > len(fileData) {
		return nil, 0, fmt.Errorf("version data truncated")
	}

	raw := make([]byte, dataSize)
	copy(raw, fileData[dataOff:dataOff+dataSize])
	return raw, uint16(langName & 0xFFFF), nil
}
