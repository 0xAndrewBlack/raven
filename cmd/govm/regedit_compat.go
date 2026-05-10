//go:build guest_windows

package main

import (
	"path/filepath"
	"strings"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	regeditAcceleratorResourceID     = uint64(100)
	regeditFallbackAcceleratorHandle = uint64(0xacff0001)
)

var regeditFallbackStrings = map[uint32]string{
	16: "Registry Editor",
	17: "Name",
	18: "Data",
	19: "Computer",
	20: "(Default)",
	27: "(value not set)",
	31: "Type",
}

func isRegeditImage(imagePath string) bool {
	imagePath = strings.ReplaceAll(imagePath, `\`, "/")
	return strings.EqualFold(filepath.Base(imagePath), "regedit.exe")
}

func regeditStringFallback(hctx *HandlerCtx, instance uint64, resource uint32) string {
	if hctx == nil || hctx.MainModule == nil || hctx.PeLoadStringW == nil {
		return ""
	}
	if !isRegeditImage(hctx.ImagePath) {
		return ""
	}
	if instance != 0 && instance != hctx.MainModule.BaseAddr {
		return ""
	}
	if value, _, _ := hctx.PeLoadStringW(resource); value != "" {
		return ""
	}
	return regeditFallbackStrings[resource]
}

func regeditAcceleratorFallback(hctx *HandlerCtx, instance, resource uint64) uint64 {
	if hctx == nil || hctx.MainModule == nil || hctx.PeLoadRawResource == nil {
		return 0
	}
	if !isRegeditImage(hctx.ImagePath) {
		return 0
	}
	if instance != 0 && instance != hctx.MainModule.BaseAddr {
		return 0
	}
	if resource != regeditAcceleratorResourceID {
		return 0
	}
	_, _, found := hctx.PeLoadRawResource(
		hctx.MainModule.BaseAddr,
		hctx.MainModule.ResourceDirRVA,
		9,
		uint32(resource),
	)
	if found {
		return 0
	}
	return regeditFallbackAcceleratorHandle
}

func registerRegeditCompatibility(hctx *HandlerCtx) {
	if hctx == nil || hctx.MainModule == nil || !isRegeditImage(hctx.ImagePath) {
		return
	}
	if user32, ok := hctx.SynthByName["user32.dll"]; ok {
		hctx.Disp.WrapAutoStubHandler(user32, "LoadStringW", func(previous ntapi.TrapHandler) ntapi.TrapHandler {
			return func(ctx *ntapi.TrapContext) uint32 {
				value := regeditStringFallback(hctx, ctx.Arg(0), uint32(ctx.Arg(1)))
				maxChars := int(int32(ctx.Arg(3)))
				if value == "" || ctx.Arg(2) == 0 || maxChars <= 0 {
					return previous(ctx)
				}
				written := writeUTF16(ctx.Mem, ctx.Arg(2), value, maxChars)
				ravelog.Logf("[regedit] using fallback string %d for missing MUI resource\n", ctx.Arg(1))
				ctx.SetReturn(uint64(written))
				return 0
			}
		})
	}
	if user32, ok := hctx.SynthByName["user32.dll"]; ok &&
		regeditAcceleratorFallback(hctx, hctx.MainModule.BaseAddr, regeditAcceleratorResourceID) != 0 {
		hctx.Disp.WrapAutoStubHandler(user32, "LoadAcceleratorsW", func(previous ntapi.TrapHandler) ntapi.TrapHandler {
			return func(ctx *ntapi.TrapContext) uint32 {
				handle := regeditAcceleratorFallback(hctx, ctx.Arg(0), ctx.Arg(1))
				if handle == 0 {
					return previous(ctx)
				}
				ravelog.Logf("[regedit] using fallback accelerator handle for missing MUI resource 100\n")
				ctx.SetReturn(handle)
				return 0
			}
		})
	}
}
