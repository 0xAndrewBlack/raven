package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerUserenvHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["userenv.dll"]
	if !ok {
		return
	}
	_ = dll
	sharedHeapAlloc := hctx.HeapAlloc

	d.RegisterAutoStubHandler(dll, "CreateEnvironmentBlock", func(ctx *ntapi.TrapContext) uint32 {
		lpEnvironment := ctx.Arg(0)
		hToken := ctx.Arg(1)
		bInherit := ctx.Arg(2)
		ravelog.Logf("[userenv] CreateEnvironmentBlock token=0x%x inherit=%d\n", hToken, bInherit)
		// Create minimal environment block: double-NUL terminated UTF-16
		if lpEnvironment != 0 {
			buf := sharedHeapAlloc(256, true)
			// Write "USERPROFILE=C:\Users\User" + NUL + NUL
			env := "USERPROFILE=C:\\Users\\User"
			off := uint64(0)
			for _, ch := range env {
				ctx.Mem.Write16(buf+off, uint16(ch))
				off += 2
			}
			ctx.Mem.Write16(buf+off, 0) // NUL terminator
			off += 2
			ctx.Mem.Write16(buf+off, 0) // double NUL = end
			ctx.Mem.Write64(lpEnvironment, buf)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DeleteProfileA", func(ctx *ntapi.TrapContext) uint32 {
		lpSidString := ctx.Arg(0)
		lpProfilePath := ctx.Arg(1)
		lpComputerName := ctx.Arg(2)
		ravelog.Logf("[userenv] DeleteProfileA sid=0x%x path=0x%x\n", lpSidString, lpProfilePath)
		_ = lpComputerName
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DeleteProfileW", func(ctx *ntapi.TrapContext) uint32 {
		lpSidString := ctx.Arg(0)
		lpProfilePath := ctx.Arg(1)
		lpComputerName := ctx.Arg(2)
		ravelog.Logf("[userenv] DeleteProfileW sid=0x%x path=0x%x\n", lpSidString, lpProfilePath)
		_ = lpComputerName
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DestroyEnvironmentBlock", func(ctx *ntapi.TrapContext) uint32 {
		lpEnvironment := ctx.Arg(0)
		ravelog.Logf("[userenv] DestroyEnvironmentBlock env=0x%x\n", lpEnvironment)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EnterCriticalPolicySection", func(ctx *ntapi.TrapContext) uint32 {
		bMachine := ctx.Arg(0)
		ravelog.Logf("[userenv] EnterCriticalPolicySection machine=%d\n", bMachine)
		ctx.SetReturn(0xDEAD0300) // fake section handle
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ExpandEnvironmentStringsForUserA", func(ctx *ntapi.TrapContext) uint32 {
		hToken := ctx.Arg(0)
		lpSrc := ctx.Arg(1)
		lpDest := ctx.Arg(2)
		dwSize := ctx.Arg(3)
		ravelog.Logf("[userenv] ExpandEnvironmentStringsForUserA token=0x%x\n", hToken)
		// Simple copy src→dest
		if lpSrc != 0 && lpDest != 0 && dwSize > 0 {
			for i := uint64(0); i < dwSize*1; i++ {
				b, _ := ctx.Mem.Read8(lpSrc + i)
				ctx.Mem.Write8(lpDest+i, b)
				if b == 0 {
					break
				}
			}
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ExpandEnvironmentStringsForUserW", func(ctx *ntapi.TrapContext) uint32 {
		hToken := ctx.Arg(0)
		lpSrc := ctx.Arg(1)
		lpDest := ctx.Arg(2)
		dwSize := ctx.Arg(3)
		ravelog.Logf("[userenv] ExpandEnvironmentStringsForUserW token=0x%x\n", hToken)
		// Simple copy src→dest
		if lpSrc != 0 && lpDest != 0 && dwSize > 0 {
			for i := uint64(0); i < dwSize*2; i++ {
				b, _ := ctx.Mem.Read8(lpSrc + i)
				ctx.Mem.Write8(lpDest+i, b)
				if b == 0 {
					break
				}
			}
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetAllUsersProfileDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		lpProfileDir := ctx.Arg(0)
		lpcchSize := ctx.Arg(1)
		ravelog.Logf("[userenv] GetAllUsersProfileDirectoryA\n")
		path := "C:\\ProgramData"
		if lpcchSize != 0 {
			ctx.Mem.Write32(lpcchSize, uint32(len(path)+1))
		}
		if lpProfileDir != 0 {
			for i, ch := range path {
				ctx.Mem.Write8(lpProfileDir+uint64(i)*1, byte(ch))
			}
			ctx.Mem.Write8(lpProfileDir+uint64(len(path))*1, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetAllUsersProfileDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		lpProfileDir := ctx.Arg(0)
		lpcchSize := ctx.Arg(1)
		ravelog.Logf("[userenv] GetAllUsersProfileDirectoryW\n")
		path := "C:\\ProgramData"
		if lpcchSize != 0 {
			ctx.Mem.Write32(lpcchSize, uint32(len(path)+1))
		}
		if lpProfileDir != 0 {
			for i, ch := range path {
				ctx.Mem.Write16(lpProfileDir+uint64(i)*2, uint16(ch))
			}
			ctx.Mem.Write16(lpProfileDir+uint64(len(path))*2, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetAppliedGPOListA", func(ctx *ntapi.TrapContext) uint32 {
		dwFlags := ctx.Arg(0)
		pMachineName := ctx.Arg(1)
		pSidUser := ctx.Arg(2)
		pGuidExtension := ctx.Arg(3)
		ppGPOList := ctx.Arg(4)
		ravelog.Logf("[userenv] GetAppliedGPOListA flags=0x%x\n", dwFlags)
		_ = pMachineName
		_ = pSidUser
		_ = pGuidExtension
		if ppGPOList != 0 {
			ctx.Mem.Write64(ppGPOList, 0)
		} // NULL = no GPOs
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetAppliedGPOListW", func(ctx *ntapi.TrapContext) uint32 {
		dwFlags := ctx.Arg(0)
		pMachineName := ctx.Arg(1)
		pSidUser := ctx.Arg(2)
		pGuidExtension := ctx.Arg(3)
		ppGPOList := ctx.Arg(4)
		ravelog.Logf("[userenv] GetAppliedGPOListW flags=0x%x\n", dwFlags)
		_ = pMachineName
		_ = pSidUser
		_ = pGuidExtension
		if ppGPOList != 0 {
			ctx.Mem.Write64(ppGPOList, 0)
		} // NULL = no GPOs
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetDefaultUserProfileDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		lpProfileDir := ctx.Arg(0)
		lpcchSize := ctx.Arg(1)
		ravelog.Logf("[userenv] GetDefaultUserProfileDirectoryA\n")
		path := "C:\\Users\\Default"
		if lpcchSize != 0 {
			ctx.Mem.Write32(lpcchSize, uint32(len(path)+1))
		}
		if lpProfileDir != 0 {
			for i, ch := range path {
				ctx.Mem.Write8(lpProfileDir+uint64(i)*1, byte(ch))
			}
			ctx.Mem.Write8(lpProfileDir+uint64(len(path))*1, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetDefaultUserProfileDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		lpProfileDir := ctx.Arg(0)
		lpcchSize := ctx.Arg(1)
		ravelog.Logf("[userenv] GetDefaultUserProfileDirectoryW\n")
		path := "C:\\Users\\Default"
		if lpcchSize != 0 {
			ctx.Mem.Write32(lpcchSize, uint32(len(path)+1))
		}
		if lpProfileDir != 0 {
			for i, ch := range path {
				ctx.Mem.Write16(lpProfileDir+uint64(i)*2, uint16(ch))
			}
			ctx.Mem.Write16(lpProfileDir+uint64(len(path))*2, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetProfileType", func(ctx *ntapi.TrapContext) uint32 {
		pdwFlags := ctx.Arg(0)
		ravelog.Logf("[userenv] GetProfileType\n")
		if pdwFlags != 0 {
			ctx.Mem.Write32(pdwFlags, 0)
		} // PT_TEMPORARY = 0 (local profile)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetProfilesDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		lpProfileDir := ctx.Arg(0)
		lpcchSize := ctx.Arg(1)
		ravelog.Logf("[userenv] GetProfilesDirectoryA\n")
		path := "C:\\Users"
		if lpcchSize != 0 {
			ctx.Mem.Write32(lpcchSize, uint32(len(path)+1))
		}
		if lpProfileDir != 0 {
			for i, ch := range path {
				ctx.Mem.Write8(lpProfileDir+uint64(i)*1, byte(ch))
			}
			ctx.Mem.Write8(lpProfileDir+uint64(len(path))*1, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetProfilesDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		lpProfileDir := ctx.Arg(0)
		lpcchSize := ctx.Arg(1)
		ravelog.Logf("[userenv] GetProfilesDirectoryW\n")
		path := "C:\\Users"
		if lpcchSize != 0 {
			ctx.Mem.Write32(lpcchSize, uint32(len(path)+1))
		}
		if lpProfileDir != 0 {
			for i, ch := range path {
				ctx.Mem.Write16(lpProfileDir+uint64(i)*2, uint16(ch))
			}
			ctx.Mem.Write16(lpProfileDir+uint64(len(path))*2, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetUserProfileDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		hToken := ctx.Arg(0)
		lpProfileDir := ctx.Arg(1)
		lpcchSize := ctx.Arg(2)
		ravelog.Logf("[userenv] GetUserProfileDirectoryA token=0x%x\n", hToken)
		path := "C:\\Users\\User"
		if lpcchSize != 0 {
			ctx.Mem.Write32(lpcchSize, uint32(len(path)+1))
		}
		if lpProfileDir != 0 {
			for i, ch := range path {
				ctx.Mem.Write8(lpProfileDir+uint64(i)*1, byte(ch))
			}
			ctx.Mem.Write8(lpProfileDir+uint64(len(path))*1, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetUserProfileDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		hToken := ctx.Arg(0)
		lpProfileDir := ctx.Arg(1)
		lpcchSize := ctx.Arg(2)
		ravelog.Logf("[userenv] GetUserProfileDirectoryW token=0x%x\n", hToken)
		path := "C:\\Users\\User"
		if lpcchSize != 0 {
			ctx.Mem.Write32(lpcchSize, uint32(len(path)+1))
		}
		if lpProfileDir != 0 {
			for i, ch := range path {
				ctx.Mem.Write16(lpProfileDir+uint64(i)*2, uint16(ch))
			}
			ctx.Mem.Write16(lpProfileDir+uint64(len(path))*2, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LeaveCriticalPolicySection", func(ctx *ntapi.TrapContext) uint32 {
		hSection := ctx.Arg(0)
		ravelog.Logf("[userenv] LeaveCriticalPolicySection handle=0x%x\n", hSection)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LoadUserProfileA", func(ctx *ntapi.TrapContext) uint32 {
		hToken := ctx.Arg(0)
		lpProfileInfo := ctx.Arg(1)
		ravelog.Logf("[userenv] LoadUserProfileA token=0x%x info=0x%x\n", hToken, lpProfileInfo)
		// Set hProfile in PROFILEINFO (+24 on x64)
		if lpProfileInfo != 0 {
			ctx.Mem.Write64(lpProfileInfo+24, 0xDEAD0200)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LoadUserProfileW", func(ctx *ntapi.TrapContext) uint32 {
		hToken := ctx.Arg(0)
		lpProfileInfo := ctx.Arg(1)
		ravelog.Logf("[userenv] LoadUserProfileW token=0x%x info=0x%x\n", hToken, lpProfileInfo)
		// Set hProfile in PROFILEINFO (+24 on x64)
		if lpProfileInfo != 0 {
			ctx.Mem.Write64(lpProfileInfo+24, 0xDEAD0200)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "RefreshPolicy", func(ctx *ntapi.TrapContext) uint32 {
		bMachine := ctx.Arg(0)
		ravelog.Logf("[userenv] RefreshPolicy machine=%d\n", bMachine)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "RefreshPolicyEx", func(ctx *ntapi.TrapContext) uint32 {
		bMachine := ctx.Arg(0)
		dwOptions := ctx.Arg(1)
		ravelog.Logf("[userenv] RefreshPolicyEx machine=%d opts=0x%x\n", bMachine, dwOptions)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "RegisterGPNotification", func(ctx *ntapi.TrapContext) uint32 {
		hEvent := ctx.Arg(0)
		bMachine := ctx.Arg(1)
		ravelog.Logf("[userenv] RegisterGPNotification event=0x%x machine=%d\n", hEvent, bMachine)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "UnloadUserProfile", func(ctx *ntapi.TrapContext) uint32 {
		hToken := ctx.Arg(0)
		hProfile := ctx.Arg(1)
		ravelog.Logf("[userenv] UnloadUserProfile token=0x%x profile=0x%x\n", hToken, hProfile)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "UnregisterGPNotification", func(ctx *ntapi.TrapContext) uint32 {
		hEvent := ctx.Arg(0)
		ravelog.Logf("[userenv] UnregisterGPNotification event=0x%x\n", hEvent)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WaitForMachinePolicyForegroundProcessing", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[userenv] WaitForMachinePolicyForegroundProcessing()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WaitForUserPolicyForegroundProcessing", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[userenv] WaitForUserPolicyForegroundProcessing()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[userenv] -noname()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2, p3, p4, p5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", p0, p1, p2, p3, p4, p5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2, p3, p4, p5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", p0, p1, p2, p3, p4, p5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x)\n", p0, p1, p2, p3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x)\n", p0, p1, p2, p3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x)\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x)\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2, p3, p4, p5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", p0, p1, p2, p3, p4, p5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2, p3, p4, p5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", p0, p1, p2, p3, p4, p5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[userenv] -noname(0x%x)\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2, p3, p4, p5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", p0, p1, p2, p3, p4, p5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2, p3, p4, p5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", p0, p1, p2, p3, p4, p5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[userenv] -noname(0x%x)\n", p0)
		ctx.SetReturn(0)
		return 0
	})
}
