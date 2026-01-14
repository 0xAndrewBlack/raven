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

	d.RegisterAutoStubHandler(dll, "CreateEnvironmentBlock", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[userenv] CreateEnvironmentBlock(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DeleteProfileA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[userenv] DeleteProfileA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DeleteProfileW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[userenv] DeleteProfileW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DestroyEnvironmentBlock", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[userenv] DestroyEnvironmentBlock(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EnterCriticalPolicySection", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[userenv] EnterCriticalPolicySection(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ExpandEnvironmentStringsForUserA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[userenv] ExpandEnvironmentStringsForUserA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ExpandEnvironmentStringsForUserW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[userenv] ExpandEnvironmentStringsForUserW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetAllUsersProfileDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] GetAllUsersProfileDirectoryA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetAllUsersProfileDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] GetAllUsersProfileDirectoryW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetAppliedGPOListA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[userenv] GetAppliedGPOListA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetAppliedGPOListW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[userenv] GetAppliedGPOListW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetDefaultUserProfileDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] GetDefaultUserProfileDirectoryA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetDefaultUserProfileDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] GetDefaultUserProfileDirectoryW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetProfileType", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[userenv] GetProfileType(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetProfilesDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] GetProfilesDirectoryA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetProfilesDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] GetProfilesDirectoryW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetUserProfileDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[userenv] GetUserProfileDirectoryA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetUserProfileDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[userenv] GetUserProfileDirectoryW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LeaveCriticalPolicySection", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[userenv] LeaveCriticalPolicySection(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LoadUserProfileA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] LoadUserProfileA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LoadUserProfileW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] LoadUserProfileW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "RefreshPolicy", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[userenv] RefreshPolicy(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "RefreshPolicyEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] RefreshPolicyEx(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "RegisterGPNotification", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] RegisterGPNotification(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "UnloadUserProfile", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] UnloadUserProfile(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "UnregisterGPNotification", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[userenv] UnregisterGPNotification(0x%x)\n", a0)
		ctx.SetReturn(0)
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
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[userenv] -noname(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[userenv] -noname(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-noname", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[userenv] -noname(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
}
