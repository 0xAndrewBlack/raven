package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerSecur32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["secur32.dll"]
	if !ok {
		return
	}
	_ = dll

	d.RegisterAutoStubHandler(dll, "AcceptSecurityContext", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[secur32] AcceptSecurityContext(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "AcquireCredentialsHandleA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[secur32] AcquireCredentialsHandleA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "AcquireCredentialsHandleW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[secur32] AcquireCredentialsHandleW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "AddCredentialsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[secur32] AddCredentialsA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "AddCredentialsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[secur32] AddCredentialsW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "AddSecurityPackageA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[secur32] AddSecurityPackageA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "AddSecurityPackageW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[secur32] AddSecurityPackageW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ApplyControlToken", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[secur32] ApplyControlToken(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CompleteAuthToken", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[secur32] CompleteAuthToken(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DecryptMessage", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[secur32] DecryptMessage(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DeleteSecurityContext", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[secur32] DeleteSecurityContext(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DeleteSecurityPackageA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[secur32] DeleteSecurityPackageA(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DeleteSecurityPackageW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[secur32] DeleteSecurityPackageW(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EncryptMessage", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[secur32] EncryptMessage(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EnumerateSecurityPackagesA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[secur32] EnumerateSecurityPackagesA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EnumerateSecurityPackagesW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[secur32] EnumerateSecurityPackagesW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ExportSecurityContext", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[secur32] ExportSecurityContext(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "FreeContextBuffer", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[secur32] FreeContextBuffer(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "FreeCredentialsHandle", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[secur32] FreeCredentialsHandle(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetComputerObjectNameA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[secur32] GetComputerObjectNameA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetComputerObjectNameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[secur32] GetComputerObjectNameW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetSecurityUserInfo", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[secur32] GetSecurityUserInfo(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetUserNameExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[secur32] GetUserNameExA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetUserNameExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[secur32] GetUserNameExW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ImpersonateSecurityContext", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[secur32] ImpersonateSecurityContext(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ImportSecurityContextA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[secur32] ImportSecurityContextA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ImportSecurityContextW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[secur32] ImportSecurityContextW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InitSecurityInterfaceA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[secur32] InitSecurityInterfaceA()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InitSecurityInterfaceW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[secur32] InitSecurityInterfaceW()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InitializeSecurityContextA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[secur32] InitializeSecurityContextA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InitializeSecurityContextW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[secur32] InitializeSecurityContextW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaCallAuthenticationPackage", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[secur32] LsaCallAuthenticationPackage(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaConnectUntrusted", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[secur32] LsaConnectUntrusted(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaDeregisterLogonProcess", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[secur32] LsaDeregisterLogonProcess(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaEnumerateLogonSessions", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[secur32] LsaEnumerateLogonSessions(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaFreeReturnBuffer", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[secur32] LsaFreeReturnBuffer(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaGetLogonSessionData", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[secur32] LsaGetLogonSessionData(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaLogonUser", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[secur32] LsaLogonUser(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaLookupAuthenticationPackage", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[secur32] LsaLookupAuthenticationPackage(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaRegisterLogonProcess", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[secur32] LsaRegisterLogonProcess(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaRegisterPolicyChangeNotification", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[secur32] LsaRegisterPolicyChangeNotification(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaUnregisterPolicyChangeNotification", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[secur32] LsaUnregisterPolicyChangeNotification(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "MakeSignature", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[secur32] MakeSignature(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QueryContextAttributesA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[secur32] QueryContextAttributesA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QueryContextAttributesW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[secur32] QueryContextAttributesW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QueryCredentialsAttributesA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[secur32] QueryCredentialsAttributesA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QueryCredentialsAttributesW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[secur32] QueryCredentialsAttributesW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QuerySecurityContextToken", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[secur32] QuerySecurityContextToken(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QuerySecurityPackageInfoA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[secur32] QuerySecurityPackageInfoA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QuerySecurityPackageInfoW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[secur32] QuerySecurityPackageInfoW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "RevertSecurityContext", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[secur32] RevertSecurityContext(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SealMessage", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[secur32] SealMessage(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetContextAttributesA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[secur32] SetContextAttributesA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetContextAttributesW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[secur32] SetContextAttributesW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "TranslateNameA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[secur32] TranslateNameA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "TranslateNameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[secur32] TranslateNameW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "UnsealMessage", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[secur32] UnsealMessage(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "VerifySignature", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[secur32] VerifySignature(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
}
