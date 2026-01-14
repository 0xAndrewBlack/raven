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
		phCredential := ctx.Arg(0)
		phContext := ctx.Arg(1)
		pInput := ctx.Arg(2)
		fContextReq := ctx.Arg(3)
		TargetDataRep := ctx.Arg(4)
		phNewContext := ctx.Arg(5)
		ravelog.Logf("[secur32] AcceptSecurityContext cred=0x%x ctx=0x%x\n", phCredential, phContext)
		_ = pInput; _ = fContextReq; _ = TargetDataRep; _ = phNewContext
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "AcquireCredentialsHandleA", func(ctx *ntapi.TrapContext) uint32 {
		pszPrincipal := ctx.Arg(0)
		pszPackage := ctx.Arg(1)
		fCredentialUse := ctx.Arg(2)
		pvLogonId := ctx.Arg(3)
		pAuthData := ctx.Arg(4)
		pGetKeyFn := ctx.Arg(5)
		ravelog.Logf("[secur32] AcquireCredentialsHandleA use=0x%x\n", fCredentialUse)
		_ = pszPrincipal; _ = pszPackage; _ = pvLogonId; _ = pAuthData; _ = pGetKeyFn
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "AcquireCredentialsHandleW", func(ctx *ntapi.TrapContext) uint32 {
		pszPrincipal := ctx.Arg(0)
		pszPackage := ctx.Arg(1)
		fCredentialUse := ctx.Arg(2)
		pvLogonId := ctx.Arg(3)
		pAuthData := ctx.Arg(4)
		pGetKeyFn := ctx.Arg(5)
		ravelog.Logf("[secur32] AcquireCredentialsHandleW use=0x%x\n", fCredentialUse)
		_ = pszPrincipal; _ = pszPackage; _ = pvLogonId; _ = pAuthData; _ = pGetKeyFn
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "AddCredentialsA", func(ctx *ntapi.TrapContext) uint32 {
		phCredentials := ctx.Arg(0)
		pszPrincipal := ctx.Arg(1)
		pszPackage := ctx.Arg(2)
		fCredentialUse := ctx.Arg(3)
		pAuthData := ctx.Arg(4)
		pGetKeyFn := ctx.Arg(5)
		ravelog.Logf("[secur32] AddCredentialsA use=0x%x\n", fCredentialUse)
		_ = phCredentials; _ = pszPrincipal; _ = pszPackage; _ = pAuthData; _ = pGetKeyFn
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "AddCredentialsW", func(ctx *ntapi.TrapContext) uint32 {
		phCredentials := ctx.Arg(0)
		pszPrincipal := ctx.Arg(1)
		pszPackage := ctx.Arg(2)
		fCredentialUse := ctx.Arg(3)
		pAuthData := ctx.Arg(4)
		pGetKeyFn := ctx.Arg(5)
		ravelog.Logf("[secur32] AddCredentialsW use=0x%x\n", fCredentialUse)
		_ = phCredentials; _ = pszPrincipal; _ = pszPackage; _ = pAuthData; _ = pGetKeyFn
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "AddSecurityPackageA", func(ctx *ntapi.TrapContext) uint32 {
		pszPackageName := ctx.Arg(0)
		pOptions := ctx.Arg(1)
		ravelog.Logf("[secur32] AddSecurityPackageA name=0x%x\n", pszPackageName)
		_ = pOptions
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "AddSecurityPackageW", func(ctx *ntapi.TrapContext) uint32 {
		pszPackageName := ctx.Arg(0)
		pOptions := ctx.Arg(1)
		ravelog.Logf("[secur32] AddSecurityPackageW name=0x%x\n", pszPackageName)
		_ = pOptions
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ApplyControlToken", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		pInput := ctx.Arg(1)
		ravelog.Logf("[secur32] ApplyControlToken ctx=0x%x input=0x%x\n", phContext, pInput)
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CompleteAuthToken", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		pToken := ctx.Arg(1)
		ravelog.Logf("[secur32] CompleteAuthToken ctx=0x%x token=0x%x\n", phContext, pToken)
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DecryptMessage", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		pMessage := ctx.Arg(1)
		MessageSeqNo := ctx.Arg(2)
		pfQOP := ctx.Arg(3)
		ravelog.Logf("[secur32] DecryptMessage ctx=0x%x seq=%d\n", phContext, MessageSeqNo)
		_ = pMessage
		if pfQOP != 0 { ctx.Mem.Write32(pfQOP, 0) }
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DeleteSecurityContext", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		ravelog.Logf("[secur32] DeleteSecurityContext ctx=0x%x\n", phContext)
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DeleteSecurityPackageA", func(ctx *ntapi.TrapContext) uint32 {
		pszPackageName := ctx.Arg(0)
		ravelog.Logf("[secur32] DeleteSecurityPackageA name=0x%x\n", pszPackageName)
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DeleteSecurityPackageW", func(ctx *ntapi.TrapContext) uint32 {
		pszPackageName := ctx.Arg(0)
		ravelog.Logf("[secur32] DeleteSecurityPackageW name=0x%x\n", pszPackageName)
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EncryptMessage", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		fQOP := ctx.Arg(1)
		pMessage := ctx.Arg(2)
		MessageSeqNo := ctx.Arg(3)
		ravelog.Logf("[secur32] EncryptMessage ctx=0x%x qop=0x%x seq=%d\n", phContext, fQOP, MessageSeqNo)
		_ = pMessage
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EnumerateSecurityPackagesA", func(ctx *ntapi.TrapContext) uint32 {
		pcPackages := ctx.Arg(0)
		ppPackageInfo := ctx.Arg(1)
		ravelog.Logf("[secur32] EnumerateSecurityPackagesA\n")
		if pcPackages != 0 { ctx.Mem.Write32(pcPackages, 0) } // 0 packages
		if ppPackageInfo != 0 { ctx.Mem.Write64(ppPackageInfo, 0) }
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EnumerateSecurityPackagesW", func(ctx *ntapi.TrapContext) uint32 {
		pcPackages := ctx.Arg(0)
		ppPackageInfo := ctx.Arg(1)
		ravelog.Logf("[secur32] EnumerateSecurityPackagesW\n")
		if pcPackages != 0 { ctx.Mem.Write32(pcPackages, 0) } // 0 packages
		if ppPackageInfo != 0 { ctx.Mem.Write64(ppPackageInfo, 0) }
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ExportSecurityContext", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		fFlags := ctx.Arg(1)
		pPackedContext := ctx.Arg(2)
		pToken := ctx.Arg(3)
		ravelog.Logf("[secur32] ExportSecurityContext ctx=0x%x flags=0x%x\n", phContext, fFlags)
		_ = pPackedContext; _ = pToken
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "FreeContextBuffer", func(ctx *ntapi.TrapContext) uint32 {
		pvContextBuffer := ctx.Arg(0)
		ravelog.Logf("[secur32] FreeContextBuffer buf=0x%x\n", pvContextBuffer)
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "FreeCredentialsHandle", func(ctx *ntapi.TrapContext) uint32 {
		phCredential := ctx.Arg(0)
		ravelog.Logf("[secur32] FreeCredentialsHandle cred=0x%x\n", phCredential)
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetComputerObjectNameA", func(ctx *ntapi.TrapContext) uint32 {
		NameFormat := ctx.Arg(0)
		lpNameBuffer := ctx.Arg(1)
		nSize := ctx.Arg(2)
		ravelog.Logf("[secur32] GetComputerObjectNameA format=%d\n", NameFormat)
		name := "RAVEN-PC"
		if nSize != 0 { ctx.Mem.Write32(nSize, uint32(len(name)+1)) }
		if lpNameBuffer != 0 {
			for i, ch := range name { ctx.Mem.Write8(lpNameBuffer+uint64(i)*1, byte(ch)) }
			ctx.Mem.Write8(lpNameBuffer+uint64(len(name))*1, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetComputerObjectNameW", func(ctx *ntapi.TrapContext) uint32 {
		NameFormat := ctx.Arg(0)
		lpNameBuffer := ctx.Arg(1)
		nSize := ctx.Arg(2)
		ravelog.Logf("[secur32] GetComputerObjectNameW format=%d\n", NameFormat)
		name := "RAVEN-PC"
		if nSize != 0 { ctx.Mem.Write32(nSize, uint32(len(name)+1)) }
		if lpNameBuffer != 0 {
			for i, ch := range name { ctx.Mem.Write16(lpNameBuffer+uint64(i)*2, uint16(ch)) }
			ctx.Mem.Write16(lpNameBuffer+uint64(len(name))*2, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetSecurityUserInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[secur32] GetSecurityUserInfo p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetUserNameExA", func(ctx *ntapi.TrapContext) uint32 {
		NameFormat := ctx.Arg(0)
		lpNameBuffer := ctx.Arg(1)
		nSize := ctx.Arg(2)
		ravelog.Logf("[secur32] GetUserNameExA format=%d\n", NameFormat)
		name := "User"
		if nSize != 0 { ctx.Mem.Write32(nSize, uint32(len(name)+1)) }
		if lpNameBuffer != 0 {
			for i, ch := range name { ctx.Mem.Write8(lpNameBuffer+uint64(i)*1, byte(ch)) }
			ctx.Mem.Write8(lpNameBuffer+uint64(len(name))*1, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetUserNameExW", func(ctx *ntapi.TrapContext) uint32 {
		NameFormat := ctx.Arg(0)
		lpNameBuffer := ctx.Arg(1)
		nSize := ctx.Arg(2)
		ravelog.Logf("[secur32] GetUserNameExW format=%d\n", NameFormat)
		name := "User"
		if nSize != 0 { ctx.Mem.Write32(nSize, uint32(len(name)+1)) }
		if lpNameBuffer != 0 {
			for i, ch := range name { ctx.Mem.Write16(lpNameBuffer+uint64(i)*2, uint16(ch)) }
			ctx.Mem.Write16(lpNameBuffer+uint64(len(name))*2, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ImpersonateSecurityContext", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		ravelog.Logf("[secur32] ImpersonateSecurityContext ctx=0x%x\n", phContext)
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ImportSecurityContextA", func(ctx *ntapi.TrapContext) uint32 {
		pszPackage := ctx.Arg(0)
		pPackedContext := ctx.Arg(1)
		Token := ctx.Arg(2)
		phContext := ctx.Arg(3)
		ravelog.Logf("[secur32] ImportSecurityContextA pkg=0x%x\n", pszPackage)
		_ = pPackedContext; _ = Token; _ = phContext
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ImportSecurityContextW", func(ctx *ntapi.TrapContext) uint32 {
		pszPackage := ctx.Arg(0)
		pPackedContext := ctx.Arg(1)
		Token := ctx.Arg(2)
		phContext := ctx.Arg(3)
		ravelog.Logf("[secur32] ImportSecurityContextW pkg=0x%x\n", pszPackage)
		_ = pPackedContext; _ = Token; _ = phContext
		ctx.SetReturn(0) // SEC_E_OK
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
		phCredential := ctx.Arg(0)
		phContext := ctx.Arg(1)
		pszTargetName := ctx.Arg(2)
		fContextReq := ctx.Arg(3)
		Reserved1 := ctx.Arg(4)
		TargetDataRep := ctx.Arg(5)
		ravelog.Logf("[secur32] InitializeSecurityContextA cred=0x%x ctx=0x%x req=0x%x\n", phCredential, phContext, fContextReq)
		_ = pszTargetName; _ = Reserved1; _ = TargetDataRep
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InitializeSecurityContextW", func(ctx *ntapi.TrapContext) uint32 {
		phCredential := ctx.Arg(0)
		phContext := ctx.Arg(1)
		pszTargetName := ctx.Arg(2)
		fContextReq := ctx.Arg(3)
		Reserved1 := ctx.Arg(4)
		TargetDataRep := ctx.Arg(5)
		ravelog.Logf("[secur32] InitializeSecurityContextW cred=0x%x ctx=0x%x req=0x%x\n", phCredential, phContext, fContextReq)
		_ = pszTargetName; _ = Reserved1; _ = TargetDataRep
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaCallAuthenticationPackage", func(ctx *ntapi.TrapContext) uint32 {
		LsaHandle := ctx.Arg(0)
		AuthPackage := ctx.Arg(1)
		ProtocolSubmitBuffer := ctx.Arg(2)
		SubmitBufferLength := ctx.Arg(3)
		ProtocolReturnBuffer := ctx.Arg(4)
		ReturnBufferLength := ctx.Arg(5)
		ravelog.Logf("[secur32] LsaCallAuthenticationPackage handle=0x%x pkg=%d\n", LsaHandle, AuthPackage)
		_ = ProtocolSubmitBuffer; _ = SubmitBufferLength
		if ProtocolReturnBuffer != 0 { ctx.Mem.Write64(ProtocolReturnBuffer, 0) }
		if ReturnBufferLength != 0 { ctx.Mem.Write32(ReturnBufferLength, 0) }
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaConnectUntrusted", func(ctx *ntapi.TrapContext) uint32 {
		LsaHandle := ctx.Arg(0)
		ravelog.Logf("[secur32] LsaConnectUntrusted\n")
		if LsaHandle != 0 { ctx.Mem.Write64(LsaHandle, 0xDEAD0900) }
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaDeregisterLogonProcess", func(ctx *ntapi.TrapContext) uint32 {
		LsaHandle := ctx.Arg(0)
		ravelog.Logf("[secur32] LsaDeregisterLogonProcess handle=0x%x\n", LsaHandle)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaEnumerateLogonSessions", func(ctx *ntapi.TrapContext) uint32 {
		LogonSessionCount := ctx.Arg(0)
		LogonSessionList := ctx.Arg(1)
		ravelog.Logf("[secur32] LsaEnumerateLogonSessions\n")
		if LogonSessionCount != 0 { ctx.Mem.Write32(LogonSessionCount, 0) }
		if LogonSessionList != 0 { ctx.Mem.Write64(LogonSessionList, 0) }
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaFreeReturnBuffer", func(ctx *ntapi.TrapContext) uint32 {
		Buffer := ctx.Arg(0)
		ravelog.Logf("[secur32] LsaFreeReturnBuffer buf=0x%x\n", Buffer)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaGetLogonSessionData", func(ctx *ntapi.TrapContext) uint32 {
		LogonId := ctx.Arg(0)
		ppLogonSessionData := ctx.Arg(1)
		ravelog.Logf("[secur32] LsaGetLogonSessionData id=0x%x\n", LogonId)
		if ppLogonSessionData != 0 { ctx.Mem.Write64(ppLogonSessionData, 0) }
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaLogonUser", func(ctx *ntapi.TrapContext) uint32 {
		LsaHandle := ctx.Arg(0)
		OriginName := ctx.Arg(1)
		LogonType := ctx.Arg(2)
		AuthPackage := ctx.Arg(3)
		AuthInfo := ctx.Arg(4)
		AuthInfoLength := ctx.Arg(5)
		ravelog.Logf("[secur32] LsaLogonUser handle=0x%x type=%d pkg=%d\n", LsaHandle, LogonType, AuthPackage)
		_ = OriginName; _ = AuthInfo; _ = AuthInfoLength
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaLookupAuthenticationPackage", func(ctx *ntapi.TrapContext) uint32 {
		LsaHandle := ctx.Arg(0)
		PackageName := ctx.Arg(1)
		AuthPackage := ctx.Arg(2)
		ravelog.Logf("[secur32] LsaLookupAuthenticationPackage handle=0x%x\n", LsaHandle)
		_ = PackageName
		if AuthPackage != 0 { ctx.Mem.Write32(AuthPackage, 0) }
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaRegisterLogonProcess", func(ctx *ntapi.TrapContext) uint32 {
		LogonProcessName := ctx.Arg(0)
		LsaHandle := ctx.Arg(1)
		SecurityMode := ctx.Arg(2)
		ravelog.Logf("[secur32] LsaRegisterLogonProcess name=0x%x\n", LogonProcessName)
		_ = SecurityMode
		if LsaHandle != 0 { ctx.Mem.Write64(LsaHandle, 0xDEAD0901) }
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaRegisterPolicyChangeNotification", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[secur32] LsaRegisterPolicyChangeNotification p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "LsaUnregisterPolicyChangeNotification", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[secur32] LsaUnregisterPolicyChangeNotification p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "MakeSignature", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		fQOP := ctx.Arg(1)
		pMessage := ctx.Arg(2)
		MessageSeqNo := ctx.Arg(3)
		ravelog.Logf("[secur32] MakeSignature ctx=0x%x qop=0x%x seq=%d\n", phContext, fQOP, MessageSeqNo)
		_ = pMessage
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QueryContextAttributesA", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		ulAttribute := ctx.Arg(1)
		pBuffer := ctx.Arg(2)
		ravelog.Logf("[secur32] QueryContextAttributesA ctx=0x%x attr=%d\n", phContext, ulAttribute)
		_ = pBuffer
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QueryContextAttributesW", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		ulAttribute := ctx.Arg(1)
		pBuffer := ctx.Arg(2)
		ravelog.Logf("[secur32] QueryContextAttributesW ctx=0x%x attr=%d\n", phContext, ulAttribute)
		_ = pBuffer
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QueryCredentialsAttributesA", func(ctx *ntapi.TrapContext) uint32 {
		phCredential := ctx.Arg(0)
		ulAttribute := ctx.Arg(1)
		pBuffer := ctx.Arg(2)
		ravelog.Logf("[secur32] QueryCredentialsAttributesA cred=0x%x attr=%d\n", phCredential, ulAttribute)
		_ = pBuffer
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QueryCredentialsAttributesW", func(ctx *ntapi.TrapContext) uint32 {
		phCredential := ctx.Arg(0)
		ulAttribute := ctx.Arg(1)
		pBuffer := ctx.Arg(2)
		ravelog.Logf("[secur32] QueryCredentialsAttributesW cred=0x%x attr=%d\n", phCredential, ulAttribute)
		_ = pBuffer
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QuerySecurityContextToken", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		Token := ctx.Arg(1)
		ravelog.Logf("[secur32] QuerySecurityContextToken ctx=0x%x\n", phContext)
		if Token != 0 { ctx.Mem.Write64(Token, 0xDEAD0800) }
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QuerySecurityPackageInfoA", func(ctx *ntapi.TrapContext) uint32 {
		pszPackageName := ctx.Arg(0)
		ppPackageInfo := ctx.Arg(1)
		ravelog.Logf("[secur32] QuerySecurityPackageInfoA name=0x%x\n", pszPackageName)
		if ppPackageInfo != 0 { ctx.Mem.Write64(ppPackageInfo, 0) }
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QuerySecurityPackageInfoW", func(ctx *ntapi.TrapContext) uint32 {
		pszPackageName := ctx.Arg(0)
		ppPackageInfo := ctx.Arg(1)
		ravelog.Logf("[secur32] QuerySecurityPackageInfoW name=0x%x\n", pszPackageName)
		if ppPackageInfo != 0 { ctx.Mem.Write64(ppPackageInfo, 0) }
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "RevertSecurityContext", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		ravelog.Logf("[secur32] RevertSecurityContext ctx=0x%x\n", phContext)
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SealMessage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[secur32] SealMessage p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetContextAttributesA", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		ulAttribute := ctx.Arg(1)
		pBuffer := ctx.Arg(2)
		cbBuffer := ctx.Arg(3)
		ravelog.Logf("[secur32] SetContextAttributesA ctx=0x%x attr=%d\n", phContext, ulAttribute)
		_ = pBuffer; _ = cbBuffer
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetContextAttributesW", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		ulAttribute := ctx.Arg(1)
		pBuffer := ctx.Arg(2)
		cbBuffer := ctx.Arg(3)
		ravelog.Logf("[secur32] SetContextAttributesW ctx=0x%x attr=%d\n", phContext, ulAttribute)
		_ = pBuffer; _ = cbBuffer
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
	d.RegisterAutoStubHandler(dll, "TranslateNameA", func(ctx *ntapi.TrapContext) uint32 {
		lpAccountName := ctx.Arg(0)
		AccountNameFormat := ctx.Arg(1)
		DesiredNameFormat := ctx.Arg(2)
		lpTranslatedName := ctx.Arg(3)
		nSize := ctx.Arg(4)
		ravelog.Logf("[secur32] TranslateNameA from=%d to=%d\n", AccountNameFormat, DesiredNameFormat)
		_ = lpAccountName; _ = lpTranslatedName
		if nSize != 0 { ctx.Mem.Write32(nSize, 0) }
		ctx.SetReturn(0) // FALSE - translation not available
		return 0
	})
	d.RegisterAutoStubHandler(dll, "TranslateNameW", func(ctx *ntapi.TrapContext) uint32 {
		lpAccountName := ctx.Arg(0)
		AccountNameFormat := ctx.Arg(1)
		DesiredNameFormat := ctx.Arg(2)
		lpTranslatedName := ctx.Arg(3)
		nSize := ctx.Arg(4)
		ravelog.Logf("[secur32] TranslateNameW from=%d to=%d\n", AccountNameFormat, DesiredNameFormat)
		_ = lpAccountName; _ = lpTranslatedName
		if nSize != 0 { ctx.Mem.Write32(nSize, 0) }
		ctx.SetReturn(0) // FALSE - translation not available
		return 0
	})
	d.RegisterAutoStubHandler(dll, "UnsealMessage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[secur32] UnsealMessage p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "VerifySignature", func(ctx *ntapi.TrapContext) uint32 {
		phContext := ctx.Arg(0)
		pMessage := ctx.Arg(1)
		MessageSeqNo := ctx.Arg(2)
		pfQOP := ctx.Arg(3)
		ravelog.Logf("[secur32] VerifySignature ctx=0x%x seq=%d\n", phContext, MessageSeqNo)
		_ = pMessage
		if pfQOP != 0 { ctx.Mem.Write32(pfQOP, 0) }
		ctx.SetReturn(0) // SEC_E_OK
		return 0
	})
}
