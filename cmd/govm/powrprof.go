package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerPowrprofHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["powrprof.dll"]
	if !ok {
		return
	}
	_ = dll
	sharedHeapAlloc := hctx.HeapAlloc

	d.RegisterAutoStubHandler(dll, "CallNtPowerInformation", func(ctx *ntapi.TrapContext) uint32 {
		InformationLevel := ctx.Arg(0)
		InputBuffer := ctx.Arg(1)
		InputBufferLength := ctx.Arg(2)
		OutputBuffer := ctx.Arg(3)
		OutputBufferLength := ctx.Arg(4)
		ravelog.Logf("[powrprof] CallNtPowerInformation level=%d\n", InformationLevel)
		_ = InputBuffer; _ = InputBufferLength
		// Zero-fill output buffer
		if OutputBuffer != 0 {
			for i := uint64(0); i < OutputBufferLength; i++ { ctx.Mem.Write8(OutputBuffer+i, 0) }
		}
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CanUserWritePwrScheme", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[powrprof] CanUserWritePwrScheme()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DeletePwrScheme", func(ctx *ntapi.TrapContext) uint32 {
		uiID := ctx.Arg(0)
		ravelog.Logf("[powrprof] DeletePwrScheme id=%d\n", uiID)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EnumPwrSchemes", func(ctx *ntapi.TrapContext) uint32 {
		lpfnPwrSchemesEnumProc := ctx.Arg(0)
		lParam := ctx.Arg(1)
		ravelog.Logf("[powrprof] EnumPwrSchemes fn=0x%x\n", lpfnPwrSchemesEnumProc)
		_ = lParam
		ctx.SetReturn(1) // TRUE (0 schemes enumerated)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetActivePwrScheme", func(ctx *ntapi.TrapContext) uint32 {
		puiID := ctx.Arg(0)
		ravelog.Logf("[powrprof] GetActivePwrScheme\n")
		if puiID != 0 { ctx.Mem.Write32(puiID, 0) } // scheme 0 = Balanced
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetCurrentPowerPolicies", func(ctx *ntapi.TrapContext) uint32 {
		pGlobalPowerPolicy := ctx.Arg(0)
		pPowerPolicy := ctx.Arg(1)
		ravelog.Logf("[powrprof] GetCurrentPowerPolicies\n")
		if pGlobalPowerPolicy != 0 {
			for i := uint64(0); i < 128; i++ { ctx.Mem.Write8(pGlobalPowerPolicy+i, 0) }
		}
		if pPowerPolicy != 0 {
			for i := uint64(0); i < 256; i++ { ctx.Mem.Write8(pPowerPolicy+i, 0) }
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetPwrCapabilities", func(ctx *ntapi.TrapContext) uint32 {
		lpSystemPowerCapabilities := ctx.Arg(0)
		ravelog.Logf("[powrprof] GetPwrCapabilities\n")
		if lpSystemPowerCapabilities != 0 {
			// SYSTEM_POWER_CAPABILITIES: zero-fill then set key fields
			for i := uint64(0); i < 100; i++ { ctx.Mem.Write8(lpSystemPowerCapabilities+i, 0) }
			ctx.Mem.Write8(lpSystemPowerCapabilities, 1)   // PowerButtonPresent
			ctx.Mem.Write8(lpSystemPowerCapabilities+1, 0)  // SleepButtonPresent
			ctx.Mem.Write8(lpSystemPowerCapabilities+2, 0)  // LidPresent
			ctx.Mem.Write8(lpSystemPowerCapabilities+3, 1)  // SystemS1 (standby)
			ctx.Mem.Write8(lpSystemPowerCapabilities+7, 1)  // SystemS5 (soft off)
			ctx.Mem.Write8(lpSystemPowerCapabilities+12, 1) // ProcessorThrottle
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetPwrDiskSpindownRange", func(ctx *ntapi.TrapContext) uint32 {
		puiMax := ctx.Arg(0)
		puiMin := ctx.Arg(1)
		ravelog.Logf("[powrprof] GetPwrDiskSpindownRange\n")
		if puiMax != 0 { ctx.Mem.Write32(puiMax, 3600) } // 60 minutes
		if puiMin != 0 { ctx.Mem.Write32(puiMin, 0) }    // never
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "IsAdminOverrideActive", func(ctx *ntapi.TrapContext) uint32 {
		pScheme := ctx.Arg(0)
		ravelog.Logf("[powrprof] IsAdminOverrideActive scheme=0x%x\n", pScheme)
		_ = pScheme
		ctx.SetReturn(0) // FALSE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "IsPwrHibernateAllowed", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[powrprof] IsPwrHibernateAllowed()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "IsPwrShutdownAllowed", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[powrprof] IsPwrShutdownAllowed()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "IsPwrSuspendAllowed", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[powrprof] IsPwrSuspendAllowed()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerDeterminePlatformRole", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[powrprof] PowerDeterminePlatformRole()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerDeterminePlatformRoleEx", func(ctx *ntapi.TrapContext) uint32 {
		flags := ctx.Arg(0)
		ravelog.Logf("[powrprof] PowerDeterminePlatformRoleEx flags=0x%x\n", flags)
		_ = flags
		ctx.SetReturn(1) // PlatformRoleDesktop
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerEnumerate", func(ctx *ntapi.TrapContext) uint32 {
		RootPowerKey := ctx.Arg(0)
		SchemeGuid := ctx.Arg(1)
		SubGroupOfPowerSettingsGuid := ctx.Arg(2)
		AccessFlags := ctx.Arg(3)
		Index := ctx.Arg(4)
		Buffer := ctx.Arg(5)
		ravelog.Logf("[powrprof] PowerEnumerate flags=0x%x idx=%d\n", AccessFlags, Index)
		_ = RootPowerKey; _ = SchemeGuid; _ = SubGroupOfPowerSettingsGuid; _ = Buffer
		ctx.SetReturn(259) // ERROR_NO_MORE_ITEMS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerGetActiveScheme", func(ctx *ntapi.TrapContext) uint32 {
		RootPowerKey := ctx.Arg(0)
		ActivePolicyGuid := ctx.Arg(1)
		ravelog.Logf("[powrprof] PowerGetActiveScheme root=0x%x\n", RootPowerKey)
		// Write GUID_BALANCED_POWER_PLAN: {381b4222-f694-41f0-9685-ff5bb260df2e}
		if ActivePolicyGuid != 0 {
			buf := sharedHeapAlloc(16, true)
			ctx.Mem.Write32(buf, 0x381b4222)
			ctx.Mem.Write16(buf+4, 0xf694)
			ctx.Mem.Write16(buf+6, 0x41f0)
			ctx.Mem.Write8(buf+8, 0x96); ctx.Mem.Write8(buf+9, 0x85)
			ctx.Mem.Write8(buf+10, 0xff); ctx.Mem.Write8(buf+11, 0x5b)
			ctx.Mem.Write8(buf+12, 0xb2); ctx.Mem.Write8(buf+13, 0x60)
			ctx.Mem.Write8(buf+14, 0xdf); ctx.Mem.Write8(buf+15, 0x2e)
			ctx.Mem.Write64(ActivePolicyGuid, buf)
		}
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerSetActiveScheme", func(ctx *ntapi.TrapContext) uint32 {
		RootPowerKey := ctx.Arg(0)
		SchemeGuid := ctx.Arg(1)
		ravelog.Logf("[powrprof] PowerSetActiveScheme root=0x%x guid=0x%x\n", RootPowerKey, SchemeGuid)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerReadACValue", func(ctx *ntapi.TrapContext) uint32 {
		RootPowerKey := ctx.Arg(0)
		SchemeGuid := ctx.Arg(1)
		SubGroupGuid := ctx.Arg(2)
		PowerSettingGuid := ctx.Arg(3)
		Type := ctx.Arg(4)
		Buffer := ctx.Arg(5)
		ravelog.Logf("[powrprof] PowerReadACValue\n")
		_ = RootPowerKey; _ = SchemeGuid; _ = SubGroupGuid; _ = PowerSettingGuid
		if Type != 0 { ctx.Mem.Write32(Type, 4) } // REG_DWORD
		if Buffer != 0 { ctx.Mem.Write32(Buffer, 0) }
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerReadACValueIndex", func(ctx *ntapi.TrapContext) uint32 {
		rootKey := ctx.Arg(0)
		schemeGuid := ctx.Arg(1)
		subgroupGuid := ctx.Arg(2)
		settingGuid := ctx.Arg(3)
		valueIndex := ctx.Arg(4)
		ravelog.Logf("[powrprof] PowerReadACValueIndex root=0x%x scheme=0x%x sub=0x%x set=0x%x out=0x%x\n", rootKey, schemeGuid, subgroupGuid, settingGuid, valueIndex)
		if valueIndex != 0 { ctx.Mem.Write32(valueIndex, 0) }
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerReadDCValue", func(ctx *ntapi.TrapContext) uint32 {
		RootPowerKey := ctx.Arg(0)
		SchemeGuid := ctx.Arg(1)
		SubGroupGuid := ctx.Arg(2)
		PowerSettingGuid := ctx.Arg(3)
		Type := ctx.Arg(4)
		Buffer := ctx.Arg(5)
		ravelog.Logf("[powrprof] PowerReadDCValue\n")
		_ = RootPowerKey; _ = SchemeGuid; _ = SubGroupGuid; _ = PowerSettingGuid
		if Type != 0 { ctx.Mem.Write32(Type, 4) } // REG_DWORD
		if Buffer != 0 { ctx.Mem.Write32(Buffer, 0) } // value = 0
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerReadDCValueIndex", func(ctx *ntapi.TrapContext) uint32 {
		rootKey := ctx.Arg(0)
		schemeGuid := ctx.Arg(1)
		subgroupGuid := ctx.Arg(2)
		settingGuid := ctx.Arg(3)
		valueIndex := ctx.Arg(4)
		ravelog.Logf("[powrprof] PowerReadDCValueIndex root=0x%x scheme=0x%x sub=0x%x set=0x%x out=0x%x\n", rootKey, schemeGuid, subgroupGuid, settingGuid, valueIndex)
		if valueIndex != 0 { ctx.Mem.Write32(valueIndex, 0) }
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerReadFriendlyName", func(ctx *ntapi.TrapContext) uint32 {
		rootKey := ctx.Arg(0)
		schemeGuid := ctx.Arg(1)
		subgroupGuid := ctx.Arg(2)
		settingGuid := ctx.Arg(3)
		buffer := ctx.Arg(4)
		bufferSize := ctx.Arg(5)
		ravelog.Logf("[powrprof] PowerReadFriendlyName root=0x%x buf=0x%x\n", rootKey, buffer)
		_, _, _, _ = schemeGuid, subgroupGuid, settingGuid, buffer
		if bufferSize != 0 { ctx.Mem.Write32(bufferSize, 0) }
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerRegisterSuspendResumeNotification", func(ctx *ntapi.TrapContext) uint32 {
		Flags := ctx.Arg(0)
		Recipient := ctx.Arg(1)
		RegistrationHandle := ctx.Arg(2)
		ravelog.Logf("[powrprof] PowerRegisterSuspendResumeNotification flags=0x%x\n", Flags)
		_ = Recipient
		if RegistrationHandle != 0 { ctx.Mem.Write64(RegistrationHandle, 0xDEAD0701) }
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerUnregisterSuspendResumeNotification", func(ctx *ntapi.TrapContext) uint32 {
		RegistrationHandle := ctx.Arg(0)
		ravelog.Logf("[powrprof] PowerUnregisterSuspendResumeNotification handle=0x%x\n", RegistrationHandle)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerSettingRegisterNotification", func(ctx *ntapi.TrapContext) uint32 {
		SettingGuid := ctx.Arg(0)
		Flags := ctx.Arg(1)
		Recipient := ctx.Arg(2)
		RegistrationHandle := ctx.Arg(3)
		ravelog.Logf("[powrprof] PowerSettingRegisterNotification flags=0x%x\n", Flags)
		_ = SettingGuid; _ = Recipient
		if RegistrationHandle != 0 { ctx.Mem.Write64(RegistrationHandle, 0xDEAD0700) }
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerSettingUnregisterNotification", func(ctx *ntapi.TrapContext) uint32 {
		RegistrationHandle := ctx.Arg(0)
		ravelog.Logf("[powrprof] PowerSettingUnregisterNotification handle=0x%x\n", RegistrationHandle)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerWriteACValueIndex", func(ctx *ntapi.TrapContext) uint32 {
		RootPowerKey := ctx.Arg(0)
		SchemeGuid := ctx.Arg(1)
		SubGroupGuid := ctx.Arg(2)
		PowerSettingGuid := ctx.Arg(3)
		ACValueIndex := ctx.Arg(4)
		ravelog.Logf("[powrprof] PowerWriteACValueIndex val=%d\n", ACValueIndex)
		_ = RootPowerKey; _ = SchemeGuid; _ = SubGroupGuid; _ = PowerSettingGuid
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PowerWriteDCValueIndex", func(ctx *ntapi.TrapContext) uint32 {
		RootPowerKey := ctx.Arg(0)
		SchemeGuid := ctx.Arg(1)
		SubGroupGuid := ctx.Arg(2)
		PowerSettingGuid := ctx.Arg(3)
		DCValueIndex := ctx.Arg(4)
		ravelog.Logf("[powrprof] PowerWriteDCValueIndex val=%d\n", DCValueIndex)
		_ = RootPowerKey; _ = SchemeGuid; _ = SubGroupGuid; _ = PowerSettingGuid
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ReadGlobalPwrPolicy", func(ctx *ntapi.TrapContext) uint32 {
		pGlobalPowerPolicy := ctx.Arg(0)
		ravelog.Logf("[powrprof] ReadGlobalPwrPolicy\n")
		if pGlobalPowerPolicy != 0 {
			for i := uint64(0); i < 128; i++ { ctx.Mem.Write8(pGlobalPowerPolicy+i, 0) }
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ReadProcessorPwrScheme", func(ctx *ntapi.TrapContext) uint32 {
		uiID := ctx.Arg(0)
		pMachineProcessorPowerPolicy := ctx.Arg(1)
		ravelog.Logf("[powrprof] ReadProcessorPwrScheme id=%d\n", uiID)
		if pMachineProcessorPowerPolicy != 0 {
			for i := uint64(0); i < 64; i++ { ctx.Mem.Write8(pMachineProcessorPowerPolicy+i, 0) }
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ReadPwrScheme", func(ctx *ntapi.TrapContext) uint32 {
		uiID := ctx.Arg(0)
		pPowerPolicy := ctx.Arg(1)
		ravelog.Logf("[powrprof] ReadPwrScheme id=%d\n", uiID)
		if pPowerPolicy != 0 {
			for i := uint64(0); i < 256; i++ { ctx.Mem.Write8(pPowerPolicy+i, 0) }
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetActivePwrScheme", func(ctx *ntapi.TrapContext) uint32 {
		uiID := ctx.Arg(0)
		pGlobalPP := ctx.Arg(1)
		pPP := ctx.Arg(2)
		ravelog.Logf("[powrprof] SetActivePwrScheme id=%d\n", uiID)
		_ = pGlobalPP; _ = pPP
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetSuspendState", func(ctx *ntapi.TrapContext) uint32 {
		bHibernate := ctx.Arg(0)
		bForce := ctx.Arg(1)
		bWakeupEventsDisabled := ctx.Arg(2)
		ravelog.Logf("[powrprof] SetSuspendState hibernate=%d force=%d wakeup=%d\n", bHibernate, bForce, bWakeupEventsDisabled)
		ctx.SetReturn(1) // TRUE (pretend we suspended)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WriteGlobalPwrPolicy", func(ctx *ntapi.TrapContext) uint32 {
		pGlobalPowerPolicy := ctx.Arg(0)
		ravelog.Logf("[powrprof] WriteGlobalPwrPolicy\n")
		_ = pGlobalPowerPolicy
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WriteProcessorPwrScheme", func(ctx *ntapi.TrapContext) uint32 {
		uiID := ctx.Arg(0)
		pMachineProcessorPowerPolicy := ctx.Arg(1)
		ravelog.Logf("[powrprof] WriteProcessorPwrScheme id=%d\n", uiID)
		_ = pMachineProcessorPowerPolicy
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WritePwrScheme", func(ctx *ntapi.TrapContext) uint32 {
		puiID := ctx.Arg(0)
		lpszSchemeName := ctx.Arg(1)
		lpszDescription := ctx.Arg(2)
		lpScheme := ctx.Arg(3)
		ravelog.Logf("[powrprof] WritePwrScheme id=0x%x\n", puiID)
		_ = lpszSchemeName; _ = lpszDescription; _ = lpScheme
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "ValidatePowerPolicies", func(ctx *ntapi.TrapContext) uint32 {
		pGlobalPowerPolicy := ctx.Arg(0)
		pPowerPolicy := ctx.Arg(1)
		ravelog.Logf("[powrprof] ValidatePowerPolicies\n")
		_ = pGlobalPowerPolicy; _ = pPowerPolicy
		ctx.SetReturn(1) // TRUE - valid
		return 0
	})
}
