package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerSetupapiHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["setupapi.dll"]
	if !ok {
		return
	}
	_ = dll

	d.RegisterAutoStubHandler(dll, "CMP_GetBlockedDriverInfo", func(ctx *ntapi.TrapContext) uint32 {
		List := ctx.Arg(0)
		ListSize := ctx.Arg(1)
		Flags := ctx.Arg(2)
		hMachine := ctx.Arg(3)
		_ = List
		_ = ListSize
		_ = Flags
		_ = hMachine
		ravelog.Logf("[setupapi] CMP_GetBlockedDriverInfo List=0x%x ListSize=0x%x Flags=0x%x hMachine=0x%x\n", List, ListSize, Flags, hMachine)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_GetServerSideDeviceInstallFlags", func(ctx *ntapi.TrapContext) uint32 {
		Flags := ctx.Arg(0)
		MachineHandle := ctx.Arg(1)
		Reserved := ctx.Arg(2)
		_ = Flags
		_ = MachineHandle
		_ = Reserved
		ravelog.Logf("[setupapi] CMP_GetServerSideDeviceInstallFlags Flags=0x%x MachineHandle=0x%x Reserved=0x%x\n", Flags, MachineHandle, Reserved)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_Init_Detection", func(ctx *ntapi.TrapContext) uint32 {
		InitType := ctx.Arg(0)
		_ = InitType
		ravelog.Logf("[setupapi] CMP_Init_Detection InitType=0x%x\n", InitType)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_RegisterNotification", func(ctx *ntapi.TrapContext) uint32 {
		hRecipient := ctx.Arg(0)
		pNotificationFilter := ctx.Arg(1)
		ulFlags := ctx.Arg(2)
		phDevNotify := ctx.Arg(3)
		_ = hRecipient
		_ = pNotificationFilter
		_ = ulFlags
		_ = phDevNotify
		ravelog.Logf("[setupapi] CMP_RegisterNotification hRecipient=0x%x pNotificationFilter=0x%x ulFlags=0x%x phDevNotify=0x%x\n", hRecipient, pNotificationFilter, ulFlags, phDevNotify)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_Report_LogOn", func(ctx *ntapi.TrapContext) uint32 {
		CSDVersion := ctx.Arg(0)
		hMachine := ctx.Arg(1)
		_ = CSDVersion
		_ = hMachine
		ravelog.Logf("[setupapi] CMP_Report_LogOn CSDVersion=0x%x hMachine=0x%x\n", CSDVersion, hMachine)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_UnregisterNotification", func(ctx *ntapi.TrapContext) uint32 {
		hDevNotify := ctx.Arg(0)
		_ = hDevNotify
		ravelog.Logf("[setupapi] CMP_UnregisterNotification hDevNotify=0x%x\n", hDevNotify)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_WaitNoPendingInstallEvents", func(ctx *ntapi.TrapContext) uint32 {
		dwTimeout := ctx.Arg(0)
		_ = dwTimeout
		ravelog.Logf("[setupapi] CMP_WaitNoPendingInstallEvents dwTimeout=0x%x\n", dwTimeout)
		// WAIT_OBJECT_0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_WaitServicesAvailable", func(ctx *ntapi.TrapContext) uint32 {
		hMachine := ctx.Arg(0)
		_ = hMachine
		ravelog.Logf("[setupapi] CMP_WaitServicesAvailable hMachine=0x%x\n", hMachine)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_Empty_Log_Conf", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Add_Empty_Log_Conf arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_Empty_Log_Conf_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Add_Empty_Log_Conf_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_IDA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Add_IDA arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_IDW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Add_IDW arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_ID_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Add_ID_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_ID_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Add_ID_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_Range", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Add_Range arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_Res_Des", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Add_Res_Des arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_Res_Des_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Add_Res_Des_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Connect_MachineA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Connect_MachineA arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Connect_MachineW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Connect_MachineW arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Create_DevNodeA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Create_DevNodeA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Create_DevNodeW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Create_DevNodeW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Create_DevNode_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Create_DevNode_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Create_DevNode_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Create_DevNode_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Create_Range_List", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Create_Range_List arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Delete_Class_Key", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Delete_Class_Key arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Delete_Class_Key_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Delete_Class_Key_Ex arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Delete_DevNode_Key", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Delete_DevNode_Key arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Delete_DevNode_Key_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Delete_DevNode_Key_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Delete_Range", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Delete_Range arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Detect_Resource_Conflict", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Detect_Resource_Conflict arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Detect_Resource_Conflict_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Detect_Resource_Conflict_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Disable_DevNode", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Disable_DevNode arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Disable_DevNode_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Disable_DevNode_Ex arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Disconnect_Machine", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] CM_Disconnect_Machine arg0=0x%x\n", arg0)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Dup_Range_List", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Dup_Range_List arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enable_DevNode", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Enable_DevNode arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enable_DevNode_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Enable_DevNode_Ex arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enumerate_Classes", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Enumerate_Classes arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enumerate_Classes_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Enumerate_Classes_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enumerate_EnumeratorsA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Enumerate_EnumeratorsA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enumerate_EnumeratorsW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Enumerate_EnumeratorsW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enumerate_Enumerators_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Enumerate_Enumerators_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enumerate_Enumerators_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Enumerate_Enumerators_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Find_Range", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Find_Range arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_First_Range", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_First_Range arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Log_Conf", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Free_Log_Conf arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Log_Conf_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Free_Log_Conf_Ex arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Log_Conf_Handle", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] CM_Free_Log_Conf_Handle arg0=0x%x\n", arg0)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Range_List", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Free_Range_List arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Res_Des", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Free_Res_Des arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Res_Des_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Free_Res_Des_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Res_Des_Handle", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] CM_Free_Res_Des_Handle arg0=0x%x\n", arg0)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Resource_Conflict_Handle", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] CM_Free_Resource_Conflict_Handle arg0=0x%x\n", arg0)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Child", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Child arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Child_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Child_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Key_NameA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Class_Key_NameA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Key_NameW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Class_Key_NameW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Key_Name_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Class_Key_Name_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Key_Name_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Class_Key_Name_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_NameA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Class_NameA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_NameW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Class_NameW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Name_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Class_Name_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Name_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Class_Name_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Registry_PropertyA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_Class_Registry_PropertyA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Registry_PropertyW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_Class_Registry_PropertyW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Depth", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Depth arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Depth_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Depth_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Custom_PropertyA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_DevNode_Custom_PropertyA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Custom_PropertyW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_DevNode_Custom_PropertyW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Custom_Property_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_DevNode_Custom_Property_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Custom_Property_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_DevNode_Custom_Property_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Registry_PropertyA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_DevNode_Registry_PropertyA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Registry_PropertyW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_DevNode_Registry_PropertyW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Registry_Property_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_DevNode_Registry_Property_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Registry_Property_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_DevNode_Registry_Property_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Status", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_DevNode_Status arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Status_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_DevNode_Status_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_IDA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Device_IDA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_IDW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Device_IDW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Device_ID_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Device_ID_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_ListA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Device_ID_ListA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_ListW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Device_ID_ListW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_List_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Device_ID_List_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_List_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Device_ID_List_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_List_SizeA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Device_ID_List_SizeA arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_List_SizeW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Device_ID_List_SizeW arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_List_Size_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Device_ID_List_Size_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_List_Size_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Device_ID_List_Size_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_Size", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Device_ID_Size arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_Size_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Device_ID_Size_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_AliasA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_AliasA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_AliasW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_AliasW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_Alias_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_Alias_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_Alias_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_Alias_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_ListA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_ListA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_ListW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_ListW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_List_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_List_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_List_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_List_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_List_SizeA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_List_SizeA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_List_SizeW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_List_SizeW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_List_Size_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_List_Size_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_List_Size_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_List_Size_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_First_Log_Conf", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_First_Log_Conf arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_First_Log_Conf_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_First_Log_Conf_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Global_State", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Get_Global_State arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Global_State_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Global_State_Ex arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_HW_Prof_FlagsA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_HW_Prof_FlagsA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_HW_Prof_FlagsW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_HW_Prof_FlagsW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_HW_Prof_Flags_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_HW_Prof_Flags_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_HW_Prof_Flags_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_HW_Prof_Flags_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Hardware_Profile_InfoA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Hardware_Profile_InfoA arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Hardware_Profile_InfoW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Hardware_Profile_InfoW arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Hardware_Profile_Info_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Hardware_Profile_Info_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Hardware_Profile_Info_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Hardware_Profile_Info_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Log_Conf_Priority", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Log_Conf_Priority arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Log_Conf_Priority_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Log_Conf_Priority_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Next_Log_Conf", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Next_Log_Conf arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Next_Log_Conf_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Next_Log_Conf_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Next_Res_Des", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Next_Res_Des arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Next_Res_Des_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Get_Next_Res_Des_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Parent", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Parent arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Parent_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Parent_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Res_Des_Data", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Res_Des_Data arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Res_Des_Data_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Get_Res_Des_Data_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Res_Des_Data_Size", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Res_Des_Data_Size arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Res_Des_Data_Size_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Res_Des_Data_Size_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Resource_Conflict_Count", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Get_Resource_Conflict_Count arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Resource_Conflict_DetailsA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Resource_Conflict_DetailsA arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Resource_Conflict_DetailsW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Resource_Conflict_DetailsW arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Sibling", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Get_Sibling arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Sibling_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Get_Sibling_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Version", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] CM_Get_Version\n")
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Version_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] CM_Get_Version_Ex arg0=0x%x\n", arg0)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Intersect_Range_List", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Intersect_Range_List arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Invert_Range_List", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Invert_Range_List arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Is_Dock_Station_Present", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] CM_Is_Dock_Station_Present arg0=0x%x\n", arg0)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Is_Dock_Station_Present_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Is_Dock_Station_Present_Ex arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Is_Version_Available", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] CM_Is_Version_Available arg0=0x%x\n", arg0)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Is_Version_Available_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Is_Version_Available_Ex arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Locate_DevNodeA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Locate_DevNodeA arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Locate_DevNodeW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Locate_DevNodeW arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Locate_DevNode_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Locate_DevNode_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Locate_DevNode_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Locate_DevNode_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Merge_Range_List", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Merge_Range_List arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Modify_Res_Des", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Modify_Res_Des arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Modify_Res_Des_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Modify_Res_Des_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Move_DevNode", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Move_DevNode arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Move_DevNode_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Move_DevNode_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Next_Range", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Next_Range arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_NO_SUCH_VALUE/end of enumeration
		ctx.SetReturn(0x0D)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Open_Class_KeyA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Open_Class_KeyA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Open_Class_KeyW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Open_Class_KeyW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Open_Class_Key_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Open_Class_Key_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Open_Class_Key_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Open_Class_Key_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Open_DevNode_Key", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Open_DevNode_Key arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Open_DevNode_Key_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Open_DevNode_Key_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_And_Remove_SubTreeA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Query_And_Remove_SubTreeA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_And_Remove_SubTreeW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Query_And_Remove_SubTreeW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_And_Remove_SubTree_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Query_And_Remove_SubTree_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_And_Remove_SubTree_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Query_And_Remove_SubTree_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Arbitrator_Free_Data", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Query_Arbitrator_Free_Data arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Arbitrator_Free_Data_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Query_Arbitrator_Free_Data_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Arbitrator_Free_Size", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Query_Arbitrator_Free_Size arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Arbitrator_Free_Size_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Query_Arbitrator_Free_Size_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Remove_SubTree", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Query_Remove_SubTree arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Remove_SubTree_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Query_Remove_SubTree_Ex arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Resource_Conflict_List", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Query_Resource_Conflict_List arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Reenumerate_DevNode", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Reenumerate_DevNode arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Reenumerate_DevNode_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Reenumerate_DevNode_Ex arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Register_Device_Driver", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Register_Device_Driver arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Register_Device_Driver_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Register_Device_Driver_Ex arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Register_Device_InterfaceA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Register_Device_InterfaceA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Register_Device_InterfaceW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Register_Device_InterfaceW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Register_Device_Interface_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Register_Device_Interface_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Register_Device_Interface_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Register_Device_Interface_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Remove_SubTree", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Remove_SubTree arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Remove_SubTree_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Remove_SubTree_Ex arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Request_Device_EjectA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Request_Device_EjectA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Request_Device_EjectW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Request_Device_EjectW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Request_Device_Eject_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Request_Device_Eject_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Request_Device_Eject_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Request_Device_Eject_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Request_Eject_PC", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] CM_Request_Eject_PC\n")
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Request_Eject_PC_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] CM_Request_Eject_PC_Ex arg0=0x%x\n", arg0)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Run_Detection", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] CM_Run_Detection arg0=0x%x\n", arg0)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Run_Detection_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Run_Detection_Ex arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_Class_Registry_PropertyA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Set_Class_Registry_PropertyA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_Class_Registry_PropertyW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Set_Class_Registry_PropertyW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_DevNode_Problem", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Set_DevNode_Problem arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_DevNode_Problem_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Set_DevNode_Problem_Ex arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_DevNode_Registry_PropertyA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Set_DevNode_Registry_PropertyA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_DevNode_Registry_PropertyW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Set_DevNode_Registry_PropertyW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_DevNode_Registry_Property_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Set_DevNode_Registry_Property_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_DevNode_Registry_Property_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] CM_Set_DevNode_Registry_Property_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_HW_Prof", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Set_HW_Prof arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_HW_Prof_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Set_HW_Prof_Ex arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_HW_Prof_FlagsA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Set_HW_Prof_FlagsA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_HW_Prof_FlagsW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Set_HW_Prof_FlagsW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_HW_Prof_Flags_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Set_HW_Prof_Flags_ExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_HW_Prof_Flags_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] CM_Set_HW_Prof_Flags_ExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Setup_DevNode", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Setup_DevNode arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Setup_DevNode_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Setup_DevNode_Ex arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Test_Range_Available", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] CM_Test_Range_Available arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Uninstall_DevNode", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Uninstall_DevNode arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Uninstall_DevNode_Ex", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Uninstall_DevNode_Ex arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Unregister_Device_InterfaceA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Unregister_Device_InterfaceA arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Unregister_Device_InterfaceW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] CM_Unregister_Device_InterfaceW arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Unregister_Device_Interface_ExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Unregister_Device_Interface_ExA arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Unregister_Device_Interface_ExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] CM_Unregister_Device_Interface_ExW arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// CR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DoesUserHavePrivilege", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] DoesUserHavePrivilege arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InstallCatalog", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] InstallCatalog arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InstallHinfSection", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] InstallHinfSection arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InstallHinfSectionA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] InstallHinfSectionA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InstallHinfSectionW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] InstallHinfSectionW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "IsUserAdmin", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] IsUserAdmin\n")
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "MyFree", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] MyFree arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "MyMalloc", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] MyMalloc arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "MyRealloc", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] MyRealloc arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupAddInstallSectionToDiskSpaceListA", func(ctx *ntapi.TrapContext) uint32 {
		DiskSpace := ctx.Arg(0)
		InfHandle := ctx.Arg(1)
		LayoutInfHandle := ctx.Arg(2)
		SectionName := ctx.Arg(3)
		Reserved1 := ctx.Arg(4)
		Reserved2 := ctx.Arg(5)
		_ = DiskSpace
		_ = InfHandle
		_ = LayoutInfHandle
		_ = SectionName
		_ = Reserved1
		_ = Reserved2
		ravelog.Logf("[setupapi] SetupAddInstallSectionToDiskSpaceListA DiskSpace=0x%x InfHandle=0x%x LayoutInfHandle=0x%x SectionName=0x%x Reserved1=0x%x Reserved2=0x%x\n", DiskSpace, InfHandle, LayoutInfHandle, SectionName, Reserved1, Reserved2)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] -stub arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupAddToDiskSpaceListA", func(ctx *ntapi.TrapContext) uint32 {
		DiskSpace := ctx.Arg(0)
		TargetFilespec := ctx.Arg(1)
		TargetFileSize := ctx.Arg(2)
		Operation := ctx.Arg(3)
		Reserved1 := ctx.Arg(4)
		Reserved2 := ctx.Arg(5)
		_ = DiskSpace
		_ = TargetFilespec
		_ = TargetFileSize
		_ = Operation
		_ = Reserved1
		_ = Reserved2
		ravelog.Logf("[setupapi] SetupAddToDiskSpaceListA DiskSpace=0x%x TargetFilespec=0x%x TargetFileSize=0x%x Operation=0x%x Reserved1=0x%x Reserved2=0x%x\n", DiskSpace, TargetFilespec, TargetFileSize, Operation, Reserved1, Reserved2)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupAddToDiskSpaceListW", func(ctx *ntapi.TrapContext) uint32 {
		DiskSpace := ctx.Arg(0)
		TargetFilespec := ctx.Arg(1)
		TargetFileSize := ctx.Arg(2)
		Operation := ctx.Arg(3)
		Reserved1 := ctx.Arg(4)
		Reserved2 := ctx.Arg(5)
		_ = DiskSpace
		_ = TargetFilespec
		_ = TargetFileSize
		_ = Operation
		_ = Reserved1
		_ = Reserved2
		ravelog.Logf("[setupapi] SetupAddToDiskSpaceListW DiskSpace=0x%x TargetFilespec=0x%x TargetFileSize=0x%x Operation=0x%x Reserved1=0x%x Reserved2=0x%x\n", DiskSpace, TargetFilespec, TargetFileSize, Operation, Reserved1, Reserved2)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupAddToSourceListA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] SetupAddToSourceListA arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupAddToSourceListW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] SetupAddToSourceListW arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCloseFileQueue", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		_ = QueueHandle
		ravelog.Logf("[setupapi] SetupCloseFileQueue QueueHandle=0x%x\n", QueueHandle)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCloseInfFile", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		_ = InfHandle
		ravelog.Logf("[setupapi] SetupCloseInfFile InfHandle=0x%x\n", InfHandle)
		// void/0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCloseLog", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] SetupCloseLog\n")
		// void/0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCommitFileQueue", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] SetupCommitFileQueue arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCommitFileQueueA", func(ctx *ntapi.TrapContext) uint32 {
		Owner := ctx.Arg(0)
		QueueHandle := ctx.Arg(1)
		MsgHandler := ctx.Arg(2)
		Context := ctx.Arg(3)
		_ = Owner
		_ = QueueHandle
		_ = MsgHandler
		_ = Context
		ravelog.Logf("[setupapi] SetupCommitFileQueueA Owner=0x%x QueueHandle=0x%x MsgHandler=0x%x Context=0x%x\n", Owner, QueueHandle, MsgHandler, Context)
		// TRUE/no files to commit
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCommitFileQueueW", func(ctx *ntapi.TrapContext) uint32 {
		Owner := ctx.Arg(0)
		QueueHandle := ctx.Arg(1)
		MsgHandler := ctx.Arg(2)
		Context := ctx.Arg(3)
		_ = Owner
		_ = QueueHandle
		_ = MsgHandler
		_ = Context
		ravelog.Logf("[setupapi] SetupCommitFileQueueW Owner=0x%x QueueHandle=0x%x MsgHandler=0x%x Context=0x%x\n", Owner, QueueHandle, MsgHandler, Context)
		// TRUE/no files to commit
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCopyErrorA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupCopyErrorA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCopyErrorW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupCopyErrorW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCopyOEMInfA", func(ctx *ntapi.TrapContext) uint32 {
		SourceInfFileName := ctx.Arg(0)
		OEMSourceMediaLocation := ctx.Arg(1)
		OEMSourceMediaType := ctx.Arg(2)
		CopyStyle := ctx.Arg(3)
		DestinationInfFileName := ctx.Arg(4)
		DestinationInfFileNameSize := ctx.Arg(5)
		_ = SourceInfFileName
		_ = OEMSourceMediaLocation
		_ = OEMSourceMediaType
		_ = CopyStyle
		_ = DestinationInfFileName
		_ = DestinationInfFileNameSize
		ravelog.Logf("[setupapi] SetupCopyOEMInfA SourceInfFileName=0x%x OEMSourceMediaLocation=0x%x OEMSourceMediaType=0x%x CopyStyle=0x%x DestinationInfFileName=0x%x DestinationInfFileNameSize=0x%x\n", SourceInfFileName, OEMSourceMediaLocation, OEMSourceMediaType, CopyStyle, DestinationInfFileName, DestinationInfFileNameSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCopyOEMInfW", func(ctx *ntapi.TrapContext) uint32 {
		SourceInfFileName := ctx.Arg(0)
		OEMSourceMediaLocation := ctx.Arg(1)
		OEMSourceMediaType := ctx.Arg(2)
		CopyStyle := ctx.Arg(3)
		DestinationInfFileName := ctx.Arg(4)
		DestinationInfFileNameSize := ctx.Arg(5)
		_ = SourceInfFileName
		_ = OEMSourceMediaLocation
		_ = OEMSourceMediaType
		_ = CopyStyle
		_ = DestinationInfFileName
		_ = DestinationInfFileNameSize
		ravelog.Logf("[setupapi] SetupCopyOEMInfW SourceInfFileName=0x%x OEMSourceMediaLocation=0x%x OEMSourceMediaType=0x%x CopyStyle=0x%x DestinationInfFileName=0x%x DestinationInfFileNameSize=0x%x\n", SourceInfFileName, OEMSourceMediaLocation, OEMSourceMediaType, CopyStyle, DestinationInfFileName, DestinationInfFileNameSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCreateDiskSpaceListA", func(ctx *ntapi.TrapContext) uint32 {
		Reserved1 := ctx.Arg(0)
		Reserved2 := ctx.Arg(1)
		Flags := ctx.Arg(2)
		_ = Reserved1
		_ = Reserved2
		_ = Flags
		ravelog.Logf("[setupapi] SetupCreateDiskSpaceListA Reserved1=0x%x Reserved2=0x%x Flags=0x%x\n", Reserved1, Reserved2, Flags)
		// fake disk space handle
		ctx.SetReturn(0xDEAD0010)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCreateDiskSpaceListW", func(ctx *ntapi.TrapContext) uint32 {
		Reserved1 := ctx.Arg(0)
		Reserved2 := ctx.Arg(1)
		Flags := ctx.Arg(2)
		_ = Reserved1
		_ = Reserved2
		_ = Flags
		ravelog.Logf("[setupapi] SetupCreateDiskSpaceListW Reserved1=0x%x Reserved2=0x%x Flags=0x%x\n", Reserved1, Reserved2, Flags)
		// fake disk space handle
		ctx.SetReturn(0xDEAD0010)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDecompressOrCopyFileA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] SetupDecompressOrCopyFileA arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDecompressOrCopyFileW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] SetupDecompressOrCopyFileW arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDefaultQueueCallback", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] SetupDefaultQueueCallback arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDefaultQueueCallbackA", func(ctx *ntapi.TrapContext) uint32 {
		Context := ctx.Arg(0)
		Notification := ctx.Arg(1)
		Param1 := ctx.Arg(2)
		Param2 := ctx.Arg(3)
		_ = Context
		_ = Notification
		_ = Param1
		_ = Param2
		ravelog.Logf("[setupapi] SetupDefaultQueueCallbackA Context=0x%x Notification=0x%x Param1=0x%x Param2=0x%x\n", Context, Notification, Param1, Param2)
		// FILEOP_SKIP
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDefaultQueueCallbackW", func(ctx *ntapi.TrapContext) uint32 {
		Context := ctx.Arg(0)
		Notification := ctx.Arg(1)
		Param1 := ctx.Arg(2)
		Param2 := ctx.Arg(3)
		_ = Context
		_ = Notification
		_ = Param1
		_ = Param2
		ravelog.Logf("[setupapi] SetupDefaultQueueCallbackW Context=0x%x Notification=0x%x Param1=0x%x Param2=0x%x\n", Context, Notification, Param1, Param2)
		// FILEOP_SKIP
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDeleteErrorA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] SetupDeleteErrorA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDeleteErrorW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] SetupDeleteErrorW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDestroyDiskSpaceList", func(ctx *ntapi.TrapContext) uint32 {
		DiskSpace := ctx.Arg(0)
		_ = DiskSpace
		ravelog.Logf("[setupapi] SetupDestroyDiskSpaceList DiskSpace=0x%x\n", DiskSpace)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiBuildClassInfoList", func(ctx *ntapi.TrapContext) uint32 {
		Flags := ctx.Arg(0)
		ClassGuidList := ctx.Arg(1)
		ClassGuidListSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		_ = Flags
		_ = ClassGuidList
		_ = ClassGuidListSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiBuildClassInfoList Flags=0x%x ClassGuidList=0x%x ClassGuidListSize=0x%x RequiredSize=0x%x\n", Flags, ClassGuidList, ClassGuidListSize, RequiredSize)
		// FALSE/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiBuildClassInfoListExA", func(ctx *ntapi.TrapContext) uint32 {
		Flags := ctx.Arg(0)
		ClassGuidList := ctx.Arg(1)
		ClassGuidListSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		MachineName := ctx.Arg(4)
		Reserved := ctx.Arg(5)
		_ = Flags
		_ = ClassGuidList
		_ = ClassGuidListSize
		_ = RequiredSize
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiBuildClassInfoListExA Flags=0x%x ClassGuidList=0x%x ClassGuidListSize=0x%x RequiredSize=0x%x MachineName=0x%x Reserved=0x%x\n", Flags, ClassGuidList, ClassGuidListSize, RequiredSize, MachineName, Reserved)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiBuildClassInfoListExW", func(ctx *ntapi.TrapContext) uint32 {
		Flags := ctx.Arg(0)
		ClassGuidList := ctx.Arg(1)
		ClassGuidListSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		MachineName := ctx.Arg(4)
		Reserved := ctx.Arg(5)
		_ = Flags
		_ = ClassGuidList
		_ = ClassGuidListSize
		_ = RequiredSize
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiBuildClassInfoListExW Flags=0x%x ClassGuidList=0x%x ClassGuidListSize=0x%x RequiredSize=0x%x MachineName=0x%x Reserved=0x%x\n", Flags, ClassGuidList, ClassGuidListSize, RequiredSize, MachineName, Reserved)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiBuildDriverInfoList", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DriverType := ctx.Arg(2)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DriverType
		ravelog.Logf("[setupapi] SetupDiBuildDriverInfoList DeviceInfoSet=0x%x DeviceInfoData=0x%x DriverType=0x%x\n", DeviceInfoSet, DeviceInfoData, DriverType)
		// FALSE/no drivers
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCallClassInstaller", func(ctx *ntapi.TrapContext) uint32 {
		InstallFunction := ctx.Arg(0)
		DeviceInfoSet := ctx.Arg(1)
		DeviceInfoData := ctx.Arg(2)
		_ = InstallFunction
		_ = DeviceInfoSet
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiCallClassInstaller InstallFunction=0x%x DeviceInfoSet=0x%x DeviceInfoData=0x%x\n", InstallFunction, DeviceInfoSet, DeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiChangeState", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiChangeState DeviceInfoSet=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassGuidsFromNameA", func(ctx *ntapi.TrapContext) uint32 {
		ClassName := ctx.Arg(0)
		ClassGuidList := ctx.Arg(1)
		ClassGuidListSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		_ = ClassName
		_ = ClassGuidList
		_ = ClassGuidListSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiClassGuidsFromNameA ClassName=0x%x ClassGuidList=0x%x ClassGuidListSize=0x%x RequiredSize=0x%x\n", ClassName, ClassGuidList, ClassGuidListSize, RequiredSize)
		// FALSE/no class
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassGuidsFromNameExA", func(ctx *ntapi.TrapContext) uint32 {
		ClassName := ctx.Arg(0)
		ClassGuidList := ctx.Arg(1)
		ClassGuidListSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		MachineName := ctx.Arg(4)
		Reserved := ctx.Arg(5)
		_ = ClassName
		_ = ClassGuidList
		_ = ClassGuidListSize
		_ = RequiredSize
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiClassGuidsFromNameExA ClassName=0x%x ClassGuidList=0x%x ClassGuidListSize=0x%x RequiredSize=0x%x MachineName=0x%x Reserved=0x%x\n", ClassName, ClassGuidList, ClassGuidListSize, RequiredSize, MachineName, Reserved)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassGuidsFromNameExW", func(ctx *ntapi.TrapContext) uint32 {
		ClassName := ctx.Arg(0)
		ClassGuidList := ctx.Arg(1)
		ClassGuidListSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		MachineName := ctx.Arg(4)
		Reserved := ctx.Arg(5)
		_ = ClassName
		_ = ClassGuidList
		_ = ClassGuidListSize
		_ = RequiredSize
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiClassGuidsFromNameExW ClassName=0x%x ClassGuidList=0x%x ClassGuidListSize=0x%x RequiredSize=0x%x MachineName=0x%x Reserved=0x%x\n", ClassName, ClassGuidList, ClassGuidListSize, RequiredSize, MachineName, Reserved)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassGuidsFromNameW", func(ctx *ntapi.TrapContext) uint32 {
		ClassName := ctx.Arg(0)
		ClassGuidList := ctx.Arg(1)
		ClassGuidListSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		_ = ClassName
		_ = ClassGuidList
		_ = ClassGuidListSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiClassGuidsFromNameW ClassName=0x%x ClassGuidList=0x%x ClassGuidListSize=0x%x RequiredSize=0x%x\n", ClassName, ClassGuidList, ClassGuidListSize, RequiredSize)
		// FALSE/no class
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassNameFromGuidA", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		ClassName := ctx.Arg(1)
		ClassNameSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		_ = ClassGuid
		_ = ClassName
		_ = ClassNameSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiClassNameFromGuidA ClassGuid=0x%x ClassName=0x%x ClassNameSize=0x%x RequiredSize=0x%x\n", ClassGuid, ClassName, ClassNameSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassNameFromGuidExA", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		ClassName := ctx.Arg(1)
		ClassNameSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		MachineName := ctx.Arg(4)
		Reserved := ctx.Arg(5)
		_ = ClassGuid
		_ = ClassName
		_ = ClassNameSize
		_ = RequiredSize
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiClassNameFromGuidExA ClassGuid=0x%x ClassName=0x%x ClassNameSize=0x%x RequiredSize=0x%x MachineName=0x%x Reserved=0x%x\n", ClassGuid, ClassName, ClassNameSize, RequiredSize, MachineName, Reserved)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassNameFromGuidExW", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		ClassName := ctx.Arg(1)
		ClassNameSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		MachineName := ctx.Arg(4)
		Reserved := ctx.Arg(5)
		_ = ClassGuid
		_ = ClassName
		_ = ClassNameSize
		_ = RequiredSize
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiClassNameFromGuidExW ClassGuid=0x%x ClassName=0x%x ClassNameSize=0x%x RequiredSize=0x%x MachineName=0x%x Reserved=0x%x\n", ClassGuid, ClassName, ClassNameSize, RequiredSize, MachineName, Reserved)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassNameFromGuidW", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		ClassName := ctx.Arg(1)
		ClassNameSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		_ = ClassGuid
		_ = ClassName
		_ = ClassNameSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiClassNameFromGuidW ClassGuid=0x%x ClassName=0x%x ClassNameSize=0x%x RequiredSize=0x%x\n", ClassGuid, ClassName, ClassNameSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDevRegKeyA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		Scope := ctx.Arg(2)
		HwProfile := ctx.Arg(3)
		KeyType := ctx.Arg(4)
		InfHandle := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = Scope
		_ = HwProfile
		_ = KeyType
		_ = InfHandle
		ravelog.Logf("[setupapi] SetupDiCreateDevRegKeyA DeviceInfoSet=0x%x DeviceInfoData=0x%x Scope=0x%x HwProfile=0x%x KeyType=0x%x InfHandle=0x%x\n", DeviceInfoSet, DeviceInfoData, Scope, HwProfile, KeyType, InfHandle)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDevRegKeyW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		Scope := ctx.Arg(2)
		HwProfile := ctx.Arg(3)
		KeyType := ctx.Arg(4)
		InfHandle := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = Scope
		_ = HwProfile
		_ = KeyType
		_ = InfHandle
		ravelog.Logf("[setupapi] SetupDiCreateDevRegKeyW DeviceInfoSet=0x%x DeviceInfoData=0x%x Scope=0x%x HwProfile=0x%x KeyType=0x%x InfHandle=0x%x\n", DeviceInfoSet, DeviceInfoData, Scope, HwProfile, KeyType, InfHandle)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInfoA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceName := ctx.Arg(1)
		ClassGuid := ctx.Arg(2)
		DeviceDescription := ctx.Arg(3)
		hwndParent := ctx.Arg(4)
		CreationFlags := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceName
		_ = ClassGuid
		_ = DeviceDescription
		_ = hwndParent
		_ = CreationFlags
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInfoA DeviceInfoSet=0x%x DeviceName=0x%x ClassGuid=0x%x DeviceDescription=0x%x hwndParent=0x%x CreationFlags=0x%x\n", DeviceInfoSet, DeviceName, ClassGuid, DeviceDescription, hwndParent, CreationFlags)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInfoList", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		hwndParent := ctx.Arg(1)
		_ = ClassGuid
		_ = hwndParent
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInfoList ClassGuid=0x%x hwndParent=0x%x\n", ClassGuid, hwndParent)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInfoListExA", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		hwndParent := ctx.Arg(1)
		MachineName := ctx.Arg(2)
		Reserved := ctx.Arg(3)
		_ = ClassGuid
		_ = hwndParent
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInfoListExA ClassGuid=0x%x hwndParent=0x%x MachineName=0x%x Reserved=0x%x\n", ClassGuid, hwndParent, MachineName, Reserved)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInfoListExW", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		hwndParent := ctx.Arg(1)
		MachineName := ctx.Arg(2)
		Reserved := ctx.Arg(3)
		_ = ClassGuid
		_ = hwndParent
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInfoListExW ClassGuid=0x%x hwndParent=0x%x MachineName=0x%x Reserved=0x%x\n", ClassGuid, hwndParent, MachineName, Reserved)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInfoW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceName := ctx.Arg(1)
		ClassGuid := ctx.Arg(2)
		DeviceDescription := ctx.Arg(3)
		hwndParent := ctx.Arg(4)
		CreationFlags := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceName
		_ = ClassGuid
		_ = DeviceDescription
		_ = hwndParent
		_ = CreationFlags
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInfoW DeviceInfoSet=0x%x DeviceName=0x%x ClassGuid=0x%x DeviceDescription=0x%x hwndParent=0x%x CreationFlags=0x%x\n", DeviceInfoSet, DeviceName, ClassGuid, DeviceDescription, hwndParent, CreationFlags)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInterfaceA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		InterfaceClassGuid := ctx.Arg(2)
		ReferenceString := ctx.Arg(3)
		CreationFlags := ctx.Arg(4)
		DeviceInterfaceData := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = InterfaceClassGuid
		_ = ReferenceString
		_ = CreationFlags
		_ = DeviceInterfaceData
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInterfaceA DeviceInfoSet=0x%x DeviceInfoData=0x%x InterfaceClassGuid=0x%x ReferenceString=0x%x CreationFlags=0x%x DeviceInterfaceData=0x%x\n", DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, ReferenceString, CreationFlags, DeviceInterfaceData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInterfaceRegKeyA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInterfaceRegKeyA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInterfaceRegKeyW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInterfaceRegKeyW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInterfaceW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		InterfaceClassGuid := ctx.Arg(2)
		ReferenceString := ctx.Arg(3)
		CreationFlags := ctx.Arg(4)
		DeviceInterfaceData := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = InterfaceClassGuid
		_ = ReferenceString
		_ = CreationFlags
		_ = DeviceInterfaceData
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInterfaceW DeviceInfoSet=0x%x DeviceInfoData=0x%x InterfaceClassGuid=0x%x ReferenceString=0x%x CreationFlags=0x%x DeviceInterfaceData=0x%x\n", DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, ReferenceString, CreationFlags, DeviceInterfaceData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDeleteDevRegKey", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		Scope := ctx.Arg(2)
		HwProfile := ctx.Arg(3)
		KeyType := ctx.Arg(4)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = Scope
		_ = HwProfile
		_ = KeyType
		ravelog.Logf("[setupapi] SetupDiDeleteDevRegKey DeviceInfoSet=0x%x DeviceInfoData=0x%x Scope=0x%x HwProfile=0x%x KeyType=0x%x\n", DeviceInfoSet, DeviceInfoData, Scope, HwProfile, KeyType)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDeleteDeviceInfo", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiDeleteDeviceInfo DeviceInfoSet=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDeleteDeviceInterfaceData", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInterfaceData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInterfaceData
		ravelog.Logf("[setupapi] SetupDiDeleteDeviceInterfaceData DeviceInfoSet=0x%x DeviceInterfaceData=0x%x\n", DeviceInfoSet, DeviceInterfaceData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDeleteDeviceInterfaceRegKey", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] SetupDiDeleteDeviceInterfaceRegKey arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDestroyClassImageList", func(ctx *ntapi.TrapContext) uint32 {
		ClassImageListData := ctx.Arg(0)
		_ = ClassImageListData
		ravelog.Logf("[setupapi] SetupDiDestroyClassImageList ClassImageListData=0x%x\n", ClassImageListData)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDestroyDeviceInfoList", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		_ = DeviceInfoSet
		ravelog.Logf("[setupapi] SetupDiDestroyDeviceInfoList DeviceInfoSet=0x%x\n", DeviceInfoSet)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDestroyDriverInfoList", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DriverType := ctx.Arg(2)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DriverType
		ravelog.Logf("[setupapi] SetupDiDestroyDriverInfoList DeviceInfoSet=0x%x DeviceInfoData=0x%x DriverType=0x%x\n", DeviceInfoSet, DeviceInfoData, DriverType)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiEnumDeviceInfo", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		MemberIndex := ctx.Arg(1)
		DeviceInfoData := ctx.Arg(2)
		_ = DeviceInfoSet
		_ = MemberIndex
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiEnumDeviceInfo DeviceInfoSet=0x%x MemberIndex=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, MemberIndex, DeviceInfoData)
		// FALSE/no more items
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiEnumDeviceInterfaces", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		InterfaceClassGuid := ctx.Arg(2)
		MemberIndex := ctx.Arg(3)
		DeviceInterfaceData := ctx.Arg(4)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = InterfaceClassGuid
		_ = MemberIndex
		_ = DeviceInterfaceData
		ravelog.Logf("[setupapi] SetupDiEnumDeviceInterfaces DeviceInfoSet=0x%x DeviceInfoData=0x%x InterfaceClassGuid=0x%x MemberIndex=0x%x DeviceInterfaceData=0x%x\n", DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, MemberIndex, DeviceInterfaceData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiEnumDriverInfoA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DriverType := ctx.Arg(2)
		MemberIndex := ctx.Arg(3)
		DriverInfoData := ctx.Arg(4)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DriverType
		_ = MemberIndex
		_ = DriverInfoData
		ravelog.Logf("[setupapi] SetupDiEnumDriverInfoA DeviceInfoSet=0x%x DeviceInfoData=0x%x DriverType=0x%x MemberIndex=0x%x DriverInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData, DriverType, MemberIndex, DriverInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiEnumDriverInfoW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DriverType := ctx.Arg(2)
		MemberIndex := ctx.Arg(3)
		DriverInfoData := ctx.Arg(4)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DriverType
		_ = MemberIndex
		_ = DriverInfoData
		ravelog.Logf("[setupapi] SetupDiEnumDriverInfoW DeviceInfoSet=0x%x DeviceInfoData=0x%x DriverType=0x%x MemberIndex=0x%x DriverInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData, DriverType, MemberIndex, DriverInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetActualSectionToInstallA", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		InfSectionName := ctx.Arg(1)
		InfSectionWithExt := ctx.Arg(2)
		InfSectionWithExtSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		Extension := ctx.Arg(5)
		_ = InfHandle
		_ = InfSectionName
		_ = InfSectionWithExt
		_ = InfSectionWithExtSize
		_ = RequiredSize
		_ = Extension
		ravelog.Logf("[setupapi] SetupDiGetActualSectionToInstallA InfHandle=0x%x InfSectionName=0x%x InfSectionWithExt=0x%x InfSectionWithExtSize=0x%x RequiredSize=0x%x Extension=0x%x\n", InfHandle, InfSectionName, InfSectionWithExt, InfSectionWithExtSize, RequiredSize, Extension)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetActualSectionToInstallExA", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		InfSectionName := ctx.Arg(1)
		AlternatePlatformInfo := ctx.Arg(2)
		InfSectionWithExt := ctx.Arg(3)
		InfSectionWithExtSize := ctx.Arg(4)
		RequiredSize := ctx.Arg(5)
		_ = InfHandle
		_ = InfSectionName
		_ = AlternatePlatformInfo
		_ = InfSectionWithExt
		_ = InfSectionWithExtSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiGetActualSectionToInstallExA InfHandle=0x%x InfSectionName=0x%x AlternatePlatformInfo=0x%x InfSectionWithExt=0x%x InfSectionWithExtSize=0x%x RequiredSize=0x%x\n", InfHandle, InfSectionName, AlternatePlatformInfo, InfSectionWithExt, InfSectionWithExtSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetActualSectionToInstallExW", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		InfSectionName := ctx.Arg(1)
		AlternatePlatformInfo := ctx.Arg(2)
		InfSectionWithExt := ctx.Arg(3)
		InfSectionWithExtSize := ctx.Arg(4)
		RequiredSize := ctx.Arg(5)
		_ = InfHandle
		_ = InfSectionName
		_ = AlternatePlatformInfo
		_ = InfSectionWithExt
		_ = InfSectionWithExtSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiGetActualSectionToInstallExW InfHandle=0x%x InfSectionName=0x%x AlternatePlatformInfo=0x%x InfSectionWithExt=0x%x InfSectionWithExtSize=0x%x RequiredSize=0x%x\n", InfHandle, InfSectionName, AlternatePlatformInfo, InfSectionWithExt, InfSectionWithExtSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetActualSectionToInstallW", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		InfSectionName := ctx.Arg(1)
		InfSectionWithExt := ctx.Arg(2)
		InfSectionWithExtSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		Extension := ctx.Arg(5)
		_ = InfHandle
		_ = InfSectionName
		_ = InfSectionWithExt
		_ = InfSectionWithExtSize
		_ = RequiredSize
		_ = Extension
		ravelog.Logf("[setupapi] SetupDiGetActualSectionToInstallW InfHandle=0x%x InfSectionName=0x%x InfSectionWithExt=0x%x InfSectionWithExtSize=0x%x RequiredSize=0x%x Extension=0x%x\n", InfHandle, InfSectionName, InfSectionWithExt, InfSectionWithExtSize, RequiredSize, Extension)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDescriptionA", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		ClassDescription := ctx.Arg(1)
		ClassDescriptionSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		_ = ClassGuid
		_ = ClassDescription
		_ = ClassDescriptionSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiGetClassDescriptionA ClassGuid=0x%x ClassDescription=0x%x ClassDescriptionSize=0x%x RequiredSize=0x%x\n", ClassGuid, ClassDescription, ClassDescriptionSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDescriptionExA", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		ClassDescription := ctx.Arg(1)
		ClassDescriptionSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		MachineName := ctx.Arg(4)
		Reserved := ctx.Arg(5)
		_ = ClassGuid
		_ = ClassDescription
		_ = ClassDescriptionSize
		_ = RequiredSize
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiGetClassDescriptionExA ClassGuid=0x%x ClassDescription=0x%x ClassDescriptionSize=0x%x RequiredSize=0x%x MachineName=0x%x Reserved=0x%x\n", ClassGuid, ClassDescription, ClassDescriptionSize, RequiredSize, MachineName, Reserved)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDescriptionExW", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		ClassDescription := ctx.Arg(1)
		ClassDescriptionSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		MachineName := ctx.Arg(4)
		Reserved := ctx.Arg(5)
		_ = ClassGuid
		_ = ClassDescription
		_ = ClassDescriptionSize
		_ = RequiredSize
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiGetClassDescriptionExW ClassGuid=0x%x ClassDescription=0x%x ClassDescriptionSize=0x%x RequiredSize=0x%x MachineName=0x%x Reserved=0x%x\n", ClassGuid, ClassDescription, ClassDescriptionSize, RequiredSize, MachineName, Reserved)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDescriptionW", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		ClassDescription := ctx.Arg(1)
		ClassDescriptionSize := ctx.Arg(2)
		RequiredSize := ctx.Arg(3)
		_ = ClassGuid
		_ = ClassDescription
		_ = ClassDescriptionSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiGetClassDescriptionW ClassGuid=0x%x ClassDescription=0x%x ClassDescriptionSize=0x%x RequiredSize=0x%x\n", ClassGuid, ClassDescription, ClassDescriptionSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDevPropertySheetsA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupDiGetClassDevPropertySheetsA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDevPropertySheetsW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupDiGetClassDevPropertySheetsW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDevsA", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		Enumerator := ctx.Arg(1)
		hwndParent := ctx.Arg(2)
		Flags := ctx.Arg(3)
		_ = ClassGuid
		_ = Enumerator
		_ = hwndParent
		_ = Flags
		ravelog.Logf("[setupapi] SetupDiGetClassDevsA ClassGuid=0x%x Enumerator=0x%x hwndParent=0x%x Flags=0x%x\n", ClassGuid, Enumerator, hwndParent, Flags)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDevsExA", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		Enumerator := ctx.Arg(1)
		hwndParent := ctx.Arg(2)
		Flags := ctx.Arg(3)
		DeviceInfoSet := ctx.Arg(4)
		MachineName := ctx.Arg(5)
		_ = ClassGuid
		_ = Enumerator
		_ = hwndParent
		_ = Flags
		_ = DeviceInfoSet
		_ = MachineName
		ravelog.Logf("[setupapi] SetupDiGetClassDevsExA ClassGuid=0x%x Enumerator=0x%x hwndParent=0x%x Flags=0x%x DeviceInfoSet=0x%x MachineName=0x%x\n", ClassGuid, Enumerator, hwndParent, Flags, DeviceInfoSet, MachineName)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDevsExW", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		Enumerator := ctx.Arg(1)
		hwndParent := ctx.Arg(2)
		Flags := ctx.Arg(3)
		DeviceInfoSet := ctx.Arg(4)
		MachineName := ctx.Arg(5)
		_ = ClassGuid
		_ = Enumerator
		_ = hwndParent
		_ = Flags
		_ = DeviceInfoSet
		_ = MachineName
		ravelog.Logf("[setupapi] SetupDiGetClassDevsExW ClassGuid=0x%x Enumerator=0x%x hwndParent=0x%x Flags=0x%x DeviceInfoSet=0x%x MachineName=0x%x\n", ClassGuid, Enumerator, hwndParent, Flags, DeviceInfoSet, MachineName)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDevsW", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		Enumerator := ctx.Arg(1)
		hwndParent := ctx.Arg(2)
		Flags := ctx.Arg(3)
		_ = ClassGuid
		_ = Enumerator
		_ = hwndParent
		_ = Flags
		ravelog.Logf("[setupapi] SetupDiGetClassDevsW ClassGuid=0x%x Enumerator=0x%x hwndParent=0x%x Flags=0x%x\n", ClassGuid, Enumerator, hwndParent, Flags)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassImageIndex", func(ctx *ntapi.TrapContext) uint32 {
		ClassImageListData := ctx.Arg(0)
		ClassGuid := ctx.Arg(1)
		ImageIndex := ctx.Arg(2)
		_ = ClassImageListData
		_ = ClassGuid
		_ = ImageIndex
		ravelog.Logf("[setupapi] SetupDiGetClassImageIndex ClassImageListData=0x%x ClassGuid=0x%x ImageIndex=0x%x\n", ClassImageListData, ClassGuid, ImageIndex)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassImageList", func(ctx *ntapi.TrapContext) uint32 {
		ClassImageListData := ctx.Arg(0)
		_ = ClassImageListData
		ravelog.Logf("[setupapi] SetupDiGetClassImageList ClassImageListData=0x%x\n", ClassImageListData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassImageListExA", func(ctx *ntapi.TrapContext) uint32 {
		ClassImageListData := ctx.Arg(0)
		MachineName := ctx.Arg(1)
		Reserved := ctx.Arg(2)
		_ = ClassImageListData
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiGetClassImageListExA ClassImageListData=0x%x MachineName=0x%x Reserved=0x%x\n", ClassImageListData, MachineName, Reserved)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassImageListExW", func(ctx *ntapi.TrapContext) uint32 {
		ClassImageListData := ctx.Arg(0)
		MachineName := ctx.Arg(1)
		Reserved := ctx.Arg(2)
		_ = ClassImageListData
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiGetClassImageListExW ClassImageListData=0x%x MachineName=0x%x Reserved=0x%x\n", ClassImageListData, MachineName, Reserved)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassInstallParamsA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		ClassInstallParams := ctx.Arg(2)
		ClassInstallParamsSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = ClassInstallParams
		_ = ClassInstallParamsSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiGetClassInstallParamsA DeviceInfoSet=0x%x DeviceInfoData=0x%x ClassInstallParams=0x%x ClassInstallParamsSize=0x%x RequiredSize=0x%x\n", DeviceInfoSet, DeviceInfoData, ClassInstallParams, ClassInstallParamsSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassInstallParamsW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		ClassInstallParams := ctx.Arg(2)
		ClassInstallParamsSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = ClassInstallParams
		_ = ClassInstallParamsSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiGetClassInstallParamsW DeviceInfoSet=0x%x DeviceInfoData=0x%x ClassInstallParams=0x%x ClassInstallParamsSize=0x%x RequiredSize=0x%x\n", DeviceInfoSet, DeviceInfoData, ClassInstallParams, ClassInstallParamsSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassRegistryPropertyA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupDiGetClassRegistryPropertyA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassRegistryPropertyW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupDiGetClassRegistryPropertyW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetCustomDevicePropertyA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupDiGetCustomDevicePropertyA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetCustomDevicePropertyW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupDiGetCustomDevicePropertyW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInfoListClass", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		ClassGuid := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = ClassGuid
		ravelog.Logf("[setupapi] SetupDiGetDeviceInfoListClass DeviceInfoSet=0x%x ClassGuid=0x%x\n", DeviceInfoSet, ClassGuid)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInfoListDetailA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoSetDetailData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInfoSetDetailData
		ravelog.Logf("[setupapi] SetupDiGetDeviceInfoListDetailA DeviceInfoSet=0x%x DeviceInfoSetDetailData=0x%x\n", DeviceInfoSet, DeviceInfoSetDetailData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInfoListDetailW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoSetDetailData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInfoSetDetailData
		ravelog.Logf("[setupapi] SetupDiGetDeviceInfoListDetailW DeviceInfoSet=0x%x DeviceInfoSetDetailData=0x%x\n", DeviceInfoSet, DeviceInfoSetDetailData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInstallParamsA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DeviceInstallParams := ctx.Arg(2)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DeviceInstallParams
		ravelog.Logf("[setupapi] SetupDiGetDeviceInstallParamsA DeviceInfoSet=0x%x DeviceInfoData=0x%x DeviceInstallParams=0x%x\n", DeviceInfoSet, DeviceInfoData, DeviceInstallParams)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInstallParamsW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DeviceInstallParams := ctx.Arg(2)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DeviceInstallParams
		ravelog.Logf("[setupapi] SetupDiGetDeviceInstallParamsW DeviceInfoSet=0x%x DeviceInfoData=0x%x DeviceInstallParams=0x%x\n", DeviceInfoSet, DeviceInfoData, DeviceInstallParams)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInstanceIdA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DeviceInstanceId := ctx.Arg(2)
		DeviceInstanceIdSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DeviceInstanceId
		_ = DeviceInstanceIdSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiGetDeviceInstanceIdA DeviceInfoSet=0x%x DeviceInfoData=0x%x DeviceInstanceId=0x%x DeviceInstanceIdSize=0x%x RequiredSize=0x%x\n", DeviceInfoSet, DeviceInfoData, DeviceInstanceId, DeviceInstanceIdSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInstanceIdW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DeviceInstanceId := ctx.Arg(2)
		DeviceInstanceIdSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DeviceInstanceId
		_ = DeviceInstanceIdSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiGetDeviceInstanceIdW DeviceInfoSet=0x%x DeviceInfoData=0x%x DeviceInstanceId=0x%x DeviceInstanceIdSize=0x%x RequiredSize=0x%x\n", DeviceInfoSet, DeviceInfoData, DeviceInstanceId, DeviceInstanceIdSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInterfaceAlias", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInterfaceData := ctx.Arg(1)
		AliasInterfaceClassGuid := ctx.Arg(2)
		AliasDeviceInterfaceData := ctx.Arg(3)
		_ = DeviceInfoSet
		_ = DeviceInterfaceData
		_ = AliasInterfaceClassGuid
		_ = AliasDeviceInterfaceData
		ravelog.Logf("[setupapi] SetupDiGetDeviceInterfaceAlias DeviceInfoSet=0x%x DeviceInterfaceData=0x%x AliasInterfaceClassGuid=0x%x AliasDeviceInterfaceData=0x%x\n", DeviceInfoSet, DeviceInterfaceData, AliasInterfaceClassGuid, AliasDeviceInterfaceData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInterfaceDetailA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInterfaceData := ctx.Arg(1)
		DeviceInterfaceDetailData := ctx.Arg(2)
		DeviceInterfaceDetailDataSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		DeviceInfoData := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceInterfaceData
		_ = DeviceInterfaceDetailData
		_ = DeviceInterfaceDetailDataSize
		_ = RequiredSize
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiGetDeviceInterfaceDetailA DeviceInfoSet=0x%x DeviceInterfaceData=0x%x DeviceInterfaceDetailData=0x%x DeviceInterfaceDetailDataSize=0x%x RequiredSize=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInterfaceData, DeviceInterfaceDetailData, DeviceInterfaceDetailDataSize, RequiredSize, DeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInterfaceDetailW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInterfaceData := ctx.Arg(1)
		DeviceInterfaceDetailData := ctx.Arg(2)
		DeviceInterfaceDetailDataSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		DeviceInfoData := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceInterfaceData
		_ = DeviceInterfaceDetailData
		_ = DeviceInterfaceDetailDataSize
		_ = RequiredSize
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiGetDeviceInterfaceDetailW DeviceInfoSet=0x%x DeviceInterfaceData=0x%x DeviceInterfaceDetailData=0x%x DeviceInterfaceDetailDataSize=0x%x RequiredSize=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInterfaceData, DeviceInterfaceDetailData, DeviceInterfaceDetailDataSize, RequiredSize, DeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceRegistryPropertyA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		Property := ctx.Arg(2)
		PropertyRegDataType := ctx.Arg(3)
		PropertyBuffer := ctx.Arg(4)
		PropertyBufferSize := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = Property
		_ = PropertyRegDataType
		_ = PropertyBuffer
		_ = PropertyBufferSize
		ravelog.Logf("[setupapi] SetupDiGetDeviceRegistryPropertyA DeviceInfoSet=0x%x DeviceInfoData=0x%x Property=0x%x PropertyRegDataType=0x%x PropertyBuffer=0x%x PropertyBufferSize=0x%x\n", DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceRegistryPropertyW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		Property := ctx.Arg(2)
		PropertyRegDataType := ctx.Arg(3)
		PropertyBuffer := ctx.Arg(4)
		PropertyBufferSize := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = Property
		_ = PropertyRegDataType
		_ = PropertyBuffer
		_ = PropertyBufferSize
		ravelog.Logf("[setupapi] SetupDiGetDeviceRegistryPropertyW DeviceInfoSet=0x%x DeviceInfoData=0x%x Property=0x%x PropertyRegDataType=0x%x PropertyBuffer=0x%x PropertyBufferSize=0x%x\n", DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDriverInfoDetailA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DriverInfoData := ctx.Arg(2)
		DriverInfoDetailData := ctx.Arg(3)
		DriverInfoDetailDataSize := ctx.Arg(4)
		RequiredSize := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DriverInfoData
		_ = DriverInfoDetailData
		_ = DriverInfoDetailDataSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiGetDriverInfoDetailA DeviceInfoSet=0x%x DeviceInfoData=0x%x DriverInfoData=0x%x DriverInfoDetailData=0x%x DriverInfoDetailDataSize=0x%x RequiredSize=0x%x\n", DeviceInfoSet, DeviceInfoData, DriverInfoData, DriverInfoDetailData, DriverInfoDetailDataSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDriverInfoDetailW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DriverInfoData := ctx.Arg(2)
		DriverInfoDetailData := ctx.Arg(3)
		DriverInfoDetailDataSize := ctx.Arg(4)
		RequiredSize := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DriverInfoData
		_ = DriverInfoDetailData
		_ = DriverInfoDetailDataSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiGetDriverInfoDetailW DeviceInfoSet=0x%x DeviceInfoData=0x%x DriverInfoData=0x%x DriverInfoDetailData=0x%x DriverInfoDetailDataSize=0x%x RequiredSize=0x%x\n", DeviceInfoSet, DeviceInfoData, DriverInfoData, DriverInfoDetailData, DriverInfoDetailDataSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDriverInstallParamsW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DriverInfoData := ctx.Arg(2)
		DriverInstallParams := ctx.Arg(3)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DriverInfoData
		_ = DriverInstallParams
		ravelog.Logf("[setupapi] SetupDiGetDriverInstallParamsW DeviceInfoSet=0x%x DeviceInfoData=0x%x DriverInfoData=0x%x DriverInstallParams=0x%x\n", DeviceInfoSet, DeviceInfoData, DriverInfoData, DriverInstallParams)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetINFClassA", func(ctx *ntapi.TrapContext) uint32 {
		InfName := ctx.Arg(0)
		ClassGuid := ctx.Arg(1)
		ClassName := ctx.Arg(2)
		ClassNameSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		_ = InfName
		_ = ClassGuid
		_ = ClassName
		_ = ClassNameSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiGetINFClassA InfName=0x%x ClassGuid=0x%x ClassName=0x%x ClassNameSize=0x%x RequiredSize=0x%x\n", InfName, ClassGuid, ClassName, ClassNameSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetINFClassW", func(ctx *ntapi.TrapContext) uint32 {
		InfName := ctx.Arg(0)
		ClassGuid := ctx.Arg(1)
		ClassName := ctx.Arg(2)
		ClassNameSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		_ = InfName
		_ = ClassGuid
		_ = ClassName
		_ = ClassNameSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupDiGetINFClassW InfName=0x%x ClassGuid=0x%x ClassName=0x%x ClassNameSize=0x%x RequiredSize=0x%x\n", InfName, ClassGuid, ClassName, ClassNameSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetSelectedDevice", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiGetSelectedDevice DeviceInfoSet=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetSelectedDriverA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DriverInfoData := ctx.Arg(2)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DriverInfoData
		ravelog.Logf("[setupapi] SetupDiGetSelectedDriverA DeviceInfoSet=0x%x DeviceInfoData=0x%x DriverInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData, DriverInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetSelectedDriverW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DriverInfoData := ctx.Arg(2)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DriverInfoData
		ravelog.Logf("[setupapi] SetupDiGetSelectedDriverW DeviceInfoSet=0x%x DeviceInfoData=0x%x DriverInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData, DriverInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallClassA", func(ctx *ntapi.TrapContext) uint32 {
		hwndParent := ctx.Arg(0)
		InfFileName := ctx.Arg(1)
		Flags := ctx.Arg(2)
		FileQueue := ctx.Arg(3)
		_ = hwndParent
		_ = InfFileName
		_ = Flags
		_ = FileQueue
		ravelog.Logf("[setupapi] SetupDiInstallClassA hwndParent=0x%x InfFileName=0x%x Flags=0x%x FileQueue=0x%x\n", hwndParent, InfFileName, Flags, FileQueue)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallClassExA", func(ctx *ntapi.TrapContext) uint32 {
		hwndParent := ctx.Arg(0)
		InfFileName := ctx.Arg(1)
		Flags := ctx.Arg(2)
		FileQueue := ctx.Arg(3)
		InterfaceClassGuid := ctx.Arg(4)
		Reserved1 := ctx.Arg(5)
		_ = hwndParent
		_ = InfFileName
		_ = Flags
		_ = FileQueue
		_ = InterfaceClassGuid
		_ = Reserved1
		ravelog.Logf("[setupapi] SetupDiInstallClassExA hwndParent=0x%x InfFileName=0x%x Flags=0x%x FileQueue=0x%x InterfaceClassGuid=0x%x Reserved1=0x%x\n", hwndParent, InfFileName, Flags, FileQueue, InterfaceClassGuid, Reserved1)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallClassExW", func(ctx *ntapi.TrapContext) uint32 {
		hwndParent := ctx.Arg(0)
		InfFileName := ctx.Arg(1)
		Flags := ctx.Arg(2)
		FileQueue := ctx.Arg(3)
		InterfaceClassGuid := ctx.Arg(4)
		Reserved1 := ctx.Arg(5)
		_ = hwndParent
		_ = InfFileName
		_ = Flags
		_ = FileQueue
		_ = InterfaceClassGuid
		_ = Reserved1
		ravelog.Logf("[setupapi] SetupDiInstallClassExW hwndParent=0x%x InfFileName=0x%x Flags=0x%x FileQueue=0x%x InterfaceClassGuid=0x%x Reserved1=0x%x\n", hwndParent, InfFileName, Flags, FileQueue, InterfaceClassGuid, Reserved1)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallClassW", func(ctx *ntapi.TrapContext) uint32 {
		hwndParent := ctx.Arg(0)
		InfFileName := ctx.Arg(1)
		Flags := ctx.Arg(2)
		FileQueue := ctx.Arg(3)
		_ = hwndParent
		_ = InfFileName
		_ = Flags
		_ = FileQueue
		ravelog.Logf("[setupapi] SetupDiInstallClassW hwndParent=0x%x InfFileName=0x%x Flags=0x%x FileQueue=0x%x\n", hwndParent, InfFileName, Flags, FileQueue)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallDevice", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiInstallDevice DeviceInfoSet=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData)
		// FALSE/not supported
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallDeviceInterfaces", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiInstallDeviceInterfaces DeviceInfoSet=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallDriverFiles", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiInstallDriverFiles DeviceInfoSet=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiLoadClassIcon", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		LargeIcon := ctx.Arg(1)
		MiniIconIndex := ctx.Arg(2)
		_ = ClassGuid
		_ = LargeIcon
		_ = MiniIconIndex
		ravelog.Logf("[setupapi] SetupDiLoadClassIcon ClassGuid=0x%x LargeIcon=0x%x MiniIconIndex=0x%x\n", ClassGuid, LargeIcon, MiniIconIndex)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenClassRegKey", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		samDesired := ctx.Arg(1)
		_ = ClassGuid
		_ = samDesired
		ravelog.Logf("[setupapi] SetupDiOpenClassRegKey ClassGuid=0x%x samDesired=0x%x\n", ClassGuid, samDesired)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenClassRegKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		samDesired := ctx.Arg(1)
		Flags := ctx.Arg(2)
		MachineName := ctx.Arg(3)
		Reserved := ctx.Arg(4)
		_ = ClassGuid
		_ = samDesired
		_ = Flags
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiOpenClassRegKeyExA ClassGuid=0x%x samDesired=0x%x Flags=0x%x MachineName=0x%x Reserved=0x%x\n", ClassGuid, samDesired, Flags, MachineName, Reserved)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenClassRegKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		ClassGuid := ctx.Arg(0)
		samDesired := ctx.Arg(1)
		Flags := ctx.Arg(2)
		MachineName := ctx.Arg(3)
		Reserved := ctx.Arg(4)
		_ = ClassGuid
		_ = samDesired
		_ = Flags
		_ = MachineName
		_ = Reserved
		ravelog.Logf("[setupapi] SetupDiOpenClassRegKeyExW ClassGuid=0x%x samDesired=0x%x Flags=0x%x MachineName=0x%x Reserved=0x%x\n", ClassGuid, samDesired, Flags, MachineName, Reserved)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenDevRegKey", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		Scope := ctx.Arg(2)
		HwProfile := ctx.Arg(3)
		KeyType := ctx.Arg(4)
		samDesired := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = Scope
		_ = HwProfile
		_ = KeyType
		_ = samDesired
		ravelog.Logf("[setupapi] SetupDiOpenDevRegKey DeviceInfoSet=0x%x DeviceInfoData=0x%x Scope=0x%x HwProfile=0x%x KeyType=0x%x samDesired=0x%x\n", DeviceInfoSet, DeviceInfoData, Scope, HwProfile, KeyType, samDesired)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenDeviceInfoA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInstanceId := ctx.Arg(1)
		hwndParent := ctx.Arg(2)
		OpenFlags := ctx.Arg(3)
		DeviceInfoData := ctx.Arg(4)
		_ = DeviceInfoSet
		_ = DeviceInstanceId
		_ = hwndParent
		_ = OpenFlags
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiOpenDeviceInfoA DeviceInfoSet=0x%x DeviceInstanceId=0x%x hwndParent=0x%x OpenFlags=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInstanceId, hwndParent, OpenFlags, DeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenDeviceInfoW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInstanceId := ctx.Arg(1)
		hwndParent := ctx.Arg(2)
		OpenFlags := ctx.Arg(3)
		DeviceInfoData := ctx.Arg(4)
		_ = DeviceInfoSet
		_ = DeviceInstanceId
		_ = hwndParent
		_ = OpenFlags
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiOpenDeviceInfoW DeviceInfoSet=0x%x DeviceInstanceId=0x%x hwndParent=0x%x OpenFlags=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInstanceId, hwndParent, OpenFlags, DeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenDeviceInterfaceA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DevicePath := ctx.Arg(1)
		OpenFlags := ctx.Arg(2)
		DeviceInterfaceData := ctx.Arg(3)
		_ = DeviceInfoSet
		_ = DevicePath
		_ = OpenFlags
		_ = DeviceInterfaceData
		ravelog.Logf("[setupapi] SetupDiOpenDeviceInterfaceA DeviceInfoSet=0x%x DevicePath=0x%x OpenFlags=0x%x DeviceInterfaceData=0x%x\n", DeviceInfoSet, DevicePath, OpenFlags, DeviceInterfaceData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenDeviceInterfaceRegKey", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] SetupDiOpenDeviceInterfaceRegKey arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenDeviceInterfaceW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DevicePath := ctx.Arg(1)
		OpenFlags := ctx.Arg(2)
		DeviceInterfaceData := ctx.Arg(3)
		_ = DeviceInfoSet
		_ = DevicePath
		_ = OpenFlags
		_ = DeviceInterfaceData
		ravelog.Logf("[setupapi] SetupDiOpenDeviceInterfaceW DeviceInfoSet=0x%x DevicePath=0x%x OpenFlags=0x%x DeviceInterfaceData=0x%x\n", DeviceInfoSet, DevicePath, OpenFlags, DeviceInterfaceData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiRegisterCoDeviceInstallers", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiRegisterCoDeviceInstallers DeviceInfoSet=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiRegisterDeviceInfo", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		Flags := ctx.Arg(2)
		CompareProc := ctx.Arg(3)
		CompareContext := ctx.Arg(4)
		DupDeviceInfoData := ctx.Arg(5)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = Flags
		_ = CompareProc
		_ = CompareContext
		_ = DupDeviceInfoData
		ravelog.Logf("[setupapi] SetupDiRegisterDeviceInfo DeviceInfoSet=0x%x DeviceInfoData=0x%x Flags=0x%x CompareProc=0x%x CompareContext=0x%x DupDeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData, Flags, CompareProc, CompareContext, DupDeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiRemoveDevice", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiRemoveDevice DeviceInfoSet=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiRemoveDeviceInterface", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInterfaceData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInterfaceData
		ravelog.Logf("[setupapi] SetupDiRemoveDeviceInterface DeviceInfoSet=0x%x DeviceInterfaceData=0x%x\n", DeviceInfoSet, DeviceInterfaceData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-version=0x502+", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] -version=0x502+ arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSelectBestCompatDrv", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] SetupDiSelectBestCompatDrv arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSelectDevice", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] SetupDiSelectDevice arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetClassInstallParamsA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		ClassInstallParams := ctx.Arg(2)
		ClassInstallParamsSize := ctx.Arg(3)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = ClassInstallParams
		_ = ClassInstallParamsSize
		ravelog.Logf("[setupapi] SetupDiSetClassInstallParamsA DeviceInfoSet=0x%x DeviceInfoData=0x%x ClassInstallParams=0x%x ClassInstallParamsSize=0x%x\n", DeviceInfoSet, DeviceInfoData, ClassInstallParams, ClassInstallParamsSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetClassInstallParamsW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		ClassInstallParams := ctx.Arg(2)
		ClassInstallParamsSize := ctx.Arg(3)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = ClassInstallParams
		_ = ClassInstallParamsSize
		ravelog.Logf("[setupapi] SetupDiSetClassInstallParamsW DeviceInfoSet=0x%x DeviceInfoData=0x%x ClassInstallParams=0x%x ClassInstallParamsSize=0x%x\n", DeviceInfoSet, DeviceInfoData, ClassInstallParams, ClassInstallParamsSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetClassRegistryPropertyA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupDiSetClassRegistryPropertyA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetClassRegistryPropertyW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupDiSetClassRegistryPropertyW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetDeviceInstallParamsA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DeviceInstallParams := ctx.Arg(2)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DeviceInstallParams
		ravelog.Logf("[setupapi] SetupDiSetDeviceInstallParamsA DeviceInfoSet=0x%x DeviceInfoData=0x%x DeviceInstallParams=0x%x\n", DeviceInfoSet, DeviceInfoData, DeviceInstallParams)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetDeviceInstallParamsW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DeviceInstallParams := ctx.Arg(2)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DeviceInstallParams
		ravelog.Logf("[setupapi] SetupDiSetDeviceInstallParamsW DeviceInfoSet=0x%x DeviceInfoData=0x%x DeviceInstallParams=0x%x\n", DeviceInfoSet, DeviceInfoData, DeviceInstallParams)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetDeviceRegistryPropertyA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		Property := ctx.Arg(2)
		PropertyBuffer := ctx.Arg(3)
		PropertyBufferSize := ctx.Arg(4)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = Property
		_ = PropertyBuffer
		_ = PropertyBufferSize
		ravelog.Logf("[setupapi] SetupDiSetDeviceRegistryPropertyA DeviceInfoSet=0x%x DeviceInfoData=0x%x Property=0x%x PropertyBuffer=0x%x PropertyBufferSize=0x%x\n", DeviceInfoSet, DeviceInfoData, Property, PropertyBuffer, PropertyBufferSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetDeviceRegistryPropertyW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		Property := ctx.Arg(2)
		PropertyBuffer := ctx.Arg(3)
		PropertyBufferSize := ctx.Arg(4)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = Property
		_ = PropertyBuffer
		_ = PropertyBufferSize
		ravelog.Logf("[setupapi] SetupDiSetDeviceRegistryPropertyW DeviceInfoSet=0x%x DeviceInfoData=0x%x Property=0x%x PropertyBuffer=0x%x PropertyBufferSize=0x%x\n", DeviceInfoSet, DeviceInfoData, Property, PropertyBuffer, PropertyBufferSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetDriverInstallParamsA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DriverInfoData := ctx.Arg(2)
		DriverInstallParams := ctx.Arg(3)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DriverInfoData
		_ = DriverInstallParams
		ravelog.Logf("[setupapi] SetupDiSetDriverInstallParamsA DeviceInfoSet=0x%x DeviceInfoData=0x%x DriverInfoData=0x%x DriverInstallParams=0x%x\n", DeviceInfoSet, DeviceInfoData, DriverInfoData, DriverInstallParams)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetDriverInstallParamsW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DriverInfoData := ctx.Arg(2)
		DriverInstallParams := ctx.Arg(3)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DriverInfoData
		_ = DriverInstallParams
		ravelog.Logf("[setupapi] SetupDiSetDriverInstallParamsW DeviceInfoSet=0x%x DeviceInfoData=0x%x DriverInfoData=0x%x DriverInstallParams=0x%x\n", DeviceInfoSet, DeviceInfoData, DriverInfoData, DriverInstallParams)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetSelectedDevice", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiSetSelectedDevice DeviceInfoSet=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetSelectedDriverA", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DriverInfoData := ctx.Arg(2)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DriverInfoData
		ravelog.Logf("[setupapi] SetupDiSetSelectedDriverA DeviceInfoSet=0x%x DeviceInfoData=0x%x DriverInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData, DriverInfoData)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetSelectedDriverW", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		DriverInfoData := ctx.Arg(2)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = DriverInfoData
		ravelog.Logf("[setupapi] SetupDiSetSelectedDriverW DeviceInfoSet=0x%x DeviceInfoData=0x%x DriverInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData, DriverInfoData)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiUnremoveDevice", func(ctx *ntapi.TrapContext) uint32 {
		DeviceInfoSet := ctx.Arg(0)
		DeviceInfoData := ctx.Arg(1)
		_ = DeviceInfoSet
		_ = DeviceInfoData
		ravelog.Logf("[setupapi] SetupDiUnremoveDevice DeviceInfoSet=0x%x DeviceInfoData=0x%x\n", DeviceInfoSet, DeviceInfoData)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDuplicateDiskSpaceListA", func(ctx *ntapi.TrapContext) uint32 {
		DiskSpace := ctx.Arg(0)
		Reserved1 := ctx.Arg(1)
		Reserved2 := ctx.Arg(2)
		Flags := ctx.Arg(3)
		_ = DiskSpace
		_ = Reserved1
		_ = Reserved2
		_ = Flags
		ravelog.Logf("[setupapi] SetupDuplicateDiskSpaceListA DiskSpace=0x%x Reserved1=0x%x Reserved2=0x%x Flags=0x%x\n", DiskSpace, Reserved1, Reserved2, Flags)
		// fake disk space handle
		ctx.SetReturn(0xDEAD0010)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDuplicateDiskSpaceListW", func(ctx *ntapi.TrapContext) uint32 {
		DiskSpace := ctx.Arg(0)
		Reserved1 := ctx.Arg(1)
		Reserved2 := ctx.Arg(2)
		Flags := ctx.Arg(3)
		_ = DiskSpace
		_ = Reserved1
		_ = Reserved2
		_ = Flags
		ravelog.Logf("[setupapi] SetupDuplicateDiskSpaceListW DiskSpace=0x%x Reserved1=0x%x Reserved2=0x%x Flags=0x%x\n", DiskSpace, Reserved1, Reserved2, Flags)
		// fake disk space handle
		ctx.SetReturn(0xDEAD0010)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupEnumInfSectionsA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] SetupEnumInfSectionsA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupEnumInfSectionsW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] SetupEnumInfSectionsW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupFindFirstLineA", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		Section := ctx.Arg(1)
		Key := ctx.Arg(2)
		Context := ctx.Arg(3)
		_ = InfHandle
		_ = Section
		_ = Key
		_ = Context
		ravelog.Logf("[setupapi] SetupFindFirstLineA InfHandle=0x%x Section=0x%x Key=0x%x Context=0x%x\n", InfHandle, Section, Key, Context)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupFindFirstLineW", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		Section := ctx.Arg(1)
		Key := ctx.Arg(2)
		Context := ctx.Arg(3)
		_ = InfHandle
		_ = Section
		_ = Key
		_ = Context
		ravelog.Logf("[setupapi] SetupFindFirstLineW InfHandle=0x%x Section=0x%x Key=0x%x Context=0x%x\n", InfHandle, Section, Key, Context)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupFindNextLine", func(ctx *ntapi.TrapContext) uint32 {
		ContextIn := ctx.Arg(0)
		ContextOut := ctx.Arg(1)
		_ = ContextIn
		_ = ContextOut
		ravelog.Logf("[setupapi] SetupFindNextLine ContextIn=0x%x ContextOut=0x%x\n", ContextIn, ContextOut)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupFindNextMatchLineA", func(ctx *ntapi.TrapContext) uint32 {
		ContextIn := ctx.Arg(0)
		Key := ctx.Arg(1)
		ContextOut := ctx.Arg(2)
		_ = ContextIn
		_ = Key
		_ = ContextOut
		ravelog.Logf("[setupapi] SetupFindNextMatchLineA ContextIn=0x%x Key=0x%x ContextOut=0x%x\n", ContextIn, Key, ContextOut)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupFindNextMatchLineW", func(ctx *ntapi.TrapContext) uint32 {
		ContextIn := ctx.Arg(0)
		Key := ctx.Arg(1)
		ContextOut := ctx.Arg(2)
		_ = ContextIn
		_ = Key
		_ = ContextOut
		ravelog.Logf("[setupapi] SetupFindNextMatchLineW ContextIn=0x%x Key=0x%x ContextOut=0x%x\n", ContextIn, Key, ContextOut)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetBinaryField", func(ctx *ntapi.TrapContext) uint32 {
		Context := ctx.Arg(0)
		FieldIndex := ctx.Arg(1)
		ReturnBuffer := ctx.Arg(2)
		ReturnBufferSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		_ = Context
		_ = FieldIndex
		_ = ReturnBuffer
		_ = ReturnBufferSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupGetBinaryField Context=0x%x FieldIndex=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x RequiredSize=0x%x\n", Context, FieldIndex, ReturnBuffer, ReturnBufferSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFieldCount", func(ctx *ntapi.TrapContext) uint32 {
		Context := ctx.Arg(0)
		_ = Context
		ravelog.Logf("[setupapi] SetupGetFieldCount Context=0x%x\n", Context)
		// 0 fields
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFileCompressionInfoA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] SetupGetFileCompressionInfoA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFileCompressionInfoExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupGetFileCompressionInfoExA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFileCompressionInfoExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupGetFileCompressionInfoExW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFileCompressionInfoW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] SetupGetFileCompressionInfoW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFileQueueCount", func(ctx *ntapi.TrapContext) uint32 {
		FileQueue := ctx.Arg(0)
		SubQueueFileOp := ctx.Arg(1)
		NumOperations := ctx.Arg(2)
		_ = FileQueue
		_ = SubQueueFileOp
		_ = NumOperations
		ravelog.Logf("[setupapi] SetupGetFileQueueCount FileQueue=0x%x SubQueueFileOp=0x%x NumOperations=0x%x\n", FileQueue, SubQueueFileOp, NumOperations)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFileQueueFlags", func(ctx *ntapi.TrapContext) uint32 {
		FileQueue := ctx.Arg(0)
		Flags := ctx.Arg(1)
		_ = FileQueue
		_ = Flags
		ravelog.Logf("[setupapi] SetupGetFileQueueFlags FileQueue=0x%x Flags=0x%x\n", FileQueue, Flags)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetInfFileListA", func(ctx *ntapi.TrapContext) uint32 {
		DirectoryPath := ctx.Arg(0)
		InfStyle := ctx.Arg(1)
		ReturnBuffer := ctx.Arg(2)
		ReturnBufferSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		_ = DirectoryPath
		_ = InfStyle
		_ = ReturnBuffer
		_ = ReturnBufferSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupGetInfFileListA DirectoryPath=0x%x InfStyle=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x RequiredSize=0x%x\n", DirectoryPath, InfStyle, ReturnBuffer, ReturnBufferSize, RequiredSize)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetInfFileListW", func(ctx *ntapi.TrapContext) uint32 {
		DirectoryPath := ctx.Arg(0)
		InfStyle := ctx.Arg(1)
		ReturnBuffer := ctx.Arg(2)
		ReturnBufferSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		_ = DirectoryPath
		_ = InfStyle
		_ = ReturnBuffer
		_ = ReturnBufferSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupGetInfFileListW DirectoryPath=0x%x InfStyle=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x RequiredSize=0x%x\n", DirectoryPath, InfStyle, ReturnBuffer, ReturnBufferSize, RequiredSize)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetInfInformationA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] SetupGetInfInformationA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetInfInformationW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] SetupGetInfInformationW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetIntField", func(ctx *ntapi.TrapContext) uint32 {
		Context := ctx.Arg(0)
		FieldIndex := ctx.Arg(1)
		IntegerValue := ctx.Arg(2)
		_ = Context
		_ = FieldIndex
		_ = IntegerValue
		ravelog.Logf("[setupapi] SetupGetIntField Context=0x%x FieldIndex=0x%x IntegerValue=0x%x\n", Context, FieldIndex, IntegerValue)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetLineByIndexA", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		Section := ctx.Arg(1)
		Index := ctx.Arg(2)
		Context := ctx.Arg(3)
		_ = InfHandle
		_ = Section
		_ = Index
		_ = Context
		ravelog.Logf("[setupapi] SetupGetLineByIndexA InfHandle=0x%x Section=0x%x Index=0x%x Context=0x%x\n", InfHandle, Section, Index, Context)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetLineByIndexW", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		Section := ctx.Arg(1)
		Index := ctx.Arg(2)
		Context := ctx.Arg(3)
		_ = InfHandle
		_ = Section
		_ = Index
		_ = Context
		ravelog.Logf("[setupapi] SetupGetLineByIndexW InfHandle=0x%x Section=0x%x Index=0x%x Context=0x%x\n", InfHandle, Section, Index, Context)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetLineCountA", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		Section := ctx.Arg(1)
		_ = InfHandle
		_ = Section
		ravelog.Logf("[setupapi] SetupGetLineCountA InfHandle=0x%x Section=0x%x\n", InfHandle, Section)
		// 0 lines
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetLineCountW", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		Section := ctx.Arg(1)
		_ = InfHandle
		_ = Section
		ravelog.Logf("[setupapi] SetupGetLineCountW InfHandle=0x%x Section=0x%x\n", InfHandle, Section)
		// 0 lines
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetLineTextA", func(ctx *ntapi.TrapContext) uint32 {
		Context := ctx.Arg(0)
		InfHandle := ctx.Arg(1)
		Section := ctx.Arg(2)
		Key := ctx.Arg(3)
		ReturnBuffer := ctx.Arg(4)
		ReturnBufferSize := ctx.Arg(5)
		_ = Context
		_ = InfHandle
		_ = Section
		_ = Key
		_ = ReturnBuffer
		_ = ReturnBufferSize
		ravelog.Logf("[setupapi] SetupGetLineTextA Context=0x%x InfHandle=0x%x Section=0x%x Key=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x\n", Context, InfHandle, Section, Key, ReturnBuffer, ReturnBufferSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetLineTextW", func(ctx *ntapi.TrapContext) uint32 {
		Context := ctx.Arg(0)
		InfHandle := ctx.Arg(1)
		Section := ctx.Arg(2)
		Key := ctx.Arg(3)
		ReturnBuffer := ctx.Arg(4)
		ReturnBufferSize := ctx.Arg(5)
		_ = Context
		_ = InfHandle
		_ = Section
		_ = Key
		_ = ReturnBuffer
		_ = ReturnBufferSize
		ravelog.Logf("[setupapi] SetupGetLineTextW Context=0x%x InfHandle=0x%x Section=0x%x Key=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x\n", Context, InfHandle, Section, Key, ReturnBuffer, ReturnBufferSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetMultiSzFieldA", func(ctx *ntapi.TrapContext) uint32 {
		Context := ctx.Arg(0)
		FieldIndex := ctx.Arg(1)
		ReturnBuffer := ctx.Arg(2)
		ReturnBufferSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		_ = Context
		_ = FieldIndex
		_ = ReturnBuffer
		_ = ReturnBufferSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupGetMultiSzFieldA Context=0x%x FieldIndex=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x RequiredSize=0x%x\n", Context, FieldIndex, ReturnBuffer, ReturnBufferSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetMultiSzFieldW", func(ctx *ntapi.TrapContext) uint32 {
		Context := ctx.Arg(0)
		FieldIndex := ctx.Arg(1)
		ReturnBuffer := ctx.Arg(2)
		ReturnBufferSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		_ = Context
		_ = FieldIndex
		_ = ReturnBuffer
		_ = ReturnBufferSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupGetMultiSzFieldW Context=0x%x FieldIndex=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x RequiredSize=0x%x\n", Context, FieldIndex, ReturnBuffer, ReturnBufferSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetNonInteractiveMode", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] SetupGetNonInteractiveMode\n")
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetSourceFileLocationA", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		InfContext := ctx.Arg(1)
		FileName := ctx.Arg(2)
		SourceId := ctx.Arg(3)
		ReturnBuffer := ctx.Arg(4)
		ReturnBufferSize := ctx.Arg(5)
		_ = InfHandle
		_ = InfContext
		_ = FileName
		_ = SourceId
		_ = ReturnBuffer
		_ = ReturnBufferSize
		ravelog.Logf("[setupapi] SetupGetSourceFileLocationA InfHandle=0x%x InfContext=0x%x FileName=0x%x SourceId=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x\n", InfHandle, InfContext, FileName, SourceId, ReturnBuffer, ReturnBufferSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetSourceFileLocationW", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		InfContext := ctx.Arg(1)
		FileName := ctx.Arg(2)
		SourceId := ctx.Arg(3)
		ReturnBuffer := ctx.Arg(4)
		ReturnBufferSize := ctx.Arg(5)
		_ = InfHandle
		_ = InfContext
		_ = FileName
		_ = SourceId
		_ = ReturnBuffer
		_ = ReturnBufferSize
		ravelog.Logf("[setupapi] SetupGetSourceFileLocationW InfHandle=0x%x InfContext=0x%x FileName=0x%x SourceId=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x\n", InfHandle, InfContext, FileName, SourceId, ReturnBuffer, ReturnBufferSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetSourceInfoA", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		SourceId := ctx.Arg(1)
		InfoDesired := ctx.Arg(2)
		ReturnBuffer := ctx.Arg(3)
		ReturnBufferSize := ctx.Arg(4)
		RequiredSize := ctx.Arg(5)
		_ = InfHandle
		_ = SourceId
		_ = InfoDesired
		_ = ReturnBuffer
		_ = ReturnBufferSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupGetSourceInfoA InfHandle=0x%x SourceId=0x%x InfoDesired=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x RequiredSize=0x%x\n", InfHandle, SourceId, InfoDesired, ReturnBuffer, ReturnBufferSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetSourceInfoW", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		SourceId := ctx.Arg(1)
		InfoDesired := ctx.Arg(2)
		ReturnBuffer := ctx.Arg(3)
		ReturnBufferSize := ctx.Arg(4)
		RequiredSize := ctx.Arg(5)
		_ = InfHandle
		_ = SourceId
		_ = InfoDesired
		_ = ReturnBuffer
		_ = ReturnBufferSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupGetSourceInfoW InfHandle=0x%x SourceId=0x%x InfoDesired=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x RequiredSize=0x%x\n", InfHandle, SourceId, InfoDesired, ReturnBuffer, ReturnBufferSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetStringFieldA", func(ctx *ntapi.TrapContext) uint32 {
		Context := ctx.Arg(0)
		FieldIndex := ctx.Arg(1)
		ReturnBuffer := ctx.Arg(2)
		ReturnBufferSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		_ = Context
		_ = FieldIndex
		_ = ReturnBuffer
		_ = ReturnBufferSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupGetStringFieldA Context=0x%x FieldIndex=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x RequiredSize=0x%x\n", Context, FieldIndex, ReturnBuffer, ReturnBufferSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetStringFieldW", func(ctx *ntapi.TrapContext) uint32 {
		Context := ctx.Arg(0)
		FieldIndex := ctx.Arg(1)
		ReturnBuffer := ctx.Arg(2)
		ReturnBufferSize := ctx.Arg(3)
		RequiredSize := ctx.Arg(4)
		_ = Context
		_ = FieldIndex
		_ = ReturnBuffer
		_ = ReturnBufferSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupGetStringFieldW Context=0x%x FieldIndex=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x RequiredSize=0x%x\n", Context, FieldIndex, ReturnBuffer, ReturnBufferSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetTargetPathA", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		InfContext := ctx.Arg(1)
		Section := ctx.Arg(2)
		ReturnBuffer := ctx.Arg(3)
		ReturnBufferSize := ctx.Arg(4)
		RequiredSize := ctx.Arg(5)
		_ = InfHandle
		_ = InfContext
		_ = Section
		_ = ReturnBuffer
		_ = ReturnBufferSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupGetTargetPathA InfHandle=0x%x InfContext=0x%x Section=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x RequiredSize=0x%x\n", InfHandle, InfContext, Section, ReturnBuffer, ReturnBufferSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetTargetPathW", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		InfContext := ctx.Arg(1)
		Section := ctx.Arg(2)
		ReturnBuffer := ctx.Arg(3)
		ReturnBufferSize := ctx.Arg(4)
		RequiredSize := ctx.Arg(5)
		_ = InfHandle
		_ = InfContext
		_ = Section
		_ = ReturnBuffer
		_ = ReturnBufferSize
		_ = RequiredSize
		ravelog.Logf("[setupapi] SetupGetTargetPathW InfHandle=0x%x InfContext=0x%x Section=0x%x ReturnBuffer=0x%x ReturnBufferSize=0x%x RequiredSize=0x%x\n", InfHandle, InfContext, Section, ReturnBuffer, ReturnBufferSize, RequiredSize)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInitDefaultQueueCallback", func(ctx *ntapi.TrapContext) uint32 {
		OwnerWindow := ctx.Arg(0)
		_ = OwnerWindow
		ravelog.Logf("[setupapi] SetupInitDefaultQueueCallback OwnerWindow=0x%x\n", OwnerWindow)
		// fake callback context
		ctx.SetReturn(0xDEAD0002)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInitDefaultQueueCallbackEx", func(ctx *ntapi.TrapContext) uint32 {
		OwnerWindow := ctx.Arg(0)
		AlternateProgressWindow := ctx.Arg(1)
		ProgressMessage := ctx.Arg(2)
		Reserved1 := ctx.Arg(3)
		Reserved2 := ctx.Arg(4)
		_ = OwnerWindow
		_ = AlternateProgressWindow
		_ = ProgressMessage
		_ = Reserved1
		_ = Reserved2
		ravelog.Logf("[setupapi] SetupInitDefaultQueueCallbackEx OwnerWindow=0x%x AlternateProgressWindow=0x%x ProgressMessage=0x%x Reserved1=0x%x Reserved2=0x%x\n", OwnerWindow, AlternateProgressWindow, ProgressMessage, Reserved1, Reserved2)
		// fake callback context
		ctx.SetReturn(0xDEAD0002)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInitializeFileLogA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] SetupInitializeFileLogA arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInitializeFileLogW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] SetupInitializeFileLogW arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallFileA", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		InfContext := ctx.Arg(1)
		SourceFile := ctx.Arg(2)
		SourcePathRoot := ctx.Arg(3)
		DestinationName := ctx.Arg(4)
		CopyStyle := ctx.Arg(5)
		_ = InfHandle
		_ = InfContext
		_ = SourceFile
		_ = SourcePathRoot
		_ = DestinationName
		_ = CopyStyle
		ravelog.Logf("[setupapi] SetupInstallFileA InfHandle=0x%x InfContext=0x%x SourceFile=0x%x SourcePathRoot=0x%x DestinationName=0x%x CopyStyle=0x%x\n", InfHandle, InfContext, SourceFile, SourcePathRoot, DestinationName, CopyStyle)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallFileW", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		InfContext := ctx.Arg(1)
		SourceFile := ctx.Arg(2)
		SourcePathRoot := ctx.Arg(3)
		DestinationName := ctx.Arg(4)
		CopyStyle := ctx.Arg(5)
		_ = InfHandle
		_ = InfContext
		_ = SourceFile
		_ = SourcePathRoot
		_ = DestinationName
		_ = CopyStyle
		ravelog.Logf("[setupapi] SetupInstallFileW InfHandle=0x%x InfContext=0x%x SourceFile=0x%x SourcePathRoot=0x%x DestinationName=0x%x CopyStyle=0x%x\n", InfHandle, InfContext, SourceFile, SourcePathRoot, DestinationName, CopyStyle)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallFilesFromInfSectionA", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		LayoutInfHandle := ctx.Arg(1)
		FileQueue := ctx.Arg(2)
		SectionName := ctx.Arg(3)
		SourceRootPath := ctx.Arg(4)
		CopyFlags := ctx.Arg(5)
		_ = InfHandle
		_ = LayoutInfHandle
		_ = FileQueue
		_ = SectionName
		_ = SourceRootPath
		_ = CopyFlags
		ravelog.Logf("[setupapi] SetupInstallFilesFromInfSectionA InfHandle=0x%x LayoutInfHandle=0x%x FileQueue=0x%x SectionName=0x%x SourceRootPath=0x%x CopyFlags=0x%x\n", InfHandle, LayoutInfHandle, FileQueue, SectionName, SourceRootPath, CopyFlags)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallFilesFromInfSectionW", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		LayoutInfHandle := ctx.Arg(1)
		FileQueue := ctx.Arg(2)
		SectionName := ctx.Arg(3)
		SourceRootPath := ctx.Arg(4)
		CopyFlags := ctx.Arg(5)
		_ = InfHandle
		_ = LayoutInfHandle
		_ = FileQueue
		_ = SectionName
		_ = SourceRootPath
		_ = CopyFlags
		ravelog.Logf("[setupapi] SetupInstallFilesFromInfSectionW InfHandle=0x%x LayoutInfHandle=0x%x FileQueue=0x%x SectionName=0x%x SourceRootPath=0x%x CopyFlags=0x%x\n", InfHandle, LayoutInfHandle, FileQueue, SectionName, SourceRootPath, CopyFlags)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallFromInfSectionA", func(ctx *ntapi.TrapContext) uint32 {
		hwndOwner := ctx.Arg(0)
		InfHandle := ctx.Arg(1)
		SectionName := ctx.Arg(2)
		Flags := ctx.Arg(3)
		RelativeKeyRoot := ctx.Arg(4)
		SourceRootPath := ctx.Arg(5)
		_ = hwndOwner
		_ = InfHandle
		_ = SectionName
		_ = Flags
		_ = RelativeKeyRoot
		_ = SourceRootPath
		ravelog.Logf("[setupapi] SetupInstallFromInfSectionA hwndOwner=0x%x InfHandle=0x%x SectionName=0x%x Flags=0x%x RelativeKeyRoot=0x%x SourceRootPath=0x%x\n", hwndOwner, InfHandle, SectionName, Flags, RelativeKeyRoot, SourceRootPath)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallFromInfSectionW", func(ctx *ntapi.TrapContext) uint32 {
		hwndOwner := ctx.Arg(0)
		InfHandle := ctx.Arg(1)
		SectionName := ctx.Arg(2)
		Flags := ctx.Arg(3)
		RelativeKeyRoot := ctx.Arg(4)
		SourceRootPath := ctx.Arg(5)
		_ = hwndOwner
		_ = InfHandle
		_ = SectionName
		_ = Flags
		_ = RelativeKeyRoot
		_ = SourceRootPath
		ravelog.Logf("[setupapi] SetupInstallFromInfSectionW hwndOwner=0x%x InfHandle=0x%x SectionName=0x%x Flags=0x%x RelativeKeyRoot=0x%x SourceRootPath=0x%x\n", hwndOwner, InfHandle, SectionName, Flags, RelativeKeyRoot, SourceRootPath)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallServicesFromInfSectionA", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		SectionName := ctx.Arg(1)
		Flags := ctx.Arg(2)
		_ = InfHandle
		_ = SectionName
		_ = Flags
		ravelog.Logf("[setupapi] SetupInstallServicesFromInfSectionA InfHandle=0x%x SectionName=0x%x Flags=0x%x\n", InfHandle, SectionName, Flags)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallServicesFromInfSectionExA", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		SectionName := ctx.Arg(1)
		Flags := ctx.Arg(2)
		DeviceInfoSet := ctx.Arg(3)
		DeviceInfoData := ctx.Arg(4)
		Reserved1 := ctx.Arg(5)
		_ = InfHandle
		_ = SectionName
		_ = Flags
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = Reserved1
		ravelog.Logf("[setupapi] SetupInstallServicesFromInfSectionExA InfHandle=0x%x SectionName=0x%x Flags=0x%x DeviceInfoSet=0x%x DeviceInfoData=0x%x Reserved1=0x%x\n", InfHandle, SectionName, Flags, DeviceInfoSet, DeviceInfoData, Reserved1)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallServicesFromInfSectionExW", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		SectionName := ctx.Arg(1)
		Flags := ctx.Arg(2)
		DeviceInfoSet := ctx.Arg(3)
		DeviceInfoData := ctx.Arg(4)
		Reserved1 := ctx.Arg(5)
		_ = InfHandle
		_ = SectionName
		_ = Flags
		_ = DeviceInfoSet
		_ = DeviceInfoData
		_ = Reserved1
		ravelog.Logf("[setupapi] SetupInstallServicesFromInfSectionExW InfHandle=0x%x SectionName=0x%x Flags=0x%x DeviceInfoSet=0x%x DeviceInfoData=0x%x Reserved1=0x%x\n", InfHandle, SectionName, Flags, DeviceInfoSet, DeviceInfoData, Reserved1)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallServicesFromInfSectionW", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		SectionName := ctx.Arg(1)
		Flags := ctx.Arg(2)
		_ = InfHandle
		_ = SectionName
		_ = Flags
		ravelog.Logf("[setupapi] SetupInstallServicesFromInfSectionW InfHandle=0x%x SectionName=0x%x Flags=0x%x\n", InfHandle, SectionName, Flags)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupIterateCabinetA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] SetupIterateCabinetA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupIterateCabinetW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] SetupIterateCabinetW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupLogErrorA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] SetupLogErrorA arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupLogErrorW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] SetupLogErrorW arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenAppendInfFileA", func(ctx *ntapi.TrapContext) uint32 {
		FileName := ctx.Arg(0)
		InfHandle := ctx.Arg(1)
		ErrorLine := ctx.Arg(2)
		_ = FileName
		_ = InfHandle
		_ = ErrorLine
		ravelog.Logf("[setupapi] SetupOpenAppendInfFileA FileName=0x%x InfHandle=0x%x ErrorLine=0x%x\n", FileName, InfHandle, ErrorLine)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenAppendInfFileW", func(ctx *ntapi.TrapContext) uint32 {
		FileName := ctx.Arg(0)
		InfHandle := ctx.Arg(1)
		ErrorLine := ctx.Arg(2)
		_ = FileName
		_ = InfHandle
		_ = ErrorLine
		ravelog.Logf("[setupapi] SetupOpenAppendInfFileW FileName=0x%x InfHandle=0x%x ErrorLine=0x%x\n", FileName, InfHandle, ErrorLine)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenFileQueue", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] SetupOpenFileQueue\n")
		// fake file queue handle
		ctx.SetReturn(0xDEAD0001)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenInfFileA", func(ctx *ntapi.TrapContext) uint32 {
		FileName := ctx.Arg(0)
		InfClass := ctx.Arg(1)
		InfStyle := ctx.Arg(2)
		ErrorLine := ctx.Arg(3)
		_ = FileName
		_ = InfClass
		_ = InfStyle
		_ = ErrorLine
		ravelog.Logf("[setupapi] SetupOpenInfFileA FileName=0x%x InfClass=0x%x InfStyle=0x%x ErrorLine=0x%x\n", FileName, InfClass, InfStyle, ErrorLine)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenInfFileW", func(ctx *ntapi.TrapContext) uint32 {
		FileName := ctx.Arg(0)
		InfClass := ctx.Arg(1)
		InfStyle := ctx.Arg(2)
		ErrorLine := ctx.Arg(3)
		_ = FileName
		_ = InfClass
		_ = InfStyle
		_ = ErrorLine
		ravelog.Logf("[setupapi] SetupOpenInfFileW FileName=0x%x InfClass=0x%x InfStyle=0x%x ErrorLine=0x%x\n", FileName, InfClass, InfStyle, ErrorLine)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenLog", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] SetupOpenLog arg0=0x%x\n", arg0)
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenMasterInf", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] SetupOpenMasterInf\n")
		// INVALID_HANDLE_VALUE
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupPromptForDiskA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupPromptForDiskA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupPromptForDiskW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupPromptForDiskW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupPromptReboot", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] SetupPromptReboot arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] -stub arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueryInfFileInformationA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] SetupQueryInfFileInformationA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueryInfFileInformationW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] SetupQueryInfFileInformationW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueryInfOriginalFileInformationA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] SetupQueryInfOriginalFileInformationA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueryInfOriginalFileInformationW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] SetupQueryInfOriginalFileInformationW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueryInfVersionInformationA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupQueryInfVersionInformationA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueryInfVersionInformationW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupQueryInfVersionInformationW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQuerySpaceRequiredOnDriveA", func(ctx *ntapi.TrapContext) uint32 {
		DiskSpace := ctx.Arg(0)
		DriveSpec := ctx.Arg(1)
		SpaceRequired := ctx.Arg(2)
		Reserved1 := ctx.Arg(3)
		Reserved2 := ctx.Arg(4)
		_ = DiskSpace
		_ = DriveSpec
		_ = SpaceRequired
		_ = Reserved1
		_ = Reserved2
		ravelog.Logf("[setupapi] SetupQuerySpaceRequiredOnDriveA DiskSpace=0x%x DriveSpec=0x%x SpaceRequired=0x%x Reserved1=0x%x Reserved2=0x%x\n", DiskSpace, DriveSpec, SpaceRequired, Reserved1, Reserved2)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQuerySpaceRequiredOnDriveW", func(ctx *ntapi.TrapContext) uint32 {
		DiskSpace := ctx.Arg(0)
		DriveSpec := ctx.Arg(1)
		SpaceRequired := ctx.Arg(2)
		Reserved1 := ctx.Arg(3)
		Reserved2 := ctx.Arg(4)
		_ = DiskSpace
		_ = DriveSpec
		_ = SpaceRequired
		_ = Reserved1
		_ = Reserved2
		ravelog.Logf("[setupapi] SetupQuerySpaceRequiredOnDriveW DiskSpace=0x%x DriveSpec=0x%x SpaceRequired=0x%x Reserved1=0x%x Reserved2=0x%x\n", DiskSpace, DriveSpec, SpaceRequired, Reserved1, Reserved2)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueCopyA", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		SourceRootPath := ctx.Arg(1)
		SourcePath := ctx.Arg(2)
		SourceFilename := ctx.Arg(3)
		SourceDescription := ctx.Arg(4)
		SourceTagfile := ctx.Arg(5)
		_ = QueueHandle
		_ = SourceRootPath
		_ = SourcePath
		_ = SourceFilename
		_ = SourceDescription
		_ = SourceTagfile
		ravelog.Logf("[setupapi] SetupQueueCopyA QueueHandle=0x%x SourceRootPath=0x%x SourcePath=0x%x SourceFilename=0x%x SourceDescription=0x%x SourceTagfile=0x%x\n", QueueHandle, SourceRootPath, SourcePath, SourceFilename, SourceDescription, SourceTagfile)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueCopyIndirectA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] SetupQueueCopyIndirectA arg0=0x%x\n", arg0)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueCopyIndirectW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] SetupQueueCopyIndirectW arg0=0x%x\n", arg0)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueCopySectionA", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		SourceRootPath := ctx.Arg(1)
		InfHandle := ctx.Arg(2)
		ListInfHandle := ctx.Arg(3)
		Section := ctx.Arg(4)
		CopyStyle := ctx.Arg(5)
		_ = QueueHandle
		_ = SourceRootPath
		_ = InfHandle
		_ = ListInfHandle
		_ = Section
		_ = CopyStyle
		ravelog.Logf("[setupapi] SetupQueueCopySectionA QueueHandle=0x%x SourceRootPath=0x%x InfHandle=0x%x ListInfHandle=0x%x Section=0x%x CopyStyle=0x%x\n", QueueHandle, SourceRootPath, InfHandle, ListInfHandle, Section, CopyStyle)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueCopySectionW", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		SourceRootPath := ctx.Arg(1)
		InfHandle := ctx.Arg(2)
		ListInfHandle := ctx.Arg(3)
		Section := ctx.Arg(4)
		CopyStyle := ctx.Arg(5)
		_ = QueueHandle
		_ = SourceRootPath
		_ = InfHandle
		_ = ListInfHandle
		_ = Section
		_ = CopyStyle
		ravelog.Logf("[setupapi] SetupQueueCopySectionW QueueHandle=0x%x SourceRootPath=0x%x InfHandle=0x%x ListInfHandle=0x%x Section=0x%x CopyStyle=0x%x\n", QueueHandle, SourceRootPath, InfHandle, ListInfHandle, Section, CopyStyle)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueCopyW", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		SourceRootPath := ctx.Arg(1)
		SourcePath := ctx.Arg(2)
		SourceFilename := ctx.Arg(3)
		SourceDescription := ctx.Arg(4)
		SourceTagfile := ctx.Arg(5)
		_ = QueueHandle
		_ = SourceRootPath
		_ = SourcePath
		_ = SourceFilename
		_ = SourceDescription
		_ = SourceTagfile
		ravelog.Logf("[setupapi] SetupQueueCopyW QueueHandle=0x%x SourceRootPath=0x%x SourcePath=0x%x SourceFilename=0x%x SourceDescription=0x%x SourceTagfile=0x%x\n", QueueHandle, SourceRootPath, SourcePath, SourceFilename, SourceDescription, SourceTagfile)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueDefaultCopyA", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		InfHandle := ctx.Arg(1)
		SourceRootPath := ctx.Arg(2)
		SourceFilename := ctx.Arg(3)
		TargetFilename := ctx.Arg(4)
		CopyStyle := ctx.Arg(5)
		_ = QueueHandle
		_ = InfHandle
		_ = SourceRootPath
		_ = SourceFilename
		_ = TargetFilename
		_ = CopyStyle
		ravelog.Logf("[setupapi] SetupQueueDefaultCopyA QueueHandle=0x%x InfHandle=0x%x SourceRootPath=0x%x SourceFilename=0x%x TargetFilename=0x%x CopyStyle=0x%x\n", QueueHandle, InfHandle, SourceRootPath, SourceFilename, TargetFilename, CopyStyle)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueDefaultCopyW", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		InfHandle := ctx.Arg(1)
		SourceRootPath := ctx.Arg(2)
		SourceFilename := ctx.Arg(3)
		TargetFilename := ctx.Arg(4)
		CopyStyle := ctx.Arg(5)
		_ = QueueHandle
		_ = InfHandle
		_ = SourceRootPath
		_ = SourceFilename
		_ = TargetFilename
		_ = CopyStyle
		ravelog.Logf("[setupapi] SetupQueueDefaultCopyW QueueHandle=0x%x InfHandle=0x%x SourceRootPath=0x%x SourceFilename=0x%x TargetFilename=0x%x CopyStyle=0x%x\n", QueueHandle, InfHandle, SourceRootPath, SourceFilename, TargetFilename, CopyStyle)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueDeleteA", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		PathPart1 := ctx.Arg(1)
		PathPart2 := ctx.Arg(2)
		_ = QueueHandle
		_ = PathPart1
		_ = PathPart2
		ravelog.Logf("[setupapi] SetupQueueDeleteA QueueHandle=0x%x PathPart1=0x%x PathPart2=0x%x\n", QueueHandle, PathPart1, PathPart2)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueDeleteSectionA", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		InfHandle := ctx.Arg(1)
		ListInfHandle := ctx.Arg(2)
		Section := ctx.Arg(3)
		_ = QueueHandle
		_ = InfHandle
		_ = ListInfHandle
		_ = Section
		ravelog.Logf("[setupapi] SetupQueueDeleteSectionA QueueHandle=0x%x InfHandle=0x%x ListInfHandle=0x%x Section=0x%x\n", QueueHandle, InfHandle, ListInfHandle, Section)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueDeleteSectionW", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		InfHandle := ctx.Arg(1)
		ListInfHandle := ctx.Arg(2)
		Section := ctx.Arg(3)
		_ = QueueHandle
		_ = InfHandle
		_ = ListInfHandle
		_ = Section
		ravelog.Logf("[setupapi] SetupQueueDeleteSectionW QueueHandle=0x%x InfHandle=0x%x ListInfHandle=0x%x Section=0x%x\n", QueueHandle, InfHandle, ListInfHandle, Section)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueDeleteW", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		PathPart1 := ctx.Arg(1)
		PathPart2 := ctx.Arg(2)
		_ = QueueHandle
		_ = PathPart1
		_ = PathPart2
		ravelog.Logf("[setupapi] SetupQueueDeleteW QueueHandle=0x%x PathPart1=0x%x PathPart2=0x%x\n", QueueHandle, PathPart1, PathPart2)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueRenameA", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		SourcePath := ctx.Arg(1)
		SourceFilename := ctx.Arg(2)
		TargetPath := ctx.Arg(3)
		TargetFilename := ctx.Arg(4)
		_ = QueueHandle
		_ = SourcePath
		_ = SourceFilename
		_ = TargetPath
		_ = TargetFilename
		ravelog.Logf("[setupapi] SetupQueueRenameA QueueHandle=0x%x SourcePath=0x%x SourceFilename=0x%x TargetPath=0x%x TargetFilename=0x%x\n", QueueHandle, SourcePath, SourceFilename, TargetPath, TargetFilename)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueRenameSectionA", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		InfHandle := ctx.Arg(1)
		ListInfHandle := ctx.Arg(2)
		Section := ctx.Arg(3)
		_ = QueueHandle
		_ = InfHandle
		_ = ListInfHandle
		_ = Section
		ravelog.Logf("[setupapi] SetupQueueRenameSectionA QueueHandle=0x%x InfHandle=0x%x ListInfHandle=0x%x Section=0x%x\n", QueueHandle, InfHandle, ListInfHandle, Section)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueRenameSectionW", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		InfHandle := ctx.Arg(1)
		ListInfHandle := ctx.Arg(2)
		Section := ctx.Arg(3)
		_ = QueueHandle
		_ = InfHandle
		_ = ListInfHandle
		_ = Section
		ravelog.Logf("[setupapi] SetupQueueRenameSectionW QueueHandle=0x%x InfHandle=0x%x ListInfHandle=0x%x Section=0x%x\n", QueueHandle, InfHandle, ListInfHandle, Section)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueRenameW", func(ctx *ntapi.TrapContext) uint32 {
		QueueHandle := ctx.Arg(0)
		SourcePath := ctx.Arg(1)
		SourceFilename := ctx.Arg(2)
		TargetPath := ctx.Arg(3)
		TargetFilename := ctx.Arg(4)
		_ = QueueHandle
		_ = SourcePath
		_ = SourceFilename
		_ = TargetPath
		_ = TargetFilename
		ravelog.Logf("[setupapi] SetupQueueRenameW QueueHandle=0x%x SourcePath=0x%x SourceFilename=0x%x TargetPath=0x%x TargetFilename=0x%x\n", QueueHandle, SourcePath, SourceFilename, TargetPath, TargetFilename)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] -stub arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] -stub arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupRenameErrorA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupRenameErrorA arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupRenameErrorW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupRenameErrorW arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupScanFileQueue", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[setupapi] SetupScanFileQueue arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n", arg0, arg1, arg2, arg3, arg4, arg5)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupScanFileQueueA", func(ctx *ntapi.TrapContext) uint32 {
		FileQueue := ctx.Arg(0)
		Flags := ctx.Arg(1)
		Window := ctx.Arg(2)
		CallbackRoutine := ctx.Arg(3)
		CallbackContext := ctx.Arg(4)
		Result := ctx.Arg(5)
		_ = FileQueue
		_ = Flags
		_ = Window
		_ = CallbackRoutine
		_ = CallbackContext
		_ = Result
		ravelog.Logf("[setupapi] SetupScanFileQueueA FileQueue=0x%x Flags=0x%x Window=0x%x CallbackRoutine=0x%x CallbackContext=0x%x Result=0x%x\n", FileQueue, Flags, Window, CallbackRoutine, CallbackContext, Result)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupScanFileQueueW", func(ctx *ntapi.TrapContext) uint32 {
		FileQueue := ctx.Arg(0)
		Flags := ctx.Arg(1)
		Window := ctx.Arg(2)
		CallbackRoutine := ctx.Arg(3)
		CallbackContext := ctx.Arg(4)
		Result := ctx.Arg(5)
		_ = FileQueue
		_ = Flags
		_ = Window
		_ = CallbackRoutine
		_ = CallbackContext
		_ = Result
		ravelog.Logf("[setupapi] SetupScanFileQueueW FileQueue=0x%x Flags=0x%x Window=0x%x CallbackRoutine=0x%x CallbackContext=0x%x Result=0x%x\n", FileQueue, Flags, Window, CallbackRoutine, CallbackContext, Result)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetDirectoryIdA", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		Id := ctx.Arg(1)
		Directory := ctx.Arg(2)
		_ = InfHandle
		_ = Id
		_ = Directory
		ravelog.Logf("[setupapi] SetupSetDirectoryIdA InfHandle=0x%x Id=0x%x Directory=0x%x\n", InfHandle, Id, Directory)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetDirectoryIdW", func(ctx *ntapi.TrapContext) uint32 {
		InfHandle := ctx.Arg(0)
		Id := ctx.Arg(1)
		Directory := ctx.Arg(2)
		_ = InfHandle
		_ = Id
		_ = Directory
		ravelog.Logf("[setupapi] SetupSetDirectoryIdW InfHandle=0x%x Id=0x%x Directory=0x%x\n", InfHandle, Id, Directory)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetFileQueueAlternatePlatformA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] SetupSetFileQueueAlternatePlatformA arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetFileQueueAlternatePlatformW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] SetupSetFileQueueAlternatePlatformW arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetFileQueueFlags", func(ctx *ntapi.TrapContext) uint32 {
		FileQueue := ctx.Arg(0)
		FlagMask := ctx.Arg(1)
		Flags := ctx.Arg(2)
		_ = FileQueue
		_ = FlagMask
		_ = Flags
		ravelog.Logf("[setupapi] SetupSetFileQueueFlags FileQueue=0x%x FlagMask=0x%x Flags=0x%x\n", FileQueue, FlagMask, Flags)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetNonInteractiveMode", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] SetupSetNonInteractiveMode arg0=0x%x\n", arg0)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetSourceListA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] SetupSetSourceListA arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetSourceListW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] SetupSetSourceListW arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// TRUE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupTermDefaultQueueCallback", func(ctx *ntapi.TrapContext) uint32 {
		Context := ctx.Arg(0)
		_ = Context
		ravelog.Logf("[setupapi] SetupTermDefaultQueueCallback Context=0x%x\n", Context)
		// void/0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupTerminateFileLog", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] SetupTerminateFileLog arg0=0x%x\n", arg0)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupUninstallOEMInfA", func(ctx *ntapi.TrapContext) uint32 {
		InfFileName := ctx.Arg(0)
		Flags := ctx.Arg(1)
		Reserved := ctx.Arg(2)
		_ = InfFileName
		_ = Flags
		_ = Reserved
		ravelog.Logf("[setupapi] SetupUninstallOEMInfA InfFileName=0x%x Flags=0x%x Reserved=0x%x\n", InfFileName, Flags, Reserved)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupUninstallOEMInfW", func(ctx *ntapi.TrapContext) uint32 {
		InfFileName := ctx.Arg(0)
		Flags := ctx.Arg(1)
		Reserved := ctx.Arg(2)
		_ = InfFileName
		_ = Flags
		_ = Reserved
		ravelog.Logf("[setupapi] SetupUninstallOEMInfW InfFileName=0x%x Flags=0x%x Reserved=0x%x\n", InfFileName, Flags, Reserved)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupVerifyInfFileA", func(ctx *ntapi.TrapContext) uint32 {
		InfName := ctx.Arg(0)
		AltPlatformInfo := ctx.Arg(1)
		InfSignerInfo := ctx.Arg(2)
		_ = InfName
		_ = AltPlatformInfo
		_ = InfSignerInfo
		ravelog.Logf("[setupapi] SetupVerifyInfFileA InfName=0x%x AltPlatformInfo=0x%x InfSignerInfo=0x%x\n", InfName, AltPlatformInfo, InfSignerInfo)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupVerifyInfFileW", func(ctx *ntapi.TrapContext) uint32 {
		InfName := ctx.Arg(0)
		AltPlatformInfo := ctx.Arg(1)
		InfSignerInfo := ctx.Arg(2)
		_ = InfName
		_ = AltPlatformInfo
		_ = InfSignerInfo
		ravelog.Logf("[setupapi] SetupVerifyInfFileW InfName=0x%x AltPlatformInfo=0x%x InfSignerInfo=0x%x\n", InfName, AltPlatformInfo, InfSignerInfo)
		// FALSE
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "UnicodeToMultiByte", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] UnicodeToMultiByte arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupCaptureAndConvertAnsiArg", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] pSetupCaptureAndConvertAnsiArg arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupCenterWindowRelativeToParent", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] pSetupCenterWindowRelativeToParent arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupConcatenatePaths", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] pSetupConcatenatePaths arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupDoesUserHavePrivilege", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] pSetupDoesUserHavePrivilege arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupDuplicateString", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] pSetupDuplicateString arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupEnablePrivilege", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] pSetupEnablePrivilege arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupFree", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] pSetupFree arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupGetField", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] pSetupGetField arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupGetFileTitle", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] pSetupGetFileTitle arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupGetGlobalFlags", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] pSetupGetGlobalFlags\n")
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupGetQueueFlags", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] pSetupGetQueueFlags arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupGetVersionInfoFromImage", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] pSetupGetVersionInfoFromImage arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupGuidFromString", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] pSetupGuidFromString arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupInstallCatalog", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] pSetupInstallCatalog arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupIsGuidNull", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] pSetupIsGuidNull arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupIsUserAdmin", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] pSetupIsUserAdmin\n")
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupMalloc", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] pSetupMalloc arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupModifyGlobalFlags", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] pSetupModifyGlobalFlags arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupMultiByteToUnicode", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] pSetupMultiByteToUnicode arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupOpenAndMapFileForRead", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] pSetupOpenAndMapFileForRead arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupRealloc", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] pSetupRealloc arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupRegistryDelnode", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] pSetupRegistryDelnode arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupSetGlobalFlags", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] pSetupSetGlobalFlags arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupSetQueueFlags", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] pSetupSetQueueFlags arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringFromGuid", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] pSetupStringFromGuid arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableAddString", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] pSetupStringTableAddString arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableAddStringEx", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] pSetupStringTableAddStringEx arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableDestroy", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] pSetupStringTableDestroy arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableDuplicate", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[setupapi] pSetupStringTableDuplicate arg0=0x%x\n", arg0)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableGetExtraData", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] pSetupStringTableGetExtraData arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableInitialize", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] pSetupStringTableInitialize\n")
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableInitializeEx", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] pSetupStringTableInitializeEx arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableLookUpString", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] pSetupStringTableLookUpString arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableLookUpStringEx", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[setupapi] pSetupStringTableLookUpStringEx arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x\n", arg0, arg1, arg2, arg3, arg4)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableSetExtraData", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] pSetupStringTableSetExtraData arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableStringFromId", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] pSetupStringTableStringFromId arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableStringFromIdEx", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[setupapi] pSetupStringTableStringFromIdEx arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupUnicodeToMultiByte", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		_ = arg0
		_ = arg1
		ravelog.Logf("[setupapi] pSetupUnicodeToMultiByte arg0=0x%x arg1=0x%x\n", arg0, arg1)
		// 0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupUnmapAndCloseFile", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[setupapi] pSetupUnmapAndCloseFile arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// 0
		ctx.SetReturn(0)
		return 0
	})
}
