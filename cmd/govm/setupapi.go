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
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CMP_GetBlockedDriverInfo(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_GetServerSideDeviceInstallFlags", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CMP_GetServerSideDeviceInstallFlags(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_Init_Detection", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] CMP_Init_Detection(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_RegisterNotification", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CMP_RegisterNotification(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_Report_LogOn", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CMP_Report_LogOn(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_UnregisterNotification", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] CMP_UnregisterNotification(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_WaitNoPendingInstallEvents", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] CMP_WaitNoPendingInstallEvents(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CMP_WaitServicesAvailable", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] CMP_WaitServicesAvailable(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_Empty_Log_Conf", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Add_Empty_Log_Conf(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_Empty_Log_Conf_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Add_Empty_Log_Conf_Ex(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_IDA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Add_IDA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_IDW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Add_IDW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_ID_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Add_ID_ExA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_ID_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Add_ID_ExW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_Range", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Add_Range(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_Res_Des", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Add_Res_Des(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Add_Res_Des_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Add_Res_Des_Ex(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Connect_MachineA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Connect_MachineA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Connect_MachineW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Connect_MachineW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Create_DevNodeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Create_DevNodeA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Create_DevNodeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Create_DevNodeW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Create_DevNode_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Create_DevNode_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Create_DevNode_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Create_DevNode_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Create_Range_List", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Create_Range_List(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Delete_Class_Key", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Delete_Class_Key(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Delete_Class_Key_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Delete_Class_Key_Ex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Delete_DevNode_Key", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Delete_DevNode_Key(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Delete_DevNode_Key_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Delete_DevNode_Key_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Delete_Range", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Delete_Range(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Detect_Resource_Conflict", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Detect_Resource_Conflict(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Detect_Resource_Conflict_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Detect_Resource_Conflict_Ex(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Disable_DevNode", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Disable_DevNode(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Disable_DevNode_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Disable_DevNode_Ex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Disconnect_Machine", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] CM_Disconnect_Machine(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Dup_Range_List", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Dup_Range_List(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enable_DevNode", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Enable_DevNode(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enable_DevNode_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Enable_DevNode_Ex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enumerate_Classes", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Enumerate_Classes(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enumerate_Classes_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Enumerate_Classes_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enumerate_EnumeratorsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Enumerate_EnumeratorsA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enumerate_EnumeratorsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Enumerate_EnumeratorsW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enumerate_Enumerators_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Enumerate_Enumerators_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Enumerate_Enumerators_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Enumerate_Enumerators_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Find_Range", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Find_Range(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_First_Range", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_First_Range(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Log_Conf", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Free_Log_Conf(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Log_Conf_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Free_Log_Conf_Ex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Log_Conf_Handle", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] CM_Free_Log_Conf_Handle(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Range_List", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Free_Range_List(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Res_Des", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Free_Res_Des(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Res_Des_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Free_Res_Des_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Res_Des_Handle", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] CM_Free_Res_Des_Handle(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Free_Resource_Conflict_Handle", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] CM_Free_Resource_Conflict_Handle(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Child", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Child(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Child_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Child_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Key_NameA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Class_Key_NameA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Key_NameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Class_Key_NameW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Key_Name_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Class_Key_Name_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Key_Name_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Class_Key_Name_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_NameA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Class_NameA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_NameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Class_NameW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Name_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Class_Name_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Name_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Class_Name_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Registry_PropertyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_Class_Registry_PropertyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Class_Registry_PropertyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_Class_Registry_PropertyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Depth", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Depth(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Depth_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Depth_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Custom_PropertyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_DevNode_Custom_PropertyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Custom_PropertyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_DevNode_Custom_PropertyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Custom_Property_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_DevNode_Custom_Property_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Custom_Property_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_DevNode_Custom_Property_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Registry_PropertyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_DevNode_Registry_PropertyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Registry_PropertyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_DevNode_Registry_PropertyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Registry_Property_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_DevNode_Registry_Property_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Registry_Property_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_DevNode_Registry_Property_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Status", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_DevNode_Status(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_DevNode_Status_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_DevNode_Status_Ex(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_IDA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Device_IDA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_IDW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Device_IDW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Device_ID_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Device_ID_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_ListA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Device_ID_ListA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_ListW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Device_ID_ListW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_List_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Device_ID_List_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_List_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Device_ID_List_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_List_SizeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Device_ID_List_SizeA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_List_SizeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Device_ID_List_SizeW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_List_Size_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Device_ID_List_Size_ExA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_List_Size_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Device_ID_List_Size_ExW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_Size", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Device_ID_Size(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_ID_Size_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Device_ID_Size_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_AliasA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_AliasA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_AliasW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_AliasW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_Alias_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_Alias_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_Alias_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_Alias_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_ListA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_ListA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_ListW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_ListW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_List_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_List_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_List_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_List_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_List_SizeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_List_SizeA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_List_SizeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_List_SizeW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_List_Size_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_List_Size_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Device_Interface_List_Size_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Device_Interface_List_Size_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_First_Log_Conf", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_First_Log_Conf(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_First_Log_Conf_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_First_Log_Conf_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Global_State", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Get_Global_State(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Global_State_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Global_State_Ex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_HW_Prof_FlagsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_HW_Prof_FlagsA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_HW_Prof_FlagsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_HW_Prof_FlagsW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_HW_Prof_Flags_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_HW_Prof_Flags_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_HW_Prof_Flags_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_HW_Prof_Flags_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Hardware_Profile_InfoA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Hardware_Profile_InfoA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Hardware_Profile_InfoW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Hardware_Profile_InfoW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Hardware_Profile_Info_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Hardware_Profile_Info_ExA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Hardware_Profile_Info_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Hardware_Profile_Info_ExW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Log_Conf_Priority", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Log_Conf_Priority(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Log_Conf_Priority_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Log_Conf_Priority_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Next_Log_Conf", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Next_Log_Conf(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Next_Log_Conf_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Next_Log_Conf_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Next_Res_Des", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Next_Res_Des(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Next_Res_Des_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Get_Next_Res_Des_Ex(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Parent", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Parent(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Parent_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Parent_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Res_Des_Data", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Res_Des_Data(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Res_Des_Data_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Get_Res_Des_Data_Ex(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Res_Des_Data_Size", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Res_Des_Data_Size(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Res_Des_Data_Size_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Res_Des_Data_Size_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Resource_Conflict_Count", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Get_Resource_Conflict_Count(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Resource_Conflict_DetailsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Resource_Conflict_DetailsA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Resource_Conflict_DetailsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Resource_Conflict_DetailsW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Sibling", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Get_Sibling(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Sibling_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Get_Sibling_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Version", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] CM_Get_Version()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Get_Version_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] CM_Get_Version_Ex(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Intersect_Range_List", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Intersect_Range_List(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Invert_Range_List", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Invert_Range_List(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Is_Dock_Station_Present", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] CM_Is_Dock_Station_Present(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Is_Dock_Station_Present_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Is_Dock_Station_Present_Ex(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Is_Version_Available", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] CM_Is_Version_Available(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Is_Version_Available_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Is_Version_Available_Ex(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Locate_DevNodeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Locate_DevNodeA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Locate_DevNodeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Locate_DevNodeW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Locate_DevNode_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Locate_DevNode_ExA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Locate_DevNode_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Locate_DevNode_ExW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Merge_Range_List", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Merge_Range_List(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Modify_Res_Des", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Modify_Res_Des(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Modify_Res_Des_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Modify_Res_Des_Ex(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Move_DevNode", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Move_DevNode(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Move_DevNode_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Move_DevNode_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Next_Range", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Next_Range(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Open_Class_KeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Open_Class_KeyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Open_Class_KeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Open_Class_KeyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Open_Class_Key_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Open_Class_Key_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Open_Class_Key_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Open_Class_Key_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Open_DevNode_Key", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Open_DevNode_Key(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Open_DevNode_Key_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Open_DevNode_Key_Ex(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_And_Remove_SubTreeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Query_And_Remove_SubTreeA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_And_Remove_SubTreeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Query_And_Remove_SubTreeW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_And_Remove_SubTree_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Query_And_Remove_SubTree_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_And_Remove_SubTree_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Query_And_Remove_SubTree_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Arbitrator_Free_Data", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Query_Arbitrator_Free_Data(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Arbitrator_Free_Data_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Query_Arbitrator_Free_Data_Ex(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Arbitrator_Free_Size", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Query_Arbitrator_Free_Size(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Arbitrator_Free_Size_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Query_Arbitrator_Free_Size_Ex(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Remove_SubTree", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Query_Remove_SubTree(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Remove_SubTree_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Query_Remove_SubTree_Ex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Query_Resource_Conflict_List", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Query_Resource_Conflict_List(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Reenumerate_DevNode", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Reenumerate_DevNode(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Reenumerate_DevNode_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Reenumerate_DevNode_Ex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Register_Device_Driver", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Register_Device_Driver(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Register_Device_Driver_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Register_Device_Driver_Ex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Register_Device_InterfaceA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Register_Device_InterfaceA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Register_Device_InterfaceW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Register_Device_InterfaceW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Register_Device_Interface_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Register_Device_Interface_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Register_Device_Interface_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Register_Device_Interface_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Remove_SubTree", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Remove_SubTree(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Remove_SubTree_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Remove_SubTree_Ex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Request_Device_EjectA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Request_Device_EjectA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Request_Device_EjectW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Request_Device_EjectW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Request_Device_Eject_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Request_Device_Eject_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Request_Device_Eject_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Request_Device_Eject_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Request_Eject_PC", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] CM_Request_Eject_PC()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Request_Eject_PC_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] CM_Request_Eject_PC_Ex(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Run_Detection", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] CM_Run_Detection(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Run_Detection_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Run_Detection_Ex(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_Class_Registry_PropertyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Set_Class_Registry_PropertyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_Class_Registry_PropertyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Set_Class_Registry_PropertyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_DevNode_Problem", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Set_DevNode_Problem(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_DevNode_Problem_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Set_DevNode_Problem_Ex(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_DevNode_Registry_PropertyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Set_DevNode_Registry_PropertyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_DevNode_Registry_PropertyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Set_DevNode_Registry_PropertyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_DevNode_Registry_Property_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Set_DevNode_Registry_Property_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_DevNode_Registry_Property_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] CM_Set_DevNode_Registry_Property_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_HW_Prof", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Set_HW_Prof(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_HW_Prof_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Set_HW_Prof_Ex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_HW_Prof_FlagsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Set_HW_Prof_FlagsA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_HW_Prof_FlagsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Set_HW_Prof_FlagsW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_HW_Prof_Flags_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Set_HW_Prof_Flags_ExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Set_HW_Prof_Flags_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] CM_Set_HW_Prof_Flags_ExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Setup_DevNode", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Setup_DevNode(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Setup_DevNode_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Setup_DevNode_Ex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Test_Range_Available", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] CM_Test_Range_Available(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Uninstall_DevNode", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Uninstall_DevNode(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Uninstall_DevNode_Ex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Uninstall_DevNode_Ex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Unregister_Device_InterfaceA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Unregister_Device_InterfaceA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Unregister_Device_InterfaceW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] CM_Unregister_Device_InterfaceW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Unregister_Device_Interface_ExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Unregister_Device_Interface_ExA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CM_Unregister_Device_Interface_ExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] CM_Unregister_Device_Interface_ExW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DoesUserHavePrivilege", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] DoesUserHavePrivilege(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InstallCatalog", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] InstallCatalog(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InstallHinfSection", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] InstallHinfSection(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InstallHinfSectionA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] InstallHinfSectionA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InstallHinfSectionW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] InstallHinfSectionW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "IsUserAdmin", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] IsUserAdmin()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "MyFree", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] MyFree(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "MyMalloc", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] MyMalloc(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "MyRealloc", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] MyRealloc(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupAddInstallSectionToDiskSpaceListA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupAddInstallSectionToDiskSpaceListA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] -stub(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupAddToDiskSpaceListA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupAddToDiskSpaceListA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupAddToDiskSpaceListW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupAddToDiskSpaceListW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupAddToSourceListA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupAddToSourceListA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupAddToSourceListW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupAddToSourceListW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCloseFileQueue", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupCloseFileQueue(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCloseInfFile", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupCloseInfFile(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCloseLog", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] SetupCloseLog()\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCommitFileQueue", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupCommitFileQueue(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCommitFileQueueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupCommitFileQueueA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCommitFileQueueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupCommitFileQueueW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCopyErrorA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupCopyErrorA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCopyErrorW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupCopyErrorW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCopyOEMInfA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupCopyOEMInfA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCopyOEMInfW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupCopyOEMInfW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCreateDiskSpaceListA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupCreateDiskSpaceListA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupCreateDiskSpaceListW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupCreateDiskSpaceListW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDecompressOrCopyFileA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDecompressOrCopyFileA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDecompressOrCopyFileW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDecompressOrCopyFileW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDefaultQueueCallback", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDefaultQueueCallback(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDefaultQueueCallbackA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDefaultQueueCallbackA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDefaultQueueCallbackW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDefaultQueueCallbackW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDeleteErrorA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDeleteErrorA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDeleteErrorW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDeleteErrorW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDestroyDiskSpaceList", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupDestroyDiskSpaceList(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiBuildClassInfoList", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiBuildClassInfoList(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiBuildClassInfoListExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiBuildClassInfoListExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiBuildClassInfoListExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiBuildClassInfoListExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiBuildDriverInfoList", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiBuildDriverInfoList(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCallClassInstaller", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiCallClassInstaller(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiChangeState", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiChangeState(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassGuidsFromNameA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiClassGuidsFromNameA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassGuidsFromNameExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiClassGuidsFromNameExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassGuidsFromNameExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiClassGuidsFromNameExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassGuidsFromNameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiClassGuidsFromNameW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassNameFromGuidA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiClassNameFromGuidA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassNameFromGuidExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiClassNameFromGuidExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassNameFromGuidExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiClassNameFromGuidExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiClassNameFromGuidW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiClassNameFromGuidW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDevRegKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiCreateDevRegKeyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDevRegKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiCreateDevRegKeyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInfoA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInfoA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInfoList", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInfoList(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInfoListExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInfoListExA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInfoListExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInfoListExW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInfoW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInfoW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInterfaceA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInterfaceA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInterfaceRegKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInterfaceRegKeyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInterfaceRegKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInterfaceRegKeyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiCreateDeviceInterfaceW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiCreateDeviceInterfaceW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDeleteDevRegKey", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiDeleteDevRegKey(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDeleteDeviceInfo", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiDeleteDeviceInfo(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDeleteDeviceInterfaceData", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiDeleteDeviceInterfaceData(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDeleteDeviceInterfaceRegKey", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiDeleteDeviceInterfaceRegKey(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDestroyClassImageList", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupDiDestroyClassImageList(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDestroyDeviceInfoList", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupDiDestroyDeviceInfoList(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiDestroyDriverInfoList", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiDestroyDriverInfoList(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiEnumDeviceInfo", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiEnumDeviceInfo(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiEnumDeviceInterfaces", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiEnumDeviceInterfaces(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiEnumDriverInfoA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiEnumDriverInfoA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiEnumDriverInfoW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiEnumDriverInfoW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetActualSectionToInstallA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetActualSectionToInstallA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetActualSectionToInstallExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetActualSectionToInstallExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetActualSectionToInstallExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetActualSectionToInstallExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetActualSectionToInstallW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetActualSectionToInstallW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDescriptionA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiGetClassDescriptionA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDescriptionExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetClassDescriptionExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDescriptionExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetClassDescriptionExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDescriptionW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiGetClassDescriptionW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDevPropertySheetsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetClassDevPropertySheetsA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDevPropertySheetsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetClassDevPropertySheetsW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDevsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiGetClassDevsA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDevsExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetClassDevsExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDevsExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetClassDevsExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassDevsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiGetClassDevsW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassImageIndex", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiGetClassImageIndex(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassImageList", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupDiGetClassImageList(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassImageListExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiGetClassImageListExA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassImageListExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiGetClassImageListExW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassInstallParamsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiGetClassInstallParamsA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassInstallParamsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiGetClassInstallParamsW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassRegistryPropertyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetClassRegistryPropertyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetClassRegistryPropertyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetClassRegistryPropertyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetCustomDevicePropertyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetCustomDevicePropertyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetCustomDevicePropertyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetCustomDevicePropertyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInfoListClass", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiGetDeviceInfoListClass(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInfoListDetailA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiGetDeviceInfoListDetailA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInfoListDetailW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiGetDeviceInfoListDetailW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInstallParamsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiGetDeviceInstallParamsA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInstallParamsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiGetDeviceInstallParamsW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInstanceIdA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiGetDeviceInstanceIdA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInstanceIdW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiGetDeviceInstanceIdW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInterfaceAlias", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiGetDeviceInterfaceAlias(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInterfaceDetailA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetDeviceInterfaceDetailA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceInterfaceDetailW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetDeviceInterfaceDetailW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceRegistryPropertyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetDeviceRegistryPropertyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDeviceRegistryPropertyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetDeviceRegistryPropertyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDriverInfoDetailA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetDriverInfoDetailA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDriverInfoDetailW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiGetDriverInfoDetailW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetDriverInstallParamsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiGetDriverInstallParamsW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetINFClassA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiGetINFClassA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetINFClassW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiGetINFClassW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetSelectedDevice", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiGetSelectedDevice(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetSelectedDriverA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiGetSelectedDriverA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiGetSelectedDriverW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiGetSelectedDriverW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallClassA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiInstallClassA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallClassExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiInstallClassExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallClassExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiInstallClassExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallClassW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiInstallClassW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallDevice", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiInstallDevice(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallDeviceInterfaces", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiInstallDeviceInterfaces(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiInstallDriverFiles", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiInstallDriverFiles(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiLoadClassIcon", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiLoadClassIcon(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenClassRegKey", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiOpenClassRegKey(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenClassRegKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiOpenClassRegKeyExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenClassRegKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiOpenClassRegKeyExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenDevRegKey", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiOpenDevRegKey(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenDeviceInfoA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiOpenDeviceInfoA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenDeviceInfoW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiOpenDeviceInfoW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenDeviceInterfaceA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiOpenDeviceInterfaceA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenDeviceInterfaceRegKey", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiOpenDeviceInterfaceRegKey(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiOpenDeviceInterfaceW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiOpenDeviceInterfaceW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiRegisterCoDeviceInstallers", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiRegisterCoDeviceInstallers(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiRegisterDeviceInfo", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiRegisterDeviceInfo(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiRemoveDevice", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiRemoveDevice(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiRemoveDeviceInterface", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiRemoveDeviceInterface(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-version=0x502+", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] -version=0x502+(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSelectBestCompatDrv", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiSelectBestCompatDrv(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSelectDevice", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiSelectDevice(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetClassInstallParamsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiSetClassInstallParamsA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetClassInstallParamsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiSetClassInstallParamsW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetClassRegistryPropertyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiSetClassRegistryPropertyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetClassRegistryPropertyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupDiSetClassRegistryPropertyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetDeviceInstallParamsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiSetDeviceInstallParamsA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetDeviceInstallParamsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiSetDeviceInstallParamsW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetDeviceRegistryPropertyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiSetDeviceRegistryPropertyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetDeviceRegistryPropertyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupDiSetDeviceRegistryPropertyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetDriverInstallParamsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiSetDriverInstallParamsA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetDriverInstallParamsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDiSetDriverInstallParamsW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetSelectedDevice", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiSetSelectedDevice(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetSelectedDriverA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiSetSelectedDriverA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiSetSelectedDriverW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupDiSetSelectedDriverW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDiUnremoveDevice", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupDiUnremoveDevice(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDuplicateDiskSpaceListA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDuplicateDiskSpaceListA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupDuplicateDiskSpaceListW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupDuplicateDiskSpaceListW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupEnumInfSectionsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupEnumInfSectionsA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupEnumInfSectionsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupEnumInfSectionsW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupFindFirstLineA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupFindFirstLineA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupFindFirstLineW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupFindFirstLineW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupFindNextLine", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupFindNextLine(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupFindNextMatchLineA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupFindNextMatchLineA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupFindNextMatchLineW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupFindNextMatchLineW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetBinaryField", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupGetBinaryField(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFieldCount", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupGetFieldCount(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFileCompressionInfoA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupGetFileCompressionInfoA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFileCompressionInfoExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupGetFileCompressionInfoExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFileCompressionInfoExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupGetFileCompressionInfoExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFileCompressionInfoW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupGetFileCompressionInfoW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFileQueueCount", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupGetFileQueueCount(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetFileQueueFlags", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupGetFileQueueFlags(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetInfFileListA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupGetInfFileListA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetInfFileListW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupGetInfFileListW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetInfInformationA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupGetInfInformationA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetInfInformationW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupGetInfInformationW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetIntField", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupGetIntField(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetLineByIndexA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupGetLineByIndexA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetLineByIndexW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupGetLineByIndexW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetLineCountA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupGetLineCountA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetLineCountW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupGetLineCountW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetLineTextA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupGetLineTextA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetLineTextW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupGetLineTextW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetMultiSzFieldA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupGetMultiSzFieldA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetMultiSzFieldW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupGetMultiSzFieldW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetNonInteractiveMode", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] SetupGetNonInteractiveMode()\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetSourceFileLocationA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupGetSourceFileLocationA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetSourceFileLocationW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupGetSourceFileLocationW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetSourceInfoA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupGetSourceInfoA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetSourceInfoW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupGetSourceInfoW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetStringFieldA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupGetStringFieldA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetStringFieldW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupGetStringFieldW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetTargetPathA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupGetTargetPathA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupGetTargetPathW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupGetTargetPathW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInitDefaultQueueCallback", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupInitDefaultQueueCallback(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInitDefaultQueueCallbackEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupInitDefaultQueueCallbackEx(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInitializeFileLogA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupInitializeFileLogA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInitializeFileLogW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupInitializeFileLogW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallFileA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupInstallFileA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallFileW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupInstallFileW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallFilesFromInfSectionA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupInstallFilesFromInfSectionA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallFilesFromInfSectionW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupInstallFilesFromInfSectionW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallFromInfSectionA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupInstallFromInfSectionA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallFromInfSectionW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupInstallFromInfSectionW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallServicesFromInfSectionA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupInstallServicesFromInfSectionA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallServicesFromInfSectionExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupInstallServicesFromInfSectionExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallServicesFromInfSectionExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupInstallServicesFromInfSectionExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupInstallServicesFromInfSectionW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupInstallServicesFromInfSectionW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupIterateCabinetA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupIterateCabinetA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupIterateCabinetW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupIterateCabinetW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupLogErrorA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupLogErrorA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupLogErrorW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] SetupLogErrorW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenAppendInfFileA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupOpenAppendInfFileA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenAppendInfFileW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupOpenAppendInfFileW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenFileQueue", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] SetupOpenFileQueue()\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenInfFileA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupOpenInfFileA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenInfFileW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupOpenInfFileW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenLog", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupOpenLog(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupOpenMasterInf", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] SetupOpenMasterInf()\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupPromptForDiskA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupPromptForDiskA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupPromptForDiskW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupPromptForDiskW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupPromptReboot", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupPromptReboot(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] -stub(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueryInfFileInformationA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupQueryInfFileInformationA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueryInfFileInformationW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupQueryInfFileInformationW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueryInfOriginalFileInformationA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupQueryInfOriginalFileInformationA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueryInfOriginalFileInformationW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupQueryInfOriginalFileInformationW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueryInfVersionInformationA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupQueryInfVersionInformationA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueryInfVersionInformationW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupQueryInfVersionInformationW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQuerySpaceRequiredOnDriveA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupQuerySpaceRequiredOnDriveA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQuerySpaceRequiredOnDriveW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupQuerySpaceRequiredOnDriveW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueCopyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupQueueCopyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueCopyIndirectA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupQueueCopyIndirectA(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueCopyIndirectW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupQueueCopyIndirectW(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueCopySectionA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupQueueCopySectionA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueCopySectionW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupQueueCopySectionW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueCopyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupQueueCopyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueDefaultCopyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupQueueDefaultCopyA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueDefaultCopyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupQueueDefaultCopyW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueDeleteA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupQueueDeleteA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueDeleteSectionA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupQueueDeleteSectionA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueDeleteSectionW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupQueueDeleteSectionW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueDeleteW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupQueueDeleteW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueRenameA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupQueueRenameA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueRenameSectionA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupQueueRenameSectionA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueRenameSectionW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] SetupQueueRenameSectionW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupQueueRenameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] SetupQueueRenameW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] -stub(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] -stub(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupRenameErrorA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupRenameErrorA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupRenameErrorW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupRenameErrorW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupScanFileQueue", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupScanFileQueue(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupScanFileQueueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupScanFileQueueA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupScanFileQueueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[setupapi] SetupScanFileQueueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetDirectoryIdA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupSetDirectoryIdA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetDirectoryIdW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupSetDirectoryIdW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetFileQueueAlternatePlatformA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupSetFileQueueAlternatePlatformA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetFileQueueAlternatePlatformW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupSetFileQueueAlternatePlatformW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetFileQueueFlags", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupSetFileQueueFlags(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetNonInteractiveMode", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupSetNonInteractiveMode(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetSourceListA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupSetSourceListA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupSetSourceListW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupSetSourceListW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupTermDefaultQueueCallback", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupTermDefaultQueueCallback(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupTerminateFileLog", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] SetupTerminateFileLog(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupUninstallOEMInfA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupUninstallOEMInfA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupUninstallOEMInfW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupUninstallOEMInfW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupVerifyInfFileA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupVerifyInfFileA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetupVerifyInfFileW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] SetupVerifyInfFileW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "UnicodeToMultiByte", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] UnicodeToMultiByte(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupCaptureAndConvertAnsiArg", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] pSetupCaptureAndConvertAnsiArg(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupCenterWindowRelativeToParent", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] pSetupCenterWindowRelativeToParent(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupConcatenatePaths", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] pSetupConcatenatePaths(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupDoesUserHavePrivilege", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] pSetupDoesUserHavePrivilege(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupDuplicateString", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] pSetupDuplicateString(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupEnablePrivilege", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] pSetupEnablePrivilege(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupFree", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] pSetupFree(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupGetField", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] pSetupGetField(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupGetFileTitle", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] pSetupGetFileTitle(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupGetGlobalFlags", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] pSetupGetGlobalFlags()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupGetQueueFlags", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] pSetupGetQueueFlags(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupGetVersionInfoFromImage", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] pSetupGetVersionInfoFromImage(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupGuidFromString", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] pSetupGuidFromString(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupInstallCatalog", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] pSetupInstallCatalog(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupIsGuidNull", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] pSetupIsGuidNull(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupIsUserAdmin", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] pSetupIsUserAdmin()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupMalloc", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] pSetupMalloc(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupModifyGlobalFlags", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] pSetupModifyGlobalFlags(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupMultiByteToUnicode", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] pSetupMultiByteToUnicode(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupOpenAndMapFileForRead", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] pSetupOpenAndMapFileForRead(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupRealloc", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] pSetupRealloc(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupRegistryDelnode", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] pSetupRegistryDelnode(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupSetGlobalFlags", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] pSetupSetGlobalFlags(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupSetQueueFlags", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] pSetupSetQueueFlags(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringFromGuid", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] pSetupStringFromGuid(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableAddString", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] pSetupStringTableAddString(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableAddStringEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] pSetupStringTableAddStringEx(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableDestroy", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] pSetupStringTableDestroy(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableDuplicate", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[setupapi] pSetupStringTableDuplicate(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableGetExtraData", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] pSetupStringTableGetExtraData(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableInitialize", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[setupapi] pSetupStringTableInitialize()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableInitializeEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] pSetupStringTableInitializeEx(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableLookUpString", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] pSetupStringTableLookUpString(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableLookUpStringEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[setupapi] pSetupStringTableLookUpStringEx(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableSetExtraData", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] pSetupStringTableSetExtraData(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableStringFromId", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] pSetupStringTableStringFromId(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupStringTableStringFromIdEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[setupapi] pSetupStringTableStringFromIdEx(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupUnicodeToMultiByte", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[setupapi] pSetupUnicodeToMultiByte(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "pSetupUnmapAndCloseFile", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[setupapi] pSetupUnmapAndCloseFile(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
}
