//go:build guest_windows

package main

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

var IID_IAccessible = GUID{0x618736E0, 0x3C3D, 0x11CF, [8]byte{0x81, 0x0C, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}}

const (
	roleSystemWindow  = 0x09
	stateSystemNormal = 0x00000000
	accMethodCount    = 24
	accTrapIDBase     = 0x13000000
)

type accState struct {
	mu      sync.Mutex
	nextObj uint32
	objects map[uint32]*accObject
}

type accObject struct {
	hwnd  uint64
	role  uint32
	name  string
	state uint32
}

type accCOMObject struct {
	objID    uint32
	refCount uint32
}

var accGlobal = accState{nextObj: 0x9000, objects: make(map[uint32]*accObject)}

var (
	accCOMMu         sync.Mutex
	accCOMObjects    = map[uint64]*accCOMObject{}
	accCOMVTableAddr uint64
	accCOMNextTrapID uint32 = accTrapIDBase
	accLresultMap           = map[uint64]uint64{}
)

var roleText = map[uint32]string{
	0x09: "window", 0x0A: "title bar", 0x0B: "menu bar",
	0x0C: "menu item", 0x0D: "menu popup", 0x2B: "push button",
	0x2C: "editable text", 0x2E: "check box", 0x30: "radio button",
	0x31: "combo box", 0x22: "list item", 0x21: "list",
	0x33: "status bar", 0x3E: "client", 0x28: "text",
}

var stateText = map[uint32]string{
	0x00000000: "normal", 0x00000001: "unavailable",
	0x00000002: "selected", 0x00000004: "focused",
	0x00000010: "checked", 0x00100000: "focused",
}

func accEnsureCOMState(hctx *HandlerCtx) *comState {
	if hctx.Com == nil {
		hctx.Com = newCOMState(hctx)
	}
	return hctx.Com
}

func accRoleString(role uint32) string {
	if s, ok := roleText[role]; ok {
		return s
	}
	return fmt.Sprintf("role %d", role)
}

func accStateString(state uint32) string {
	if s, ok := stateText[state]; ok {
		return s
	}
	return fmt.Sprintf("state 0x%08x", state)
}

func accGuestObject(hwnd uint64, hctx *HandlerCtx) (uint32, *accObject) {
	accGlobal.mu.Lock()
	defer accGlobal.mu.Unlock()
	for id, obj := range accGlobal.objects {
		if obj != nil && obj.hwnd == hwnd {
			if obj.name == "" {
				obj.name = "Window"
			}
			return id, obj
		}
	}
	name := "Window"
	if hctx != nil && hctx.HwndTitle != nil {
		if title := hctx.HwndTitle[hwnd]; title != "" {
			name = title
		}
	}
	id := accGlobal.nextObj
	accGlobal.nextObj++
	obj := &accObject{
		hwnd:  hwnd,
		role:  roleSystemWindow,
		name:  name,
		state: stateSystemNormal,
	}
	accGlobal.objects[id] = obj
	return id, obj
}

func accLookupByCOMPtr(ptr uint64) (*accCOMObject, *accObject) {
	accCOMMu.Lock()
	inst := accCOMObjects[ptr]
	accCOMMu.Unlock()
	if inst == nil {
		return nil, nil
	}
	accGlobal.mu.Lock()
	obj := accGlobal.objects[inst.objID]
	accGlobal.mu.Unlock()
	return inst, obj
}

func accEnsureVTable(hctx *HandlerCtx) uint64 {
	accCOMMu.Lock()
	defer accCOMMu.Unlock()
	if accCOMVTableAddr != 0 {
		return accCOMVTableAddr
	}
	mem := hctx.Mem
	d := hctx.Disp
	totalSize := uint64(accMethodCount*8 + accMethodCount*16)
	base := mem.Mmap(0, totalSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	if base == 0 {
		return 0
	}
	vtableAddr := base
	stubBase := base + uint64(accMethodCount*8)
	for i := 0; i < accMethodCount; i++ {
		trapID := accCOMNextTrapID
		accCOMNextTrapID++
		methodIndex := i
		d.RegisterHandler(trapID, fmt.Sprintf("oleacc!IAccessible[%d]", methodIndex), func(ctx *ntapi.TrapContext) uint32 {
			return accDispatchMethod(hctx, methodIndex, ctx)
		})
		stubAddr := stubBase + uint64(i*16)
		code := make([]byte, 16)
		code[0] = 0xB8
		binary.LittleEndian.PutUint32(code[1:5], trapID)
		code[5] = 0x0F
		code[6] = 0x01
		code[7] = 0xC1
		code[8] = 0xC3
		for j := 9; j < len(code); j++ {
			code[j] = 0xCC
		}
		mem.WriteBytes(stubAddr, code)
		mem.Write64(vtableAddr+uint64(i*8), stubAddr)
	}
	accCOMVTableAddr = vtableAddr
	return vtableAddr
}

func accCreateCOMObject(hctx *HandlerCtx, hwnd uint64) uint64 {
	vtableAddr := accEnsureVTable(hctx)
	if vtableAddr == 0 {
		return 0
	}
	objID, _ := accGuestObject(hwnd, hctx)
	objAddr := hctx.Mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
	if objAddr == 0 {
		return 0
	}
	hctx.Mem.Write64(objAddr, vtableAddr)
	accCOMMu.Lock()
	accCOMObjects[objAddr] = &accCOMObject{objID: objID, refCount: 1}
	accCOMMu.Unlock()
	return objAddr
}

func accWriteBSTR(hctx *HandlerCtx, out uint64, value string) uint32 {
	if out == 0 {
		return E_POINTER
	}
	hctx.Mem.Write64(out, 0)
	cs := accEnsureCOMState(hctx)
	bstr := cs.allocBSTRString(value)
	if bstr == 0 {
		return E_OUTOFMEMORY
	}
	hctx.Mem.Write64(out, bstr)
	return S_OK
}

func accDispatchMethod(hctx *HandlerCtx, method int, ctx *ntapi.TrapContext) uint32 {
	thisPtr := ctx.Arg(0)
	switch method {
	case 0:
		riid := ctx.Arg(1)
		ppv := ctx.Arg(2)
		if ppv == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppv, 0)
		if riid == 0 {
			return E_POINTER
		}
		reqIID := readGUID(ctx.Mem, riid)
		if !guidEqual(reqIID, IID_IUnknown) && !guidEqual(reqIID, IID_IAccessible) {
			return E_NOINTERFACE
		}
		accCOMMu.Lock()
		if inst := accCOMObjects[thisPtr]; inst != nil {
			inst.refCount++
		}
		accCOMMu.Unlock()
		ctx.Mem.Write64(ppv, thisPtr)
		return S_OK
	case 1:
		accCOMMu.Lock()
		var count uint32
		if inst := accCOMObjects[thisPtr]; inst != nil {
			inst.refCount++
			count = inst.refCount
		}
		accCOMMu.Unlock()
		ctx.SetReturn(uint64(count))
		return 0
	case 2:
		accCOMMu.Lock()
		var count uint32
		if inst := accCOMObjects[thisPtr]; inst != nil {
			if inst.refCount > 0 {
				inst.refCount--
			}
			count = inst.refCount
			if inst.refCount == 0 {
				delete(accCOMObjects, thisPtr)
			}
		}
		accCOMMu.Unlock()
		ctx.SetReturn(uint64(count))
		return 0
	}

	_, obj := accLookupByCOMPtr(thisPtr)
	if obj == nil {
		return E_POINTER
	}

	switch method {
	case 3: // get_accParent
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write64(out, 0)
		}
		return S_OK
	case 4: // get_accChildCount
		if out := ctx.Arg(1); out == 0 {
			return E_POINTER
		} else {
			ctx.Mem.Write32(out, 0)
		}
		return S_OK
	case 5: // get_accChild
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write64(out, 0)
		}
		return E_INVALIDARG
	case 6: // get_accName
		return accWriteBSTR(hctx, ctx.Arg(2), obj.name)
	case 7: // get_accValue
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write64(out, 0)
		}
		return S_FALSE
	case 8: // get_accDescription
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write64(out, 0)
		}
		return S_FALSE
	case 9: // get_accRole
		if out := ctx.Arg(2); out == 0 {
			return E_POINTER
		}
		writeVariantScalar(ctx.Mem, ctx.Arg(2), VT_I4, uint64(obj.role))
		return S_OK
	case 10: // get_accState
		if out := ctx.Arg(2); out == 0 {
			return E_POINTER
		}
		writeVariantScalar(ctx.Mem, ctx.Arg(2), VT_I4, uint64(obj.state))
		return S_OK
	case 11: // get_accHelp
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write64(out, 0)
		}
		return S_FALSE
	case 12: // get_accHelpTopic
		if out := ctx.Arg(1); out != 0 {
			ctx.Mem.Write64(out, 0)
		}
		if out := ctx.Arg(3); out != 0 {
			ctx.Mem.Write32(out, 0)
		}
		return S_FALSE
	case 13: // get_accKeyboardShortcut
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write64(out, 0)
		}
		return S_FALSE
	case 14: // get_accFocus
		if out := ctx.Arg(1); out != 0 {
			writeVariantEmpty(ctx.Mem, out)
		}
		return S_FALSE
	case 15: // get_accSelection
		if out := ctx.Arg(1); out != 0 {
			writeVariantEmpty(ctx.Mem, out)
		}
		return S_FALSE
	case 16: // get_accDefaultAction
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write64(out, 0)
		}
		return S_FALSE
	case 17: // accSelect
		return S_OK
	case 18: // accLocation
		if out := ctx.Arg(1); out != 0 {
			ctx.Mem.Write32(out, 0)
		}
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write32(out, 0)
		}
		if out := ctx.Arg(3); out != 0 {
			ctx.Mem.Write32(out, 100)
		}
		if out := ctx.Arg(4); out != 0 {
			ctx.Mem.Write32(out, 100)
		}
		return S_OK
	case 19: // accNavigate
		if out := ctx.Arg(3); out != 0 {
			writeVariantEmpty(ctx.Mem, out)
		}
		return S_FALSE
	case 20: // accHitTest
		if out := ctx.Arg(3); out != 0 {
			writeVariantEmpty(ctx.Mem, out)
		}
		return S_FALSE
	case 21: // accDoDefaultAction
		return S_OK
	case 22: // put_accName
		if name := readBSTRString(ctx.Mem, ctx.Arg(2)); name != "" {
			accGlobal.mu.Lock()
			obj.name = name
			accGlobal.mu.Unlock()
		}
		return S_OK
	case 23: // put_accValue
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func registerOleaccHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem

	if dll, ok := hctx.SynthByName["oleacc.dll"]; ok {
		writeAccessibleOut := func(out uint64, hwnd uint64) uint32 {
			if out == 0 {
				return E_POINTER
			}
			mem.Write64(out, 0)
			ptr := accCreateCOMObject(hctx, hwnd)
			if ptr == 0 {
				return E_OUTOFMEMORY
			}
			mem.Write64(out, ptr)
			return S_OK
		}
		writeTextW := func(code uint32, dst uint64, cch uint32, table func(uint32) string) uint64 {
			s := table(code)
			if dst != 0 && cch != 0 {
				writeGuestUTF16StringN(mem, dst, s, int(cch))
			}
			return uint64(len(utf16Encode(s)))
		}
		writeTextA := func(code uint32, dst uint64, cch uint32, table func(uint32) string) uint64 {
			s := table(code)
			if dst != 0 && cch != 0 {
				writeGuestANSIStringN(mem, dst, s, int(cch))
			}
			return uint64(len(s))
		}

		d.RegisterAutoStubHandler(dll, "AccessibleObjectFromWindow", func(ctx *ntapi.TrapContext) uint32 {
			hr := writeAccessibleOut(ctx.Arg(3), ctx.Arg(0))
			ctx.SetReturn(uint64(hr))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "AccessibleObjectFromPoint", func(ctx *ntapi.TrapContext) uint32 {
			if out := ctx.Arg(1); out != 0 {
				mem.Write64(out, 0)
			}
			if out := ctx.Arg(2); out != 0 {
				writeVariantEmpty(mem, out)
			}
			ctx.SetReturn(E_NOTIMPL)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "AccessibleObjectFromEvent", func(ctx *ntapi.TrapContext) uint32 {
			ppacc := ctx.Arg(3)
			pvarChild := ctx.Arg(4)
			hr := writeAccessibleOut(ppacc, ctx.Arg(0))
			if pvarChild != 0 {
				writeVariantEmpty(mem, pvarChild)
			}
			ctx.SetReturn(uint64(hr))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "AccessibleChildren", func(ctx *ntapi.TrapContext) uint32 {
			if out := ctx.Arg(4); out != 0 {
				mem.Write32(out, 0)
			}
			ctx.SetReturn(S_OK)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "WindowFromAccessibleObject", func(ctx *ntapi.TrapContext) uint32 {
			pacc := ctx.Arg(0)
			phwnd := ctx.Arg(1)
			if phwnd == 0 {
				ctx.SetReturn(E_POINTER)
				return 0
			}
			mem.Write64(phwnd, 0)
			_, obj := accLookupByCOMPtr(pacc)
			if obj != nil {
				mem.Write64(phwnd, obj.hwnd)
			}
			ctx.SetReturn(S_OK)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "GetRoleTextW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(writeTextW(uint32(ctx.Arg(0)), ctx.Arg(1), uint32(ctx.Arg(2)), accRoleString))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "GetRoleTextA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(writeTextA(uint32(ctx.Arg(0)), ctx.Arg(1), uint32(ctx.Arg(2)), accRoleString))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "GetStateTextW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(writeTextW(uint32(ctx.Arg(0)), ctx.Arg(1), uint32(ctx.Arg(2)), accStateString))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "GetStateTextA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(writeTextA(uint32(ctx.Arg(0)), ctx.Arg(1), uint32(ctx.Arg(2)), accStateString))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "CreateStdAccessibleObject", func(ctx *ntapi.TrapContext) uint32 {
			hr := writeAccessibleOut(ctx.Arg(3), ctx.Arg(0))
			ctx.SetReturn(uint64(hr))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "CreateStdAccessibleProxy", func(ctx *ntapi.TrapContext) uint32 {
			hr := writeAccessibleOut(ctx.Arg(4), ctx.Arg(0))
			ctx.SetReturn(uint64(hr))
			return 0
		})
		d.RegisterAutoStubHandler(dll, "LresultFromObject", func(ctx *ntapi.TrapContext) uint32 {
			punk := ctx.Arg(2)
			if punk != 0 {
				accCOMMu.Lock()
				accLresultMap[punk] = punk
				accCOMMu.Unlock()
			}
			ctx.SetReturn(punk)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "ObjectFromLresult", func(ctx *ntapi.TrapContext) uint32 {
			lResult := ctx.Arg(0)
			ppvObject := ctx.Arg(3)
			if ppvObject == 0 {
				ctx.SetReturn(E_POINTER)
				return 0
			}
			mem.Write64(ppvObject, 0)
			accCOMMu.Lock()
			ptr := accLresultMap[lResult]
			if ptr == 0 {
				ptr = lResult
			}
			if inst := accCOMObjects[ptr]; inst != nil {
				inst.refCount++
			}
			accCOMMu.Unlock()
			if ptr != 0 {
				mem.Write64(ppvObject, ptr)
			}
			ctx.SetReturn(S_OK)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "GetOleaccVersionInfo", func(ctx *ntapi.TrapContext) uint32 {
			if out := ctx.Arg(0); out != 0 {
				mem.Write32(out, 7)
			}
			if out := ctx.Arg(1); out != 0 {
				mem.Write32(out, 0)
			}
			ctx.SetReturn(S_OK)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "GetProcessHandleFromHwnd", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(^uint64(0))
			return 0
		})
	}

	if dll, ok := hctx.SynthByName["uiautomationcore.dll"]; ok {
		d.RegisterAutoStubHandler(dll, "UiaReturnRawElementProvider", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "UiaHostProviderFromHwnd", func(ctx *ntapi.TrapContext) uint32 {
			if out := ctx.Arg(1); out != 0 {
				mem.Write64(out, 0)
			}
			ctx.SetReturn(E_NOTIMPL)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "UiaRaiseAutomationEvent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(S_OK)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "UiaRaiseAutomationPropertyChangedEvent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(S_OK)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "UiaRaiseStructureChangedEvent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(S_OK)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "UiaClientsAreListening", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "UiaGetReservedNotSupportedValue", func(ctx *ntapi.TrapContext) uint32 {
			if out := ctx.Arg(0); out != 0 {
				mem.Write64(out, 0)
			}
			ctx.SetReturn(E_NOTIMPL)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "UiaGetReservedMixedAttributeValue", func(ctx *ntapi.TrapContext) uint32 {
			if out := ctx.Arg(0); out != 0 {
				mem.Write64(out, 0)
			}
			ctx.SetReturn(E_NOTIMPL)
			return 0
		})
		d.RegisterAutoStubHandler(dll, "UiaLookupId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
	}
}
