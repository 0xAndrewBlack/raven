//go:build guest_windows

package main

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/arch"
	comctl32pkg "github.com/mirkobrombin/Raven/pkg/comctl32"
	"github.com/mirkobrombin/Raven/pkg/loader"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/thread"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"github.com/mirkobrombin/Raven/pkg/wl"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func appendUint32(code []byte, value uint32) []byte {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	return append(code, encoded[:]...)
}

func appendUint64(code []byte, value uint64) []byte {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	return append(code, encoded[:]...)
}

func installSubclassTestProc(t *testing.T, mem *mmu.MMU, is32 bool, defSubclass, idOut, refOut, orderOut uint64, order, add uint32) uint64 {
	t.Helper()
	var code []byte
	if is32 {
		code = append(code, 0x8B, 0x44, 0x24, 0x14, 0xA3)
		code = appendUint32(code, uint32(idOut))
		code = append(code, 0x8B, 0x44, 0x24, 0x18, 0xA3)
		code = appendUint32(code, uint32(refOut))
		code = append(code, 0xC7, 0x05)
		code = appendUint32(code, uint32(orderOut))
		code = appendUint32(code, order)
		for range 4 {
			code = append(code, 0xFF, 0x74, 0x24, 0x10)
		}
		code = append(code, 0xB8)
		code = appendUint32(code, uint32(defSubclass))
		code = append(code, 0xFF, 0xD0, 0x05)
		code = appendUint32(code, add)
		code = append(code, 0xC2, 0x18, 0x00)
	} else {
		code = append(code, 0x48, 0x8B, 0x44, 0x24, 0x28, 0x48, 0xA3)
		code = appendUint64(code, idOut)
		code = append(code, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48, 0xA3)
		code = appendUint64(code, refOut)
		code = append(code, 0x48, 0xB8)
		code = appendUint64(code, orderOut)
		code = append(code, 0xC7, 0x00)
		code = appendUint32(code, order)
		code = append(code, 0x48, 0x83, 0xEC, 0x28, 0x48, 0xB8)
		code = appendUint64(code, defSubclass)
		code = append(code, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0x48, 0x05)
		code = appendUint32(code, add)
		code = append(code, 0xC3)
	}
	addr := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if err := mem.WriteBytes(addr, code); err != nil {
		t.Fatal(err)
	}
	if err := mem.Mprotect(addr, mmu.PageSize, mmu.PermRead|mmu.PermExecute); err != nil {
		t.Fatal(err)
	}
	return addr
}

func installSubclassOriginalProc(t *testing.T, mem *mmu.MMU, is32 bool, result uint32) uint64 {
	t.Helper()
	code := []byte{0xB8}
	code = appendUint32(code, result)
	if is32 {
		code = append(code, 0xC2, 0x10, 0x00)
	} else {
		code = append(code, 0xC3)
	}
	addr := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if err := mem.WriteBytes(addr, code); err != nil {
		t.Fatal(err)
	}
	if err := mem.Mprotect(addr, mmu.PageSize, mmu.PermRead|mmu.PermExecute); err != nil {
		t.Fatal(err)
	}
	return addr
}

func callSubclassTestExport(t *testing.T, dispatcher *ntapi.Dispatcher, synth *ntapi.SynthPE, mem *mmu.MMU, is32 bool, name string, args ...uint64) uint64 {
	t.Helper()
	stub := synth.Exports[name]
	id := synth.StubIDs[stub]
	stack := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	cpu := x64.New(mem)
	cpu.Mode32 = is32
	cpu.SetSP(stack + 0x200)
	if is32 {
		for index, arg := range args {
			mem.Write32(cpu.GetSP()+4+uint64(index)*4, uint32(arg))
		}
	} else {
		registers := []int{x64.RCX, x64.RDX, x64.R8, x64.R9}
		for index, arg := range args {
			if index < len(registers) {
				cpu.Regs[registers[index]] = arg
			} else {
				mem.Write64(cpu.GetSP()+0x28+uint64(index-4)*8, arg)
			}
		}
	}
	cpu.Regs[x64.RAX] = uint64(id)
	dispatcher.Handle(cpu)
	return cpu.Regs[x64.RAX]
}

func TestSubclassGuestDispatchChainPE32AndPE64(t *testing.T) {
	for _, test := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			const hwnd = uint64(0x54001)
			comctl32pkg.RemoveAllSubclasses(hwnd)
			t.Cleanup(func() { comctl32pkg.RemoveAllSubclasses(hwnd) })

			mem := mmu.New()
			mem.Mode32 = test.is32
			state := &ntapi.ProcessState{Is32: test.is32}
			dispatcher := ntapi.NewDispatcher(
				mem,
				vfs.New(),
				ntapi.NewHandleTable(),
				nil,
				state,
				ntapi.GenerateNtdll(mem),
				ntapi.GenerateWin32u(mem),
			)
			comctl := ntapi.GenerateComctl32(mem)
			hctx := &HandlerCtx{
				Mem:          mem,
				Disp:         dispatcher,
				ProcState:    state,
				SynthByName:  map[string]*ntapi.SynthPE{"comctl32.dll": comctl},
				HwndWndProc:  make(map[uint64]uint64),
				HwndChildren: make(map[uint64]*controlState),
			}
			registerComctl32Handlers(hctx)

			data := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			idSize := uint64(8)
			if test.is32 {
				idSize = 4
			}
			firstIDOut := data
			secondIDOut := data + idSize
			firstRefOut := data + 2*idSize
			secondRefOut := data + 3*idSize
			orderOut := data + 4*idSize

			defSubclass := comctl.Exports["DefSubclassProc"]
			firstProc := installSubclassTestProc(t, mem, test.is32, defSubclass,
				firstIDOut, firstRefOut, orderOut, 1, 10)
			secondProc := installSubclassTestProc(t, mem, test.is32, defSubclass,
				secondIDOut, secondRefOut, orderOut, 2, 100)
			originalProc := installSubclassOriginalProc(t, mem, test.is32, 5)
			hctx.HwndWndProc[hwnd] = originalProc

			firstID := pointerSized(0x1122334455667788, test.is32)
			firstRef := pointerSized(0x8877665544332211, test.is32)
			secondID := pointerSized(0xA1A2A3A4A5A6A7A8, test.is32)
			secondRef := pointerSized(0xB1B2B3B4B5B6B7B8, test.is32)
			if got := callSubclassTestExport(t, dispatcher, comctl, mem, test.is32,
				"SetWindowSubclass", hwnd, firstProc, firstID, firstRef); got != 1 {
				t.Fatalf("first SetWindowSubclass = %d", got)
			}
			if got := callSubclassTestExport(t, dispatcher, comctl, mem, test.is32,
				"SetWindowSubclass", hwnd, secondProc, secondID, secondRef); got != 1 {
				t.Fatalf("second SetWindowSubclass = %d", got)
			}
			if hctx.HwndWndProc[hwnd] != hctx.SubclassWndProc {
				t.Fatal("window procedure was not replaced by the subclass dispatcher")
			}

			stack := mem.Mmap(0, 4*mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			stop := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			mem.WriteBytes(stop, []byte{0x0F, 0x01, 0xC1})
			if err := mem.Mprotect(stop, mmu.PageSize, mmu.PermRead|mmu.PermExecute); err != nil {
				t.Fatal(err)
			}
			cpu := x64.New(mem)
			cpu.Mode32 = test.is32
			cpu.SetSP(stack + 3*mmu.PageSize)
			cpu.SetPC(hctx.SubclassWndProc)
			if test.is32 {
				values := []uint32{uint32(stop), uint32(hwnd), 0x1234, 0x55667788, 0x99AABBCC}
				for index, value := range values {
					mem.Write32(cpu.GetSP()+uint64(index)*4, value)
				}
			} else {
				mem.Write64(cpu.GetSP(), stop)
				cpu.Regs[x64.RCX] = hwnd
				cpu.Regs[x64.RDX] = 0x1234
				cpu.Regs[x64.R8] = 0x1122334455667788
				cpu.Regs[x64.R9] = 0x8877665544332211
			}
			cpu.SetVmcallHandler(func(trapped arch.CPU) {
				if trapped.GetPC() == stop+3 {
					trapped.Stop()
					return
				}
				dispatcher.Handle(trapped)
			})
			if err := cpu.Run(); err != nil {
				t.Fatal(err)
			}
			if got := cpu.Regs[x64.RAX]; got != 115 {
				t.Fatalf("subclass chain result = %d, want 115", got)
			}

			readPointer := func(addr uint64) uint64 {
				if test.is32 {
					value, _ := mem.Read32(addr)
					return uint64(value)
				}
				value, _ := mem.Read64(addr)
				return value
			}
			if got := readPointer(firstIDOut); got != firstID {
				t.Fatalf("first subclass id = %#x, want %#x", got, firstID)
			}
			if got := readPointer(firstRefOut); got != firstRef {
				t.Fatalf("first subclass refData = %#x, want %#x", got, firstRef)
			}
			if got := readPointer(secondIDOut); got != secondID {
				t.Fatalf("second subclass id = %#x, want %#x", got, secondID)
			}
			if got := readPointer(secondRefOut); got != secondRef {
				t.Fatalf("second subclass refData = %#x, want %#x", got, secondRef)
			}
			if order, _ := mem.Read32(orderOut); order != 1 {
				t.Fatalf("final callback order marker = %d, want 1", order)
			}

			hctx.ClearSubclasses(hwnd)
			if hctx.HwndWndProc[hwnd] != originalProc || comctl32pkg.HasWindowSubclass(hwnd) {
				t.Fatal("subclass cleanup did not restore the original window procedure")
			}
		})
	}
}

func TestRedirectSubclassProcUsesGuestPointerWidth(t *testing.T) {
	tests := []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mem := mmu.New()
			stack := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			cpu := x64.New(mem)
			cpu.Mode32 = test.is32
			initialSP := stack + 0x800
			cpu.SetSP(initialSP)
			ctx := &ntapi.TrapContext{CPU: cpu, Mem: mem}

			const (
				proc       = uint64(0x12345678)
				hwnd       = uint64(0x1111222233334444)
				msg        = uint32(0x1234)
				wParam     = uint64(0x5555666677778888)
				lParam     = uint64(0x9999AAAABBBBCCCC)
				id         = uint64(0xDDDDEEEEFFFF0001)
				refData    = uint64(0x123456789ABCDEF0)
				returnAddr = uint64(0x1020304050607080)
			)
			if !redirectSubclassProc(ctx, proc, hwnd, msg, wParam, lParam, id, refData, returnAddr) {
				t.Fatal("redirectSubclassProc failed")
			}
			if cpu.GetPC() != proc || !ctx.PCRedirected || !ctx.ReturnOverridden {
				t.Fatalf("redirect state pc=%#x redirected=%v return=%v", cpu.GetPC(), ctx.PCRedirected, ctx.ReturnOverridden)
			}

			if test.is32 {
				if cpu.GetSP() != initialSP-8 {
					t.Fatalf("PE32 stack pointer = %#x, want %#x", cpu.GetSP(), initialSP-8)
				}
				want := []uint32{
					0x50607080, 0x33334444, msg, 0x77778888,
					0xBBBBCCCC, 0xFFFF0001, 0x9ABCDEF0,
				}
				for index, expected := range want {
					got, _ := mem.Read32(cpu.GetSP() + uint64(index)*4)
					if got != expected {
						t.Fatalf("PE32 stack[%d] = %#x, want %#x", index, got, expected)
					}
				}
				return
			}

			wantSP := initialSP - 16
			if cpu.GetSP() != wantSP {
				t.Fatalf("PE64 stack pointer = %#x, want %#x", cpu.GetSP(), wantSP)
			}
			if cpu.ReadReg(1) != hwnd || cpu.ReadReg(2) != uint64(msg) ||
				cpu.ReadReg(8) != wParam || cpu.ReadReg(9) != lParam {
				t.Fatalf("PE64 register arguments = %#x %#x %#x %#x",
					cpu.ReadReg(1), cpu.ReadReg(2), cpu.ReadReg(8), cpu.ReadReg(9))
			}
			gotReturn, _ := mem.Read64(wantSP)
			gotID, _ := mem.Read64(wantSP + 0x28)
			gotRef, _ := mem.Read64(wantSP + 0x30)
			if gotReturn != returnAddr || gotID != id || gotRef != refData {
				t.Fatalf("PE64 stack return=%#x id=%#x ref=%#x", gotReturn, gotID, gotRef)
			}
		})
	}
}

func TestSubclassRuntimeSkipsRemovedEntriesAndKeepsReentrantFrames(t *testing.T) {
	const (
		outerHWND = uint64(0x53001)
		innerHWND = uint64(0x53002)
	)
	t.Cleanup(func() {
		comctl32pkg.RemoveAllSubclasses(outerHWND)
		comctl32pkg.RemoveAllSubclasses(innerHWND)
	})
	comctl32pkg.SetWindowSubclass(outerHWND, 0x1000, 1, 11)
	comctl32pkg.SetWindowSubclass(outerHWND, 0x2000, 2, 22)
	comctl32pkg.SetWindowSubclass(innerHWND, 0x3000, 3, 33)

	runtime := new(subclassDispatchRuntime)
	cpu := x64.New(mmu.New())
	runtime.begin(cpu, subclassDispatchFrame{
		hwnd:       outerHWND,
		entries:    comctl32pkg.GetSubclassChain(outerHWND),
		original:   0xAAAA,
		returnAddr: 0xBBBB,
	})
	first, _, found := runtime.nextEntry(cpu, outerHWND)
	if !found || first.PfnSubclass != 0x2000 {
		t.Fatalf("first outer subclass = %#v, found=%v", first, found)
	}
	if !comctl32pkg.RemoveWindowSubclass(outerHWND, 0x1000, 1) {
		t.Fatal("failed to remove pending outer subclass")
	}

	runtime.begin(cpu, subclassDispatchFrame{
		hwnd:       innerHWND,
		entries:    comctl32pkg.GetSubclassChain(innerHWND),
		original:   0xCCCC,
		returnAddr: 0xDDDD,
	})
	inner, _, found := runtime.nextEntry(cpu, innerHWND)
	if !found || inner.PfnSubclass != 0x3000 {
		t.Fatalf("inner subclass = %#v, found=%v", inner, found)
	}
	if frame, ok := runtime.finish(cpu); !ok || frame.hwnd != innerHWND {
		t.Fatalf("finished inner frame = %#v, found=%v", frame, ok)
	}

	if _, frame, found := runtime.nextEntry(cpu, outerHWND); found || frame.original != 0xAAAA {
		t.Fatalf("removed outer callback ran, frame=%#v found=%v", frame, found)
	}
	if frame, ok := runtime.finish(cpu); !ok || frame.hwnd != outerHWND || frame.returnAddr != 0xBBBB {
		t.Fatalf("finished outer frame = %#v, found=%v", frame, ok)
	}
}

func TestSubclassRuntimeScopesFramesPerCPU(t *testing.T) {
	runtime := new(subclassDispatchRuntime)
	first := x64.New(mmu.New())
	second := x64.New(mmu.New())
	runtime.begin(first, subclassDispatchFrame{hwnd: 1, returnAddr: 11})
	runtime.begin(second, subclassDispatchFrame{hwnd: 2, returnAddr: 22})

	firstFrame, firstOK := runtime.activeFrame(first, 1)
	secondFrame, secondOK := runtime.activeFrame(second, 2)
	if !firstOK || !secondOK || firstFrame.returnAddr != 11 || secondFrame.returnAddr != 22 {
		t.Fatalf("CPU frames first=%#v/%v second=%#v/%v", firstFrame, firstOK, secondFrame, secondOK)
	}
}

func TestPointerSized(t *testing.T) {
	const value = uint64(0x123456789ABCDEF0)
	if got := pointerSized(value, true); got != 0x9ABCDEF0 {
		t.Fatalf("PE32 pointer = %#x", got)
	}
	if got := pointerSized(value, false); got != value {
		t.Fatalf("PE64 pointer = %#x", got)
	}
}

func TestTabItemOffsets(t *testing.T) {
	tests := []struct {
		name        string
		is32        bool
		text, param uint64
	}{
		{name: "win64", text: 16, param: 32},
		{name: "win32", is32: true, text: 12, param: 24},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, param := tabItemOffsets(tt.is32)
			if text != tt.text || param != tt.param {
				t.Fatalf("offsets = (%d, %d), want (%d, %d)", text, param, tt.text, tt.param)
			}
		})
	}
}

func TestTabControlItemWidth(t *testing.T) {
	previous := menuTextMeasure
	menuTextMeasure = nil
	t.Cleanup(func() {
		menuTextMeasure = previous
	})

	if got := tabControlItemWidth(""); got != 40 {
		t.Fatalf("empty tab width = %d, want 40", got)
	}
	if got := tabControlItemWidth("first.txt"); got != 95 {
		t.Fatalf("text tab width = %d, want 95", got)
	}
}

func TestCommonControlItemOffsets(t *testing.T) {
	tree32 := treeViewItemOffsets(true)
	if tree32.item != 4 || tree32.state != 8 || tree32.text != 16 || tree32.textMax != 20 || tree32.param != 36 || tree32.insertItem != 8 {
		t.Fatalf("PE32 TVITEM layout = %+v", tree32)
	}
	tree64 := treeViewItemOffsets(false)
	if tree64.item != 8 || tree64.state != 16 || tree64.text != 24 || tree64.textMax != 32 || tree64.param != 48 || tree64.insertItem != 16 {
		t.Fatalf("PE64 TVITEM layout = %+v", tree64)
	}

	list32 := listViewItemOffsets(true)
	if list32.text != 20 || list32.textMax != 24 || list32.image != 28 || list32.param != 32 {
		t.Fatalf("PE32 LVITEM layout = %+v", list32)
	}
	list64 := listViewItemOffsets(false)
	if list64.text != 24 || list64.textMax != 32 || list64.image != 36 || list64.param != 40 {
		t.Fatalf("PE64 LVITEM layout = %+v", list64)
	}
	if listViewColumnTextOffset(true) != 12 || listViewColumnTextOffset(false) != 16 {
		t.Fatal("LVCOLUMN text offsets do not match PE32 and PE64 layouts")
	}
	notifyList32 := listViewNotifyOffsets(true)
	if notifyList32.header != 12 || notifyList32.size != 72 {
		t.Fatalf("PE32 NMLVDISPINFO layout = %+v", notifyList32)
	}
	notifyList64 := listViewNotifyOffsets(false)
	if notifyList64.header != 24 || notifyList64.size != 112 {
		t.Fatalf("PE64 NMLVDISPINFO layout = %+v", notifyList64)
	}

	notify32 := treeViewNotifyOffsets(true)
	if notify32.action != 12 || notify32.itemOld != 16 || notify32.itemNew != 56 || notify32.point != 96 || notify32.size != 104 {
		t.Fatalf("PE32 NMTREEVIEW layout = %+v", notify32)
	}
	notify64 := treeViewNotifyOffsets(false)
	if notify64.action != 24 || notify64.itemOld != 32 || notify64.itemNew != 88 || notify64.point != 144 || notify64.size != 152 {
		t.Fatalf("PE64 NMTREEVIEW layout = %+v", notify64)
	}
}

func TestTreeViewMessageIDs(t *testing.T) {
	tests := map[string]struct {
		got  int
		want int
	}{
		"TVM_INSERTITEMA":  {got: tvmInsertItemA, want: 0x1100},
		"TVM_DELETEITEM":   {got: tvmDeleteItem, want: 0x1101},
		"TVM_EXPAND":       {got: tvmExpand, want: 0x1102},
		"TVM_GETITEMRECT":  {got: tvmGetItemRect, want: 0x1104},
		"TVM_GETCOUNT":     {got: tvmGetCount, want: 0x1105},
		"TVM_GETNEXTITEM":  {got: tvmGetNextItem, want: 0x110A},
		"TVM_SELECTITEM":   {got: tvmSelectItem, want: 0x110B},
		"TVM_GETITEMA":     {got: tvmGetItemA, want: 0x110C},
		"TVM_SETITEMA":     {got: tvmSetItemA, want: 0x110D},
		"TVM_SORTCHILDREN": {got: tvmSortChildren, want: 0x1113},
		"TVM_INSERTITEMW":  {got: tvmInsertItemW, want: 0x1132},
		"TVM_GETITEMW":     {got: tvmGetItemW, want: 0x113E},
		"TVM_SETITEMW":     {got: tvmSetItemW, want: 0x113F},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %#x, want %#x", name, tt.got, tt.want)
			}
		})
	}
}

func TestTextCallbackPointerWidth(t *testing.T) {
	if !isTextCallbackPointer(0xFFFFFFFF, true) || isTextCallbackPointer(0xFFFFFFFF, false) {
		t.Fatal("PE32 callback pointer was not width-sensitive")
	}
	if !isTextCallbackPointer(^uint64(0), false) {
		t.Fatal("PE64 callback pointer was not recognized")
	}
}

func TestSetListViewExtendedStyle(t *testing.T) {
	lv := &listViewState{extStyle: 0x00000021}
	if old := setListViewExtendedStyle(lv, 0x00000020, 0); old != 0x00000021 {
		t.Fatalf("masked old style = %#x, want %#x", old, uint32(0x00000021))
	}
	if lv.extStyle != 0x00000001 {
		t.Fatalf("masked style = %#x, want %#x", lv.extStyle, uint32(0x00000001))
	}
	if old := setListViewExtendedStyle(lv, 0, 0x00010000); old != 0x00000001 {
		t.Fatalf("replacement old style = %#x, want %#x", old, uint32(0x00000001))
	}
	if lv.extStyle != 0x00010000 {
		t.Fatalf("replacement style = %#x, want %#x", lv.extStyle, uint32(0x00010000))
	}
}

func TestToolbarLayouts(t *testing.T) {
	layout32 := toolbarButtonOffsets(true)
	if layout32.size != 20 || layout32.data != 12 || layout32.string != 16 {
		t.Fatalf("PE32 TBBUTTON layout = %+v", layout32)
	}
	layout64 := toolbarButtonOffsets(false)
	if layout64.size != 32 || layout64.data != 16 || layout64.string != 24 {
		t.Fatalf("PE64 TBBUTTON layout = %+v", layout64)
	}
	if toolbarAddBitmapResourceOffset(true) != 4 || toolbarAddBitmapResourceOffset(false) != 8 {
		t.Fatal("TBADDBITMAP resource offsets do not match PE32 and PE64 layouts")
	}
	info32 := toolbarButtonInfoOffsets(true)
	if info32.param != 20 || info32.text != 24 || info32.textMax != 28 {
		t.Fatalf("PE32 TBBUTTONINFO layout = %+v", info32)
	}
	info64 := toolbarButtonInfoOffsets(false)
	if info64.param != 24 || info64.text != 32 || info64.textMax != 40 {
		t.Fatalf("PE64 TBBUTTONINFO layout = %+v", info64)
	}
}

func TestRebarBandInfoLayouts(t *testing.T) {
	if got := rebarBandInfoOffsets(true); got != (rebarBandInfoLayout{
		child: 32, minChildX: 36, minChildY: 40, width: 44, structureSize: 80,
	}) {
		t.Fatalf("PE32 REBARBANDINFO layout = %+v", got)
	}
	if got := rebarBandInfoOffsets(false); got != (rebarBandInfoLayout{
		child: 40, minChildX: 48, minChildY: 52, width: 56, structureSize: 128,
	}) {
		t.Fatalf("PE64 REBARBANDINFO layout = %+v", got)
	}
}

func TestSetToolbarButtonFlag(t *testing.T) {
	toolbar := &toolbarState{buttons: []tbButton{{id: 7, state: 0x04}}}
	if !setToolbarButtonFlag(toolbar, 7, 0x01, true) || toolbar.buttons[0].state != 0x05 {
		t.Fatalf("checked state = %#x", toolbar.buttons[0].state)
	}
	if !setToolbarButtonFlag(toolbar, 7, 0x04, false) || toolbar.buttons[0].state != 0x01 {
		t.Fatalf("disabled state = %#x", toolbar.buttons[0].state)
	}
	if setToolbarButtonFlag(toolbar, 8, 0x01, true) {
		t.Fatal("unknown command was reported as updated")
	}
}

func TestMakeToolbarPlaceholderIcon(t *testing.T) {
	icon := makeToolbarPlaceholderIcon(16, 16, 3)
	if len(icon) != 256 {
		t.Fatalf("placeholder pixel count = %d", len(icon))
	}
	nonTransparent := 0
	for _, pixel := range icon {
		if pixel>>24 != 0 {
			nonTransparent++
		}
	}
	if nonTransparent == 0 || nonTransparent == len(icon) {
		t.Fatalf("placeholder opaque pixel count = %d", nonTransparent)
	}
	if !toolbarIconHasVisiblePixel(icon) || toolbarIconHasVisiblePixel(make([]uint32, 16)) {
		t.Fatal("toolbar icon visibility detection failed")
	}
}

func TestToolbarFallbackIconCache(t *testing.T) {
	hctx := &HandlerCtx{}
	icon := makeToolbarPlaceholderIcon(16, 16, 3)
	key := toolbarFallbackKey{parent: 10, layout: 20}
	cacheToolbarFallbackIcon(hctx, key, 2, 16, 16, icon)
	icon[0] = 0xFFFFFFFF

	cached := toolbarFallbackIcon(hctx, key, 2, 16, 16)
	if len(cached) != 256 || cached[0] != 0 {
		t.Fatal("toolbar fallback cache did not retain an independent icon copy")
	}
	if toolbarFallbackIcon(hctx, toolbarFallbackKey{parent: 11, layout: 20}, 2, 16, 16) != nil {
		t.Fatal("toolbar fallback cache crossed parent windows")
	}
	if toolbarFallbackIcon(hctx, toolbarFallbackKey{parent: 10, layout: 21}, 2, 16, 16) != nil {
		t.Fatal("toolbar fallback cache crossed toolbar layouts")
	}
	if toolbarFallbackIcon(hctx, key, 2, 24, 24) != nil {
		t.Fatal("toolbar fallback cache accepted mismatched dimensions")
	}

	cacheToolbarFallbackIcon(hctx, key, 0, 24, 24, makeToolbarPlaceholderIcon(24, 24, 4))
	if toolbarFallbackIcon(hctx, key, 2, 16, 16) != nil {
		t.Fatal("toolbar fallback cache retained icons with stale dimensions")
	}
}

func TestToolbarFallbackIconCacheConcurrent(t *testing.T) {
	hctx := &HandlerCtx{}
	icon := makeToolbarPlaceholderIcon(16, 16, 7)
	var wg sync.WaitGroup
	key := toolbarFallbackKey{parent: 10, layout: 20}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				cacheToolbarFallbackIcon(hctx, key, index, 16, 16, icon)
				_ = toolbarFallbackIcon(hctx, key, index, 16, 16)
			}
		}(i)
	}
	wg.Wait()
}

func TestToolbarImagePixels(t *testing.T) {
	pixels := []byte{
		1, 2, 3, 0,
		4, 5, 6, 128,
	}
	got := toolbarImagePixels(pixels, nil, true, 2, 1)
	if len(got) != 2 || got[0] != 0x00030201 || got[1] != 0x80060504 {
		t.Fatalf("alpha image pixels = %#v", got)
	}

	got = toolbarImagePixels(pixels, []byte{0, 1}, false, 2, 1)
	if got[0] != 0xFF030201 || got[1] != 0 {
		t.Fatalf("masked image pixels = %#v", got)
	}

	got = toolbarImagePixels(pixels, []byte{0x40, 0, 0, 0}, false, 2, 1)
	if got[0] != 0xFF030201 || got[1] != 0 {
		t.Fatalf("packed masked image pixels = %#v", got)
	}
}

func TestToolbarButtonInfoIndex(t *testing.T) {
	toolbar := &toolbarState{
		buttons: []tbButton{
			{id: 41001},
			{id: 41002},
			{id: 0, style: 1},
		},
	}

	if got := toolbarButtonInfoIndex(toolbar, 41002, 0); got != 1 {
		t.Fatalf("command lookup returned %d, want 1", got)
	}
	if got := toolbarButtonInfoIndex(toolbar, 2, 0x80000000); got != 2 {
		t.Fatalf("index lookup returned %d, want 2", got)
	}
	if got := toolbarButtonInfoIndex(toolbar, 41002, 0x80000000); got != -1 {
		t.Fatalf("out-of-range index lookup returned %d, want -1", got)
	}
	if got := toolbarButtonInfoIndex(toolbar, 7, 0); got != -1 {
		t.Fatalf("unknown command lookup returned %d, want -1", got)
	}
}

func TestToolbarButtonInfoSize(t *testing.T) {
	if got := toolbarButtonInfoSize(true); got != 32 {
		t.Fatalf("PE32 TBBUTTONINFO size = %d, want 32", got)
	}
	if got := toolbarButtonInfoSize(false); got != 48 {
		t.Fatalf("PE64 TBBUTTONINFO size = %d, want 48", got)
	}
}

func TestToolbarButtonGeometry(t *testing.T) {
	toolbar := &toolbarState{
		buttons: []tbButton{
			{id: 1},
			{id: 2, width: 40},
			{id: 0, iBitmap: 12, style: 0x01},
			{id: 0, iBitmap: 12, width: 5, style: 0x01},
			{id: 0, style: 0x01},
			{id: 3, width: 90, state: 0x08},
			{id: 4},
		},
	}
	items := layoutToolbarButtons(toolbar, 0)
	want := []toolbarItemGeometry{
		{left: 2, right: 26, visible: true},
		{left: 26, right: 66, visible: true},
		{left: 66, right: 78, visible: true, separator: true},
		{left: 78, right: 83, visible: true, separator: true},
		{left: 83, right: 91, visible: true, separator: true},
		{left: 91, right: 181},
		{left: 91, right: 115, visible: true},
	}
	if len(items) != len(want) {
		t.Fatalf("layout item count = %d, want %d", len(items), len(want))
	}
	for i := range want {
		if items[i] != want[i] {
			t.Fatalf("layout item %d = %+v, want %+v", i, items[i], want[i])
		}
	}

	customDefault := layoutToolbarButtons(&toolbarState{buttons: []tbButton{{id: 1}}}, 31)
	if customDefault[0].right-customDefault[0].left != 31 {
		t.Fatalf("configured default width = %d, want 31", customDefault[0].right-customDefault[0].left)
	}
}

func TestToolbarButtonGeometryQueriesAndHitTesting(t *testing.T) {
	toolbar := &toolbarState{
		buttons: []tbButton{
			{id: 1, width: 10},
			{id: 0, width: 6, style: 0x01},
			{id: 2, width: 20, state: 0x08},
			{id: 3, width: 14},
		},
	}
	items := layoutToolbarButtons(toolbar, 24)

	for _, x := range []int32{2, 7, 11} {
		if got := toolbarButtonAt(items, x); got != 0 {
			t.Fatalf("first button hit at %d = %d, want 0", x, got)
		}
	}
	for _, x := range []int32{12, 14, 17} {
		if got := toolbarButtonAt(items, x); got != -1 {
			t.Fatalf("separator hit at %d = %d, want -1", x, got)
		}
	}
	for _, x := range []int32{18, 20, 31} {
		if got := toolbarButtonAt(items, x); got != 3 {
			t.Fatalf("button after hidden item hit at %d = %d, want 3", x, got)
		}
	}
	if got := toolbarButtonAt(items, 32); got != -1 {
		t.Fatalf("out-of-range hit = %d, want -1", got)
	}

	if left, right, ok := toolbarItemRect(items, 1); !ok || left != 12 || right != 18 {
		t.Fatalf("separator rect = (%d, %d, %v), want (12, 18, true)", left, right, ok)
	}
	if _, _, ok := toolbarItemRect(items, 2); ok {
		t.Fatal("hidden button returned an item rectangle")
	}
	if _, _, ok := toolbarItemRect(items, -1); ok {
		t.Fatal("negative item index returned an item rectangle")
	}
	if _, _, ok := toolbarItemRect(items, len(items)); ok {
		t.Fatal("out-of-range item index returned an item rectangle")
	}
}

func newToolbarDispatchTestContext(t *testing.T) (*HandlerCtx, *mmu.MMU, *wl.Window) {
	t.Helper()
	mem := mmu.New()
	fs := vfs.New()
	handles := ntapi.NewHandleTable()
	registry := ntapi.NewRegistryHive()
	state := &ntapi.ProcessState{}
	state.TEBAddr = mem.Mmap(0, 0x2000, mmu.PermRead|mmu.PermWrite)
	heap := mem.Mmap(0, 1024*1024, mmu.PermRead|mmu.PermWrite)
	mem.Write64(state.TEBAddr+ntapi.TebHeapBase, heap)

	ntdll := ntapi.GenerateNtdll(mem)
	win32u := ntapi.GenerateWin32u(mem)
	kernel32 := ntapi.GenerateKernel32(mem)
	comctl32 := ntapi.GenerateComctl32(mem)
	dispatcher := ntapi.NewDispatcher(mem, fs, handles, registry, state, ntdll, win32u)
	mainModule := &loader.PEModule{Is64: true}
	var manager *thread.Manager
	hctx := registerAutoSynthHandlers(
		mem,
		dispatcher,
		[]*ntapi.SynthPE{ntdll, win32u, kernel32, comctl32},
		nil,
		"",
		"",
		"",
		handles,
		state,
		nil,
		mainModule,
		map[string]*loader.PEModule{},
		&manager,
		time.Unix(0, 0),
		registry,
		"",
		false,
		nil,
		"",
		nil,
	)
	window := wl.NewHeadlessWindow("toolbar test", 100, 40, 0)
	hctx.WlWindow = window
	hctx.OnWlWindowSet(window)
	return hctx, mem, window
}

func TestToolbarGeometryMessageDispatch(t *testing.T) {
	hctx, mem, window := newToolbarDispatchTestContext(t)
	const (
		parent  = uint64(0x60000)
		toolbar = uint64(0x60001)
	)
	hctx.MainHWND = parent
	hctx.HwndChildren[toolbar] = &controlState{
		className:  "toolbarwindow32",
		parentHWND: parent,
		w:          100,
		h:          26,
		visible:    true,
		toolbar: &toolbarState{buttons: []tbButton{
			{id: 101, state: 0x04},
			{iBitmap: 0, state: 0x04, style: 0x01},
			{id: 102, state: 0x0C},
		}},
	}

	info := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
	mem.Write32(info, toolbarButtonInfoSize(false))
	mem.Write32(info+4, 0x0040) // TBIF_SIZE
	mem.Write16(info+18, 10)
	if result, handled := hctx.BuiltinWndProc(toolbar, 0x0400+64, 101, info); !handled || result != 1 {
		t.Fatalf("TB_SETBUTTONINFOW = (%d, %v), want (1, true)", result, handled)
	}
	if width := hctx.HwndChildren[toolbar].toolbar.buttons[0].width; width != 10 {
		t.Fatalf("stored button width = %d, want 10", width)
	}

	rect := info + 0x100
	if result, handled := hctx.BuiltinWndProc(toolbar, 0x0400+29, 0, rect); !handled || result != 1 {
		t.Fatalf("TB_GETITEMRECT = (%d, %v), want (1, true)", result, handled)
	}
	left, _ := mem.Read32(rect)
	top, _ := mem.Read32(rect + 4)
	right, _ := mem.Read32(rect + 8)
	bottom, _ := mem.Read32(rect + 12)
	if left != 2 || top != 0 || right != 12 || bottom != 26 {
		t.Fatalf("button rect = (%d, %d, %d, %d), want (2, 0, 12, 26)", left, top, right, bottom)
	}

	for offset := uint64(0); offset < 16; offset += 4 {
		mem.Write32(rect+offset, 0xA5A5A5A5)
	}
	if result, handled := hctx.BuiltinWndProc(toolbar, 0x0400+29, 2, rect); !handled || result != 0 {
		t.Fatalf("hidden TB_GETITEMRECT = (%d, %v), want (0, true)", result, handled)
	}
	for offset := uint64(0); offset < 16; offset += 4 {
		if value, _ := mem.Read32(rect + offset); value != 0xA5A5A5A5 {
			t.Fatalf("hidden TB_GETITEMRECT changed RECT field at +%d", offset)
		}
	}

	cpu := x64.New(mem)
	hctx.setWindowCPU(parent, cpu)
	if result, handled := hctx.BuiltinWndProc(toolbar, 0x0201, 0, 11); !handled || result != 0 {
		t.Fatalf("WM_LBUTTONDOWN = (%d, %v), want (0, true)", result, handled)
	}
	message, ok := hctx.MsgQueue.take(cpu, nil)
	if !ok || message.hwnd != parent || message.message != 0x0111 || uint16(message.wParam) != 101 {
		t.Fatalf("toolbar click message = %+v, found=%v", message, ok)
	}
	hctx.BuiltinWndProc(toolbar, 0x0201, 0, 12)
	if hctx.MsgQueue.count(cpu) != 0 {
		t.Fatal("separator boundary queued a command")
	}

	if result, handled := hctx.BuiltinWndProc(toolbar, 0x000F, 0, 0); !handled || result != 0 {
		t.Fatalf("WM_PAINT = (%d, %v), want (0, true)", result, handled)
	}
	colorAt := func(x, y int32) uint32 {
		offset := int(y*window.Stride + x*4)
		return uint32(window.Pix[offset]) |
			uint32(window.Pix[offset+1])<<8 |
			uint32(window.Pix[offset+2])<<16
	}
	if color := colorAt(11, 2); color != 0x716F64 {
		t.Fatalf("button right edge color = %#x, want %#x", color, uint32(0x716F64))
	}
	if color := colorAt(12, 2); color != 0xD4D0C8 {
		t.Fatalf("pixel after variable-width button = %#x, want toolbar background", color)
	}
}

func TestRebarSetBandInfoReparentsChildPE32AndPE64(t *testing.T) {
	for _, test := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64", is32: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			hctx, mem, _ := newToolbarDispatchTestContext(t)
			hctx.ProcState.Is32 = test.is32
			const (
				parent  = uint64(0x61000)
				rebar   = uint64(0x61001)
				toolbar = uint64(0x61002)
			)
			hctx.MainHWND = parent
			hctx.HwndChildren[rebar] = &controlState{
				className: "rebarwindow32", parentHWND: parent,
				x: 7, y: 9, w: 320, h: 26, visible: true,
			}
			hctx.HwndChildren[toolbar] = &controlState{
				className: "toolbarwindow32", parentHWND: parent,
				w: 100, h: 20, visible: true,
				toolbar: &toolbarState{buttons: []tbButton{
					{id: 101, state: 0x04},
				}},
			}
			info := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
			layout := rebarBandInfoOffsets(test.is32)
			mem.Write32(info, uint32(layout.structureSize))
			mem.Write32(info+4, 0x30) // RBBIM_CHILD | RBBIM_CHILDSIZE
			if test.is32 {
				mem.Write32(info+layout.child, uint32(toolbar))
			} else {
				mem.Write64(info+layout.child, toolbar)
			}
			mem.Write32(info+layout.minChildY, 23)

			if result, handled := hctx.BuiltinWndProc(rebar, 0x0400+11, 0, info); !handled || result != 1 {
				t.Fatalf("RB_SETBANDINFOW = (%d, %v), want (1, true)", result, handled)
			}
			child := hctx.HwndChildren[toolbar]
			if child.parentHWND != rebar {
				t.Fatalf("toolbar parent = %#x, want %#x", child.parentHWND, rebar)
			}
			if child.x != 7 || child.y != 9 || child.w != 320 || child.h != 23 {
				t.Fatalf("toolbar geometry = (%d,%d %dx%d)", child.x, child.y, child.w, child.h)
			}
			if hctx.RebarBandCounts[rebar] != 0 {
				t.Fatalf("RB_SETBANDINFO changed band count to %d", hctx.RebarBandCounts[rebar])
			}

			cpu := x64.New(mem)
			hctx.setWindowCPU(parent, cpu)
			hctx.setWindowCPU(rebar, cpu)
			hctx.BuiltinWndProc(toolbar, 0x0201, 0, 3)
			command, ok := hctx.MsgQueue.take(cpu, nil)
			if !ok || command.hwnd != rebar || uint16(command.wParam) != 101 {
				t.Fatalf("toolbar command = %+v, present=%t", command, ok)
			}
			hctx.BuiltinWndProc(rebar, command.message, command.wParam, command.lParam)
			command, ok = hctx.MsgQueue.take(cpu, nil)
			if !ok || command.hwnd != parent || uint16(command.wParam) != 101 {
				t.Fatalf("forwarded rebar command = %+v, present=%t", command, ok)
			}
		})
	}
}

func TestDarkRebarPaintDoesNotCoverChildToolbarArea(t *testing.T) {
	resetDarkModeState()
	t.Cleanup(resetDarkModeState)
	hctx, _, window := newToolbarDispatchTestContext(t)
	const (
		parent = uint64(0x62000)
		rebar  = uint64(0x62001)
	)
	hctx.MainHWND = parent
	hctx.HwndChildren[rebar] = &controlState{
		className: "rebarwindow32", parentHWND: parent,
		x: 7, y: 9, w: 100, h: 26, visible: true,
	}
	hctx.HwndChildren[0x62002] = &controlState{
		className: "toolbarwindow32", parentHWND: rebar,
		x: 10, y: 11, w: 80, h: 23, visible: true,
	}
	setWindowThemeSelection(rebar, windowThemeSelection{SubAppName: "DarkMode_Explorer"})
	const marker = uint32(0x123456)
	window.DrawRectAbs(7, 9, 107, 35, marker)

	if result, handled := hctx.BuiltinWndProc(rebar, 0x000F, 0, 0); !handled || result != 0 {
		t.Fatalf("WM_PAINT = (%d, %v), want (0, true)", result, handled)
	}
	offset := 21*window.Stride + 20*4
	color := uint32(window.Pix[offset]) |
		uint32(window.Pix[offset+1])<<8 |
		uint32(window.Pix[offset+2])<<16
	if color != marker {
		t.Fatalf("rebar interior color = %#x, want preserved toolbar pixel %#x", color, marker)
	}
	offset = 19*window.Stride + 97*4
	color = uint32(window.Pix[offset]) |
		uint32(window.Pix[offset+1])<<8 |
		uint32(window.Pix[offset+2])<<16
	if color != darkPalette.Control {
		t.Fatalf("uncovered rebar color = %#x, want %#x", color, darkPalette.Control)
	}
}

func TestToolbarSetImageListQueuesPaint(t *testing.T) {
	hctx, _, window := newToolbarDispatchTestContext(t)
	const (
		parent  = uint64(0x63000)
		toolbar = uint64(0x63001)
	)
	hctx.MainHWND = parent
	hctx.HwndChildren[toolbar] = &controlState{
		className: "toolbarwindow32", parentHWND: parent,
		w: 100, h: 26, visible: true,
		toolbar: &toolbarState{buttons: []tbButton{
			{id: 101, iBitmap: 0, state: 0x04},
		}},
	}
	firstImageList := comctl32pkg.ImageListCreate(16, 16, comctl32pkg.ILC_COLOR32, 1, 1)
	secondImageList := comctl32pkg.ImageListCreate(4, 4, comctl32pkg.ILC_COLOR32, 1, 1)
	t.Cleanup(func() {
		comctl32pkg.ImageListDestroy(firstImageList)
		comctl32pkg.ImageListDestroy(secondImageList)
	})
	pixels := make([]byte, 4*4*4)
	for offset := 0; offset < len(pixels); offset += 4 {
		pixels[offset] = 0x12
		pixels[offset+1] = 0x34
		pixels[offset+2] = 0x56
		pixels[offset+3] = 0xFF
	}
	if index := comctl32pkg.ImageListAddImage(secondImageList, pixels, nil, true); index != 0 {
		t.Fatalf("ImageListAddImage index = %d, want 0", index)
	}

	if result, handled := hctx.BuiltinWndProc(toolbar, 0x0400+48, 0, firstImageList); !handled || result != 0 {
		t.Fatalf("TB_SETIMAGELIST = (%d, %v), want (0, true)", result, handled)
	}
	if !hctx.WinInvalid[toolbar] {
		t.Fatal("TB_SETIMAGELIST did not invalidate the toolbar")
	}
	hctx.WinInvalid[toolbar] = false
	if result, handled := hctx.BuiltinWndProc(toolbar, 0x0400+48, 0, secondImageList); !handled || result != firstImageList {
		t.Fatalf("second TB_SETIMAGELIST = (%d, %v), want (%d, true)", result, handled, firstImageList)
	}
	if !hctx.WinInvalid[toolbar] {
		t.Fatal("replacing the toolbar image list did not invalidate the toolbar")
	}
	if result, handled := hctx.BuiltinWndProc(toolbar, 0x0400+49, 0, 0); !handled || result != secondImageList {
		t.Fatalf("TB_GETIMAGELIST = (%d, %v), want (%d, true)", result, handled, secondImageList)
	}
	state := hctx.HwndChildren[toolbar]
	if state.tbBitmapIconW != 4 || state.tbBitmapIconH != 4 {
		t.Fatalf("toolbar image size = %dx%d, want 4x4", state.tbBitmapIconW, state.tbBitmapIconH)
	}
	if result, handled := hctx.BuiltinWndProc(toolbar, 0x000F, 0, 0); !handled || result != 0 {
		t.Fatalf("toolbar WM_PAINT = (%d, %v), want (0, true)", result, handled)
	}
	offset := 11*window.Stride + 12*4
	color := uint32(window.Pix[offset]) |
		uint32(window.Pix[offset+1])<<8 |
		uint32(window.Pix[offset+2])<<16
	if color != 0x563412 {
		t.Fatalf("toolbar image pixel = %#x, want %#x", color, uint32(0x563412))
	}
}

func TestToolbarLayoutSignature(t *testing.T) {
	first := &toolbarState{buttons: []tbButton{{id: 1, iBitmap: 2}, {id: 3, iBitmap: 4, style: 1}}}
	second := &toolbarState{buttons: append([]tbButton(nil), first.buttons...)}
	if toolbarLayoutSignature(first) == 0 || toolbarLayoutSignature(first) != toolbarLayoutSignature(second) {
		t.Fatal("equivalent toolbar layouts did not produce the same signature")
	}
	second.buttons[1].id = 5
	if toolbarLayoutSignature(first) == toolbarLayoutSignature(second) {
		t.Fatal("different toolbar layouts produced the same signature")
	}
}

func TestTabInputNeedsSubclassFirst(t *testing.T) {
	tests := []struct {
		name      string
		hasGuest  bool
		inBuiltin bool
		msg       uint32
		wantDefer bool
	}{
		{name: "subclass mouse down", hasGuest: true, msg: 0x0201, wantDefer: true},
		{name: "subclass double click", hasGuest: true, msg: 0x0203, wantDefer: true},
		{name: "default control mouse down", msg: 0x0201},
		{name: "call original mouse down", hasGuest: true, inBuiltin: true, msg: 0x0201},
		{name: "control message", hasGuest: true, msg: 0x130b},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tabInputNeedsSubclassFirst(tt.hasGuest, tt.inBuiltin, tt.msg); got != tt.wantDefer {
				t.Fatalf("tabInputNeedsSubclassFirst() = %v, want %v", got, tt.wantDefer)
			}
		})
	}
}

func TestSelectTabFromInputNotifiesInNativeOrder(t *testing.T) {
	if tcmAdjustRect != 0x1328 || tcnSelChange != 0xFFFFFDD9 || tcnSelChanging != 0xFFFFFDD8 {
		t.Fatalf("tab ABI values = (%#x, %#x, %#x)", tcmAdjustRect, tcnSelChange, tcnSelChanging)
	}
	tab := &tabState{items: []tabItem{{text: "one"}, {text: "two"}}, curSel: 0}
	var notifications []uint32
	changed := selectTabFromInput(tab, 1, func(code uint32) uint64 {
		notifications = append(notifications, code)
		return 0
	})
	if !changed || tab.curSel != 1 {
		t.Fatalf("selection changed=%v curSel=%d, want true and 1", changed, tab.curSel)
	}
	if len(notifications) != 2 || notifications[0] != tcnSelChanging || notifications[1] != tcnSelChange {
		t.Fatalf("notifications = %#v, want TCN_SELCHANGING then TCN_SELCHANGE", notifications)
	}
}

func TestSelectTabFromInputCanBeCancelled(t *testing.T) {
	tab := &tabState{items: []tabItem{{text: "one"}, {text: "two"}}, curSel: 0}
	var notifications []uint32
	changed := selectTabFromInput(tab, 1, func(code uint32) uint64 {
		notifications = append(notifications, code)
		return 1
	})
	if changed || tab.curSel != 0 {
		t.Fatalf("selection changed=%v curSel=%d, want false and 0", changed, tab.curSel)
	}
	if len(notifications) != 1 || notifications[0] != tcnSelChanging {
		t.Fatalf("notifications = %#v, want only TCN_SELCHANGING", notifications)
	}
}

func TestAdjustTabRect(t *testing.T) {
	window := [4]int32{0, 0, 100, 100}
	display := adjustTabRect(window, 0, false, 22, 1)
	if want := [4]int32{4, 26, 96, 96}; display != want {
		t.Fatalf("display rect = %v, want %v", display, want)
	}
	if got := adjustTabRect(display, 0, true, 22, 1); got != window {
		t.Fatalf("round trip = %v, want %v", got, window)
	}
}

func TestAdjustBottomTabRect(t *testing.T) {
	window := [4]int32{0, 0, 100, 100}
	got := adjustTabRect(window, 0x0002, false, 22, 1)
	want := [4]int32{4, 4, 96, 74}
	if got != want {
		t.Fatalf("bottom display rect = %v, want %v", got, want)
	}
}

func TestTabRowCount(t *testing.T) {
	if got := tabRowCount(nil); got != 0 {
		t.Fatalf("nil tab row count = %d, want 0", got)
	}
	tab := &tabState{items: []tabItem{{text: "readme.txt"}}}
	if got := tabRowCount(tab); got != 1 {
		t.Fatalf("populated tab row count = %d, want 1", got)
	}
}
