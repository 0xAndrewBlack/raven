//go:build guest_windows

package main

import (
	"encoding/binary"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/d3d9"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/wl"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestD3D9SurfaceDescMatchesGuestLayout(t *testing.T) {
	if got := binary.Size(d3d9SurfaceDesc{}); got != 32 {
		t.Fatalf("D3DSURFACE_DESC size = %d, want 32", got)
	}
	desc := d3d9SurfaceDesc{
		Format: 22, Type: d3d9.D3DRTYPE_SURFACE, Usage: d3d9.D3DUSAGE_DEPTHSTENCIL,
		Pool: d3d9.D3DPOOL_DEFAULT, MultiSampleType: 3, MultiSampleQuality: 4,
		Width: 640, Height: 480,
	}
	mem := mmu.New()
	const addr = uint64(0x3000)
	mem.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if !writeGuestStruct(mem, addr, desc) {
		t.Fatal("writeGuestStruct failed")
	}
	for i, want := range []uint32{22, 1, 2, 0, 3, 4, 640, 480} {
		got, err := mem.Read32(addr + uint64(i*4))
		if err != nil || got != want {
			t.Fatalf("field %d = %#x, want %#x", i, got, want)
		}
	}
}

func TestD3DCOMReleaseRunsFinalizerOnce(t *testing.T) {
	mem := mmu.New()
	cpu := x64.New(mem)
	const addr = uint64(0x12345000)
	cpu.Regs[1] = addr
	ctx := &ntapi.TrapContext{CPU: cpu, Mem: mem}
	finalized := 0
	d3dCOMMu.Lock()
	d3dCOMObjects[addr] = &d3dCOMObject{objectAddr: addr, refCount: 1, finalize: func() { finalized++ }}
	d3dCOMMu.Unlock()
	t.Cleanup(func() {
		d3dCOMMu.Lock()
		delete(d3dCOMObjects, addr)
		d3dCOMMu.Unlock()
	})

	if got := d3dDispatchCOMMethod(ctx, 2); got != 0 {
		t.Fatalf("Release returned %#x", got)
	}
	if finalized != 1 {
		t.Fatalf("finalizer calls = %d, want 1", finalized)
	}
	if got := d3dDispatchCOMMethod(ctx, 2); got != E_POINTER {
		t.Fatalf("second Release returned %#x, want E_POINTER", got)
	}
	if finalized != 1 {
		t.Fatalf("finalizer called again: %d", finalized)
	}
}

func TestD3D9ChildKeepsBridgeAliveAfterDeviceRelease(t *testing.T) {
	const childAddr = uint64(0x12346000)
	const deviceAddr = uint64(0x12347000)
	bridge := &d3d9Bridge{liveObjects: 1, deviceCOM: deviceAddr}
	d3dCOMMu.Lock()
	d3dCOMObjects[childAddr] = &d3dCOMObject{objectAddr: childAddr, refCount: 1}
	d3dCOMObjects[deviceAddr] = &d3dCOMObject{objectAddr: deviceAddr, refCount: 1, finalize: bridge.release}
	d3dCOMMu.Unlock()
	t.Cleanup(func() {
		d3dCOMMu.Lock()
		delete(d3dCOMObjects, childAddr)
		delete(d3dCOMObjects, deviceAddr)
		d3dCOMMu.Unlock()
	})

	d3d9AttachBridgeLifetime(childAddr, bridge)
	if got := d3dReleaseObject(deviceAddr); got != 1 {
		t.Fatalf("device Release returned %d, want internal reference count 1", got)
	}
	d3dCOMMu.Lock()
	_, deviceAlive := d3dCOMObjects[deviceAddr]
	d3dCOMMu.Unlock()
	if !deviceAlive {
		t.Fatal("device COM object was destroyed while child remained alive")
	}
	bridge.lifetimeMu.Lock()
	if bridge.liveObjects != 2 {
		t.Fatalf("live objects after device release = %d, want device and child", bridge.liveObjects)
	}
	bridge.lifetimeMu.Unlock()

	if got := d3dReleaseObject(childAddr); got != 0 {
		t.Fatalf("child Release returned %d", got)
	}
	bridge.lifetimeMu.Lock()
	defer bridge.lifetimeMu.Unlock()
	if bridge.liveObjects != 0 {
		t.Fatalf("live objects after child release = %d, want 0", bridge.liveObjects)
	}
	if _, alive := d3dCOMObjects[deviceAddr]; alive {
		t.Fatal("device COM object remained alive after final child release")
	}
}

func TestReadD3DPresentParameters32UsesGuestPointerLayout(t *testing.T) {
	mem := mmu.New()
	const addr = uint64(0x2000)
	mem.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	values := []uint32{1024, 768, d3d9.D3DFMT_X8R8G8B8, 2, 3, 4, 5, 0x12345678, 1, 1, 75, 6, 60, 7}
	for i, value := range values {
		if err := mem.Write32(addr+uint64(i*4), value); err != nil {
			t.Fatal(err)
		}
	}
	p, ok := readD3DPresentParameters(mem, addr, true)
	if !ok {
		t.Fatal("readD3DPresentParameters failed")
	}
	if p.HDeviceWindow != 0x12345678 || p.Windowed != 1 || p.PresentationInterval != 7 {
		t.Fatalf("misread 32-bit layout: %+v", p)
	}
}

func TestD3D9DevicePresentStdcallArgCount(t *testing.T) {
	counts := d3d9DeviceArgCounts()
	if len(counts) != d3d9DeviceMethods {
		t.Fatalf("argument count table has %d entries, want %d", len(counts), d3d9DeviceMethods)
	}
	for method, count := range counts {
		if count == 0 {
			t.Fatalf("method %d has no stdcall argument count", method)
		}
	}
	if got := counts[17]; got != 5 {
		t.Fatalf("Present stdcall arg count = %d, want 5", got)
	}
	if got := counts[28]; got != 9 {
		t.Fatalf("CreateRenderTarget stdcall arg count = %d, want 9", got)
	}
	if got := counts[84]; got != 9 {
		t.Fatalf("DrawIndexedPrimitiveUP stdcall arg count = %d, want 9", got)
	}
}

func TestD3D9ResourceStdcallArgCountsAreComplete(t *testing.T) {
	tables := []struct {
		name string
		got  []int
		want int
	}{
		{name: "texture", got: d3d9TextureArgCounts(false), want: d3d9TextureMethods},
		{name: "cube texture", got: d3d9TextureArgCounts(true), want: d3d9TextureMethods},
		{name: "vertex buffer", got: d3d9BufferArgCounts(), want: d3d9VertexBufferMethods},
		{name: "index buffer", got: d3d9BufferArgCounts(), want: d3d9IndexBufferMethods},
		{name: "vertex declaration", got: d3d9VertexDeclarationArgCounts(), want: d3d9VertexDeclarationMethods},
		{name: "surface", got: d3d9SurfaceArgCounts(), want: d3d9SurfaceMethods},
		{name: "swap chain", got: d3d9SwapChainArgCounts(), want: 10},
		{name: "shader", got: d3d9ShaderArgCounts(), want: 5},
	}
	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			if len(table.got) != table.want {
				t.Fatalf("argument count table has %d entries, want %d", len(table.got), table.want)
			}
			for method, count := range table.got {
				if count == 0 {
					t.Fatalf("method %d has no stdcall argument count", method)
				}
			}
		})
	}
	if got := d3d9TextureArgCounts(true)[19]; got != 6 {
		t.Fatalf("cube LockRect stdcall arg count = %d, want 6", got)
	}
	if got := d3d9SurfaceArgCounts()[13]; got != 4 {
		t.Fatalf("surface LockRect stdcall arg count = %d, want 4", got)
	}
}

func TestD3D9BufferLockWritesDataPointerToThirdArgument(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload any
	}{
		{name: "vertex", payload: &d3d9.VertexBuffer{Size: 32, Data: makeD3D9BufferBacking(32), Staging: makeD3D9BufferBacking(32)}},
		{name: "index", payload: &d3d9.IndexBuffer{Size: 32, Data: makeD3D9BufferBacking(32), Staging: makeD3D9BufferBacking(32)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mem := mmu.New()
			const out = uint64(0x3000)
			mem.MapRange(out, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			cpu := x64.New(mem)
			cpu.Regs[2] = 4 // RDX: OffsetToLock
			cpu.Regs[8] = 8 // R8: SizeToLock
			cpu.Regs[9] = out
			ctx := &ntapi.TrapContext{CPU: cpu, Mem: mem}
			obj := &d3dCOMObject{payload: test.payload}

			if got := d3d9ResourceDispatch(ctx, 11, obj); got != D3D_OK {
				t.Fatalf("Lock returned %#x", got)
			}
			ptr, err := mem.Read64(out)
			if err != nil || ptr == 0 {
				t.Fatalf("Lock data pointer = %#x, err = %v", ptr, err)
			}
			if got, err := mem.ReadBytes(ptr, 1); err != nil || len(got) != 1 {
				t.Fatalf("Lock data pointer is not guest-readable: %v", err)
			}
			if err := mem.Write8(ptr, 0x5a); err != nil {
				t.Fatalf("write through Lock pointer: %v", err)
			}
			var backing []byte
			switch payload := test.payload.(type) {
			case *d3d9.VertexBuffer:
				backing = payload.Data
			case *d3d9.IndexBuffer:
				backing = payload.Data
			}
			if backing[4] != 0 {
				t.Fatalf("guest write escaped staging before Unlock: %#x", backing[4])
			}
			if got := d3d9ResourceDispatch(ctx, 11, obj); got != D3DERR_INVALIDCALL {
				t.Fatalf("second Lock returned %#x, want D3DERR_INVALIDCALL", got)
			}
			if got := d3d9ResourceDispatch(ctx, 12, obj); got != D3D_OK {
				t.Fatalf("Unlock returned %#x", got)
			}
			if backing[4] != 0x5a {
				t.Fatalf("Unlock did not commit renderer backing: %#x", backing[4])
			}
			if got := d3d9ResourceDispatch(ctx, 12, obj); got != D3DERR_INVALIDCALL {
				t.Fatalf("second Unlock returned %#x, want D3DERR_INVALIDCALL", got)
			}

			cpu.Regs[2] = 33
			if got := d3d9ResourceDispatch(ctx, 11, obj); got != D3DERR_INVALIDCALL {
				t.Fatalf("out-of-range Lock returned %#x, want D3DERR_INVALIDCALL", got)
			}
			ptr, err = mem.Read64(out)
			if err != nil || ptr != 0 {
				t.Fatalf("failed Lock data pointer = %#x, err = %v", ptr, err)
			}
		})
	}
}

func TestD3D9BufferLockUsesPE32StdcallLayout(t *testing.T) {
	mem := mmu.New()
	mem.Mode32 = true
	const (
		stack = uint64(0x8000)
		out   = uint64(0x9000)
	)
	mem.MapRange(stack, mmu.PageSize*2, mmu.PermRead|mmu.PermWrite)
	cpu := x64.New(mem)
	cpu.Mode32 = true
	cpu.SetSP(stack)
	args := []uint32{0x1234, 4, 8, uint32(out), 0}
	for i, arg := range args {
		if err := mem.Write32(stack+4+uint64(i*4), arg); err != nil {
			t.Fatal(err)
		}
	}
	backing := makeD3D9BufferBacking(32)
	obj := &d3dCOMObject{payload: &d3d9.IndexBuffer{Size: 32, Data: backing, Staging: makeD3D9BufferBacking(32)}}
	ctx := &ntapi.TrapContext{CPU: cpu, Mem: mem, State: &ntapi.ProcessState{Is32: true}}

	if got := d3d9ResourceDispatch(ctx, 11, obj); got != D3D_OK {
		t.Fatalf("Lock returned %#x", got)
	}
	ptr, err := mem.Read32(out)
	if err != nil || ptr == 0 {
		t.Fatalf("PE32 Lock data pointer = %#x, err = %v", ptr, err)
	}
	if err := mem.Write8(uint64(ptr), 0xa5); err != nil {
		t.Fatalf("write through PE32 Lock pointer: %v", err)
	}
	if backing[4] != 0 {
		t.Fatalf("PE32 guest write escaped staging before Unlock: %#x", backing[4])
	}
	if got := d3d9ResourceDispatch(ctx, 12, obj); got != D3D_OK {
		t.Fatalf("Unlock returned %#x", got)
	}
	if backing[4] != 0xa5 {
		t.Fatalf("PE32 Unlock did not commit renderer backing: %#x", backing[4])
	}
}

func TestFillD3DColorRectClipsAndConvertsColor(t *testing.T) {
	win := wl.NewHeadlessWindow("test", 3, 2, 0)
	rect := [4]int32{1, -1, 4, 1}
	fillD3DColorRect(win, &rect, 0xff123456)

	if got := win.Pix[4:8]; got[0] != 0x56 || got[1] != 0x34 || got[2] != 0x12 || got[3] != 0xff {
		t.Fatalf("filled pixel = %x, want 563412ff", got)
	}
	if got := win.Pix[0:4]; got[0] != 0xc0 || got[1] != 0xc0 || got[2] != 0xc0 {
		t.Fatalf("pixel outside rect changed: %x", got)
	}
}

func TestD3D9ShaderProgramCacheUsesBytecodeIdentity(t *testing.T) {
	tokens := []uint32{
		0xfffe0101,
		0x0000001f, 0x80000000, 0x900f0000,
		0x00000001, 0x800f0003, 0x90e40000,
		0x00000014, 0xc00f0000, 0x80e40003, 0xa0e40008,
		0x0000ffff,
	}
	bridge := &d3d9Bridge{shaderCache: make(map[string]*d3d9.ShaderProgram)}
	first := bridge.shaderProgram(tokens, true)
	second := bridge.shaderProgram(append([]uint32(nil), tokens...), true)
	if first != second {
		t.Fatal("identical bytecode produced distinct shader programs")
	}
	if len(first.SPIRV) == 0 {
		t.Fatal("vertex shader was not translated")
	}

	changed := append([]uint32(nil), tokens...)
	changed[10] = 0xa0e40009
	if got := bridge.shaderProgram(changed, true); got == first {
		t.Fatal("distinct bytecode reused the cached shader program")
	}
	if got := bridge.shaderProgram(tokens, false); got == first {
		t.Fatal("vertex and pixel shaders shared a cache entry")
	}
}
