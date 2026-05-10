//go:build guest_windows

package d3d9

import (
	"encoding/binary"
	"testing"
)

// psIdent is the identity .xyzw swizzle.
var psIdent = [4]int{0, 1, 2, 3}

// assertModule runs the shared structural checks: length multiple of 4, > 100
// words, correct SPIR-V magic, and (when spirv-val is on PATH) validation.
func assertModule(t *testing.T, data []byte) {
	t.Helper()
	if len(data)%4 != 0 {
		t.Fatalf("module length %d is not a multiple of 4", len(data))
	}
	words := len(data) / 4
	if words <= 100 {
		t.Fatalf("module is trivial: %d words, want > 100", words)
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != spvMagicNumber {
		t.Fatalf("bad magic 0x%08x, want 0x%08x", magic, uint32(spvMagicNumber))
	}
	validateWithSpirvVal(t, data)
}

// TestEmitPixelSPIRVTexture builds a synthetic ps_1_3 that samples a texture and
// moves the texel to the color output:
//   tex t0            ; sample sampler 0 at texcoord 0 -> t0
//   mov oC0, t0       ; final color = texel
func TestEmitPixelSPIRVTexture(t *testing.T) {
	sh := &Shader{
		Kind:     ShaderPixel,
		MajorVer: 1,
		MinorVer: 3,
		Instrs: []Instr{
			{Op: sioTEX, Dst: &DstParam{RegType: regAddr, RegNum: 0, WriteMask: 0xF}},
			{Op: sioMOV, Dst: &DstParam{RegType: regColorOut, RegNum: 0, WriteMask: 0xF},
				Src: []SrcParam{{RegType: regAddr, RegNum: 0, Swizzle: psIdent}}},
		},
	}
	data, err := EmitPixelSPIRV(sh)
	if err != nil {
		t.Fatalf("EmitPixelSPIRV: %v", err)
	}
	assertModule(t, data)
}

// TestEmitPixelSPIRVArithmetic exercises the arithmetic opcode set with temp,
// color input and constant registers plus a negate source modifier:
//   mad r0, v0, c0, v1      ; r0 = v0*c0 + v1
//   sub r1, r0, c1          ; r1 = r0 - c1
//   dp3 r1, r1, v0          ; r1 = dot3(r1, v0) broadcast
//   lrp oC0, r1, r0, -v1    ; oC0 = lerp(-v1, r0, r1)
func TestEmitPixelSPIRVArithmetic(t *testing.T) {
	sh := &Shader{
		Kind:     ShaderPixel,
		MajorVer: 1,
		MinorVer: 3,
		Instrs: []Instr{
			{Op: sioMAD, Dst: &DstParam{RegType: regTemp, RegNum: 0, WriteMask: 0xF},
				Src: []SrcParam{
					{RegType: regInput, RegNum: 0, Swizzle: psIdent},
					{RegType: regConst, RegNum: 0, Swizzle: psIdent},
					{RegType: regInput, RegNum: 1, Swizzle: psIdent},
				}},
			{Op: sioSUB, Dst: &DstParam{RegType: regTemp, RegNum: 1, WriteMask: 0xF},
				Src: []SrcParam{
					{RegType: regTemp, RegNum: 0, Swizzle: psIdent},
					{RegType: regConst, RegNum: 1, Swizzle: psIdent},
				}},
			{Op: sioDP3, Dst: &DstParam{RegType: regTemp, RegNum: 1, WriteMask: 0xF},
				Src: []SrcParam{
					{RegType: regTemp, RegNum: 1, Swizzle: psIdent},
					{RegType: regInput, RegNum: 0, Swizzle: psIdent},
				}},
			{Op: sioLRP, Dst: &DstParam{RegType: regColorOut, RegNum: 0, WriteMask: 0xF},
				Src: []SrcParam{
					{RegType: regTemp, RegNum: 1, Swizzle: psIdent},
					{RegType: regTemp, RegNum: 0, Swizzle: psIdent},
					{RegType: regInput, RegNum: 1, Swizzle: psIdent, Modifier: 1}, // negate
				}},
		},
	}
	data, err := EmitPixelSPIRV(sh)
	if err != nil {
		t.Fatalf("EmitPixelSPIRV: %v", err)
	}
	assertModule(t, data)
}

// TestEmitPixelSPIRVWriteMask covers the masked-store path (partial write mask)
// and a per-lane swizzle on a source.
func TestEmitPixelSPIRVWriteMask(t *testing.T) {
	sh := &Shader{
		Kind:     ShaderPixel,
		MajorVer: 1,
		MinorVer: 1,
		Instrs: []Instr{
			// mov r0, c0
			{Op: sioMOV, Dst: &DstParam{RegType: regTemp, RegNum: 0, WriteMask: 0xF},
				Src: []SrcParam{{RegType: regConst, RegNum: 0, Swizzle: psIdent}}},
			// mul oC0.xy, r0, v0.yxwz  (partial mask + swizzle)
			{Op: sioMUL, Dst: &DstParam{RegType: regColorOut, RegNum: 0, WriteMask: 0x3},
				Src: []SrcParam{
					{RegType: regTemp, RegNum: 0, Swizzle: psIdent},
					{RegType: regInput, RegNum: 0, Swizzle: [4]int{1, 0, 3, 2}},
				}},
		},
	}
	data, err := EmitPixelSPIRV(sh)
	if err != nil {
		t.Fatalf("EmitPixelSPIRV: %v", err)
	}
	assertModule(t, data)
}

func TestEmitPixelSPIRVRejectsVertexShader(t *testing.T) {
	sh := &Shader{Kind: ShaderVertex, MajorVer: 1, MinorVer: 1}
	if _, err := EmitPixelSPIRV(sh); err == nil {
		t.Fatal("expected error for a vertex shader, got nil")
	}
}

func TestEmitPixelSPIRVRejectsUnsupportedOpcode(t *testing.T) {
	sh := &Shader{
		Kind:     ShaderPixel,
		MajorVer: 1,
		MinorVer: 1,
		Instrs: []Instr{
			{Op: sioRSQ, Dst: &DstParam{RegType: regTemp, RegNum: 0, WriteMask: 0xF},
				Src: []SrcParam{{RegType: regInput, RegNum: 0, Swizzle: psIdent}}},
		},
	}
	if _, err := EmitPixelSPIRV(sh); err == nil {
		t.Fatal("expected error for unsupported opcode (rsq), got nil")
	}
}

func TestEmitPixelSPIRVRejectsBadSourceModifier(t *testing.T) {
	sh := &Shader{
		Kind:     ShaderPixel,
		MajorVer: 1,
		MinorVer: 1,
		Instrs: []Instr{
			{Op: sioMOV, Dst: &DstParam{RegType: regColorOut, RegNum: 0, WriteMask: 0xF},
				Src: []SrcParam{{RegType: regInput, RegNum: 0, Swizzle: psIdent, Modifier: 5}}},
		},
	}
	if _, err := EmitPixelSPIRV(sh); err == nil {
		t.Fatal("expected error for unsupported source modifier, got nil")
	}
}
