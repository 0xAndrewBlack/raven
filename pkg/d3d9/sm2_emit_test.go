//go:build guest_windows

package d3d9

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Real kkrieger vs_1_1 token stream (captured via RAVEN_DUMP_SHADERS); identical
// to the fixture in sm2_parser_test.go. It exercises dcl/mov/m4x4/mul/mad with
// input, temp and constant registers plus a negate source modifier.
func kkriegerVertexTokens() []uint32 {
	return []uint32{
		0xfffe0101,
		0x0000001f, 0x80000000, 0x900f0000,
		0x0000001f, 0x80000005, 0x900f0001,
		0x0000001f, 0x80000003, 0x900f0002,
		0x0000001f, 0x80000006, 0x900f0003,
		0x00000001, 0x800f0003, 0x90e40000,
		0x00000014, 0xc00f0000, 0x80e40003, 0xa0e40008,
		0x00000005, 0x80070008, 0x90e40002, 0xa0ff0013,
		0x00000005, 0x8004000a, 0x90ff0002, 0xa0ff0013,
		0x00000005, 0x8003000a, 0x90e40003, 0xa0ff0013,
		0x00000005, 0x80070009, 0x80c90008, 0x80d2000a,
		0x00000004, 0x80070009, 0x81d20008, 0x80c9000a, 0x80e40009,
		0x0000ffff,
	}
}

func TestEmitVertexSPIRVKkrieger(t *testing.T) {
	sh, ok := ParseSM(kkriegerVertexTokens())
	if !ok {
		t.Fatal("ParseSM failed on real kkrieger vs")
	}

	data, err := EmitVertexSPIRV(sh)
	if err != nil {
		t.Fatalf("EmitVertexSPIRV: %v", err)
	}
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

func TestEmitVertexSPIRVRejectsPixelShader(t *testing.T) {
	sh := &Shader{Kind: ShaderPixel, MajorVer: 1, MinorVer: 1}
	if _, err := EmitVertexSPIRV(sh); err == nil {
		t.Fatal("expected error for a pixel shader, got nil")
	}
}

func TestEmitVertexSPIRVRejectsUnsupportedOpcode(t *testing.T) {
	sh := &Shader{
		Kind:     ShaderVertex,
		MajorVer: 1,
		MinorVer: 1,
		Instrs: []Instr{
			{Op: sioLOG, Dst: &DstParam{RegType: regTemp, RegNum: 0, WriteMask: 0xF},
				Src: []SrcParam{{RegType: regInput, RegNum: 0, Swizzle: [4]int{0, 1, 2, 3}}}},
		},
	}
	if _, err := EmitVertexSPIRV(sh); err == nil {
		t.Fatal("expected error for unsupported opcode (log), got nil")
	}
}

// validateWithSpirvVal runs spirv-val over the emitted module when the tool is
// on PATH; otherwise it skips that assertion.
func validateWithSpirvVal(t *testing.T, data []byte) {
	t.Helper()
	tool, err := exec.LookPath("spirv-val")
	if err != nil {
		t.Log("spirv-val not on PATH; skipping SPIR-V validation")
		return
	}
	path := filepath.Join(t.TempDir(), "shader.spv")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write module: %v", err)
	}
	out, err := exec.Command(tool, path).CombinedOutput()
	if err != nil {
		t.Fatalf("spirv-val rejected the module: %v\n%s", err, out)
	}
	t.Logf("spirv-val: valid (%d bytes)", len(data))
}
