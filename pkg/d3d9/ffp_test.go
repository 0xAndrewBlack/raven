package d3d9

import (
	"encoding/binary"
	"testing"
)

func TestGenerateFFPVertexShader(t *testing.T) {
	shader := GenerateFFPVertexShader(2, true, 2)
	if len(shader) <= 20 {
		t.Fatalf("vertex shader too small: %d", len(shader))
	}
	if binary.LittleEndian.Uint32(shader[:4]) != spvMagicNumber {
		t.Fatalf("unexpected SPIR-V magic: 0x%x", binary.LittleEndian.Uint32(shader[:4]))
	}
}

func TestGenerateFFPFragmentShader(t *testing.T) {
	shader := GenerateFFPFragmentShader(1, []TextureStageConfig{{
		ColorOp:   D3DTOP_MODULATE,
		ColorArg1: D3DTA_TEXTURE,
		ColorArg2: D3DTA_DIFFUSE,
		AlphaOp:   D3DTOP_SELECTARG1,
		AlphaArg1: D3DTA_TEXTURE,
	}})
	if len(shader) <= 20 {
		t.Fatalf("fragment shader too small: %d", len(shader))
	}
	if binary.LittleEndian.Uint32(shader[:4]) != spvMagicNumber {
		t.Fatalf("unexpected SPIR-V magic: 0x%x", binary.LittleEndian.Uint32(shader[:4]))
	}
}
