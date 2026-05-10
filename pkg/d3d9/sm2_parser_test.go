//go:build guest_windows

package d3d9

import "testing"

// Build a dst token: regType (split), regNum, writeMask=xyzw.
func regTypeBits(regType int) uint32 {
	// low 3 bits at [30:28], high 2 bits at [12:11]
	return (uint32(regType)&0x7)<<28 | (uint32(regType)>>3&0x3)<<11
}

func dstTok(regType, regNum, mask int) uint32 {
	t := uint32(0x80000000) // bit31 = 1
	t |= uint32(regNum) & 0x7FF
	t |= uint32(mask&0xF) << 16
	t |= regTypeBits(regType)
	return t
}

// Build a src token with identity swizzle (.xyzw).
func srcTok(regType, regNum int) uint32 {
	t := uint32(0x80000000)
	t |= uint32(regNum) & 0x7FF
	t |= regTypeBits(regType)
	t |= uint32(0xE4) << 16 // swizzle .xyzw = 11 10 01 00 = 0xE4
	return t
}

func instrTok(op, length int) uint32 {
	return uint32(op&0xFFFF) | uint32(length&0xF)<<24
}

func TestParseSM2Vertex(t *testing.T) {
	// vs_2_0:
	//   dcl_position v0
	//   mov oPos, v0        (mov: dst + 1 src, length 2)
	//   end
	toks := []uint32{
		0xFFFE0200, // vs_2_0
		instrTok(sioDCL, 2), 0x00000000 /*usage=position(0),idx0*/, dstTok(regInput, 0, 0xF),
		instrTok(sioMOV, 2), dstTok(regRastOut, 0, 0xF), srcTok(regInput, 0),
		0x0000FFFF, // end
	}
	sh, ok := ParseSM(toks)
	if !ok {
		t.Fatal("ParseSM failed")
	}
	if sh.Kind != ShaderVertex || sh.MajorVer != 2 || sh.MinorVer != 0 {
		t.Fatalf("version: kind=%d %d.%d", sh.Kind, sh.MajorVer, sh.MinorVer)
	}
	if len(sh.Instrs) != 2 {
		t.Fatalf("got %d instrs, want 2 (dcl, mov)", len(sh.Instrs))
	}
	dcl := sh.Instrs[0]
	if dcl.Op != sioDCL || dcl.Dst == nil || dcl.Dst.RegType != regInput || dcl.Dst.RegNum != 0 {
		t.Fatalf("dcl decode wrong: %+v", dcl)
	}
	mov := sh.Instrs[1]
	if mov.Op != sioMOV || mov.Dst == nil || mov.Dst.RegType != regRastOut {
		t.Fatalf("mov dst wrong: %+v dst=%+v", mov, mov.Dst)
	}
	if len(mov.Src) != 1 || mov.Src[0].RegType != regInput || mov.Src[0].RegNum != 0 {
		t.Fatalf("mov src wrong: %+v", mov.Src)
	}
	if mov.Src[0].Swizzle != [4]int{0, 1, 2, 3} {
		t.Fatalf("mov swizzle=%v want identity", mov.Src[0].Swizzle)
	}
	if mov.Dst.WriteMask != 0xF {
		t.Fatalf("mov writemask=%x want 0xF", mov.Dst.WriteMask)
	}
}

func TestParseSMRejectsGarbage(t *testing.T) {
	if _, ok := ParseSM([]uint32{0x12345678, 0}); ok {
		t.Fatal("should reject non-shader version word")
	}
}

// Real kkrieger vs_1_1 shader captured via RAVEN_DUMP_SHADERS.
func TestParseRealKkriegerVertexShader(t *testing.T) {
	toks := []uint32{
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
	sh, ok := ParseSM(toks)
	if !ok {
		t.Fatal("ParseSM failed on real kkrieger vs")
	}
	if sh.Kind != ShaderVertex || sh.MajorVer != 1 || sh.MinorVer != 1 {
		t.Fatalf("version wrong: kind=%d %d.%d", sh.Kind, sh.MajorVer, sh.MinorVer)
	}
	wantOps := []int{sioDCL, sioDCL, sioDCL, sioDCL, sioMOV, sioM4x4, sioMUL, sioMUL, sioMUL, sioMUL, sioMAD}
	if len(sh.Instrs) != len(wantOps) {
		var got []int
		for _, in := range sh.Instrs {
			got = append(got, in.Op)
		}
		t.Fatalf("got %d instrs %v, want %d %v", len(sh.Instrs), got, len(wantOps), wantOps)
	}
	for i, in := range sh.Instrs {
		if in.Op != wantOps[i] {
			t.Fatalf("instr %d op=%d want %d", i, in.Op, wantOps[i])
		}
	}
	// m4x4 oPos, r3, c8: dst=oPos(rastout), src0=r3(temp), src1=c8(const)
	m := sh.Instrs[5]
	if m.Dst == nil || m.Dst.RegType != regRastOut {
		t.Fatalf("m4x4 dst not rastout: %+v", m.Dst)
	}
	if len(m.Src) != 2 || m.Src[0].RegType != regTemp || m.Src[0].RegNum != 3 || m.Src[1].RegType != regConst || m.Src[1].RegNum != 8 {
		t.Fatalf("m4x4 src wrong: %+v", m.Src)
	}
	// mad r9.xyz, -r8, r10, r9: src0 has negate modifier (D3DSPSM_NEG=1)
	mad := sh.Instrs[10]
	if len(mad.Src) != 3 || mad.Src[0].Modifier != 1 {
		t.Fatalf("mad src0 modifier=%d want 1 (negate): %+v", mad.Src[0].Modifier, mad.Src)
	}
}
