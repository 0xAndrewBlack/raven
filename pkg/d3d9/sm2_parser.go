//go:build guest_windows

package d3d9

import "math"

// Parser for the Direct3D 9 shader-model 1.x/2.x/3.x token stream (the
// D3DSIO_* bytecode kkrieger and other shader-era games hand to
// CreateVertexShader / CreatePixelShader). This is NOT the DXBC container
// used by D3D10/11 (pkg/dxbc); it is the older DWORD token stream whose
// version word is 0xFFFE02xx (vertex) or 0xFFFF02xx (pixel).
//
// Reference: the token layout is documented in the DirectX SDK
// ("Shader Binary Format"). We decode enough to translate SM2 to SPIR-V.

// ShaderKind distinguishes vertex vs pixel shaders.
type ShaderKind int

const (
	ShaderVertex ShaderKind = iota
	ShaderPixel
)

// SM opcode values (D3DSIO_*).
const (
	sioNOP         = 0
	sioMOV         = 1
	sioADD         = 2
	sioSUB         = 3
	sioMAD         = 4
	sioMUL         = 5
	sioRCP         = 6
	sioRSQ         = 7
	sioDP3         = 8
	sioDP4         = 9
	sioMIN         = 10
	sioMAX         = 11
	sioSLT         = 12
	sioSGE         = 13
	sioEXP         = 14
	sioLOG         = 15
	sioLIT         = 16
	sioDST         = 17
	sioLRP         = 18
	sioFRC         = 19
	sioM4x4        = 20
	sioM4x3        = 21
	sioM3x4        = 22
	sioM3x3        = 23
	sioM3x2        = 24
	sioCALL        = 25
	sioCALLNZ      = 26
	sioLOOP        = 27
	sioRET         = 28
	sioENDLOOP     = 29
	sioLABEL       = 30
	sioDCL         = 31
	sioPOW         = 32
	sioCRS         = 33
	sioSGN         = 34
	sioABS         = 35
	sioNRM         = 36
	sioSINCOS      = 37
	sioREP         = 38
	sioENDREP      = 39
	sioIF          = 40
	sioIFC         = 41
	sioELSE        = 42
	sioENDIF       = 43
	sioBREAK       = 44
	sioBREAKC      = 45
	sioMOVA        = 46
	sioDEFB        = 47
	sioDEFI        = 48
	sioTEXCOORD    = 64
	sioTEXKILL     = 65
	sioTEX         = 66 // texld
	sioTEXBEM      = 67
	sioTEXBEML     = 68
	sioTEXREG2AR   = 69
	sioTEXREG2GB   = 70
	sioTEXM3x2PAD  = 71
	sioTEXM3x2TEX  = 72
	sioTEXM3x3PAD  = 73
	sioTEXM3x3TEX  = 74
	sioTEXM3x3SPEC = 76
	sioTEXM3x3VSPEC = 77
	sioEXPP        = 78
	sioLOGP        = 79
	sioCND         = 80
	sioDEF         = 81
	sioTEXREG2RGB  = 82
	sioTEXDP3TEX   = 83
	sioTEXM3x2DEPTH = 84
	sioTEXDP3      = 85
	sioTEXM3x3     = 86
	sioTEXDEPTH    = 87
	sioCMP         = 88
	sioBEM         = 89
	sioDP2ADD      = 90
	sioDSX         = 91
	sioDSY         = 92
	sioTEXLDD      = 93
	sioSETP        = 94
	sioTEXLDL      = 95
	sioBREAKP      = 96
	sioPHASE       = 0xFFFD
	sioCOMMENT     = 0xFFFE
	sioEND         = 0xFFFF
)

// Register file types (D3DSPR_*).
const (
	regTemp    = 0  // r#
	regInput   = 1  // v#
	regConst   = 2  // c#
	regAddr    = 3  // a# (vs) / t# texture coord (ps<1.4)
	regRastOut = 4  // oPos/oFog/oPts (vs)
	regAttrOut = 5  // oD# (vs)
	regTexCrdOut = 6 // oT# (vs)
	regOutput  = 6  // o# (vs3)
	regConstInt = 7 // i#
	regColorOut = 8 // oC# (ps)
	regDepthOut = 9 // oDepth (ps)
	regSampler = 10 // s#
	regConst2  = 11
	regConst3  = 12
	regConst4  = 13
	regConstBool = 14 // b#
	regLoop    = 15
	regTempFloat16 = 16
	regMiscType = 17 // vPos/vFace (ps3)
	regLabel   = 18
	regPredicate = 19
)

// Swizzle/write-mask component indices.
const (
	compX = 0
	compY = 1
	compZ = 2
	compW = 3
)

// DstParam is a decoded destination operand.
type DstParam struct {
	RegType   int
	RegNum    int
	WriteMask int // bit0=x bit1=y bit2=z bit3=w
	Modifier  int // result modifier (_sat=0x1, etc.)
	Shift     int
}

// SrcParam is a decoded source operand.
type SrcParam struct {
	RegType  int
	RegNum   int
	Swizzle  [4]int // component index per output lane
	Modifier int    // source modifier (D3DSPSM_*)
	Relative bool
}

// Instr is one decoded shader instruction.
type Instr struct {
	Op   int
	Dst  *DstParam
	Src  []SrcParam
	// For def/defi: the 4 immediate float/int values.
	DefReg int
	Def    [4]float32
	// For dcl: usage/index (vertex) or sampler texture type (pixel).
	DclUsage      int
	DclUsageIndex int
	DclSampler    int
}

// Shader is a parsed SM shader program.
type Shader struct {
	Kind        ShaderKind
	MajorVer    int
	MinorVer    int
	Instrs      []Instr
}

func regTypeOf(tok uint32) int {
	// D3D9 register type is a 5-bit field split across the token: the low 3
	// bits at [30:28] and the high 2 bits at [12:11] (d3d9types.h
	// D3DSP_REGTYPE_MASK / _MASK2).
	return int((tok>>28)&0x7) | int((tok>>11)&0x3)<<3
}

func decodeDst(tok uint32) *DstParam {
	return &DstParam{
		RegType:   regTypeOf(tok),
		RegNum:    int(tok & 0x7FF),
		WriteMask: int((tok >> 16) & 0xF),
		Modifier:  int((tok >> 20) & 0xF),
		Shift:     int((tok >> 24) & 0xF),
	}
}

func decodeSrc(tok uint32) SrcParam {
	sw := (tok >> 16) & 0xFF
	return SrcParam{
		RegType:  regTypeOf(tok),
		RegNum:   int(tok & 0x7FF),
		Swizzle:  [4]int{int(sw & 0x3), int((sw >> 2) & 0x3), int((sw >> 4) & 0x3), int((sw >> 6) & 0x3)},
		Modifier: int((tok >> 24) & 0xF),
		Relative: (tok>>13)&0x3 != 0,
	}
}

// ParseSM parses a D3D9 shader token stream. Returns nil, false if the stream
// is not a recognised SM1-3 program.
func ParseSM(tokens []uint32) (*Shader, bool) {
	if len(tokens) < 2 {
		return nil, false
	}
	ver := tokens[0]
	hi := ver >> 16
	var kind ShaderKind
	switch hi {
	case 0xFFFE:
		kind = ShaderVertex
	case 0xFFFF:
		kind = ShaderPixel
	default:
		return nil, false
	}
	sh := &Shader{
		Kind:     kind,
		MajorVer: int((ver >> 8) & 0xFF),
		MinorVer: int(ver & 0xFF),
	}
	i := 1
	for i < len(tokens) {
		tok := tokens[i]
		op := int(tok & 0xFFFF)
		if op == sioEND {
			break
		}
		if op == sioCOMMENT {
			// comment length in bits [30:16]
			n := int((tok >> 16) & 0x7FFF)
			i += 1 + n
			continue
		}
		// Instruction length: bits [27:24] for SM2+, else derive from opcode.
		length := int((tok >> 24) & 0xF)
		body := tokens[i+1:]
		if length == 0 || i+1+length > len(tokens) {
			// SM1.x has no length field; fall back to a conservative decode
			// using per-opcode operand counts. For SM2+ length should be set.
			length = sm1OperandCount(op)
		}
		if i+1+length > len(tokens) {
			return nil, false
		}
		in := Instr{Op: op}
		switch op {
		case sioDEF:
			in.DefReg = int(body[0] & 0x7FF)
			in.Def = [4]float32{
				f32bits(body[1]), f32bits(body[2]), f32bits(body[3]), f32bits(body[4]),
			}
		case sioDEFI:
			in.DefReg = int(body[0] & 0x7FF)
		case sioDCL:
			// dcl: token0 = usage/sampler info, token1 = dst param
			usage := body[0]
			in.DclUsage = int(usage & 0x1F)
			in.DclUsageIndex = int((usage >> 16) & 0xF)
			in.DclSampler = int((usage >> 27) & 0xF)
			in.Dst = decodeDst(body[1])
		default:
			// Regular arithmetic/texture: dst then srcs.
			nSrc := length - 1
			if opHasNoDst(op) {
				nSrc = length
			} else if length >= 1 {
				in.Dst = decodeDst(body[0])
			}
			base := 1
			if opHasNoDst(op) {
				base = 0
			}
			for s := 0; s < nSrc && base+s < len(body); s++ {
				in.Src = append(in.Src, decodeSrc(body[base+s]))
			}
		}
		sh.Instrs = append(sh.Instrs, in)
		i += 1 + length
	}
	return sh, true
}

func opHasNoDst(op int) bool {
	switch op {
	case sioNOP, sioRET, sioENDLOOP, sioENDREP, sioELSE, sioENDIF, sioBREAK,
		sioLABEL, sioCALL, sioLOOP, sioREP, sioIF, sioIFC, sioBREAKC, sioTEXKILL:
		return true
	}
	return false
}

// sm1OperandCount gives a fallback token count (dst + srcs) for SM1.x streams
// with no per-instruction length field. Counts verified against kkrieger's
// real vs_1_1/ps_1_3 token streams.
func sm1OperandCount(op int) int {
	switch op {
	case sioNOP, sioRET, sioENDLOOP, sioENDREP, sioELSE, sioENDIF:
		return 0
	case sioTEXKILL:
		return 1
	case sioMOV, sioRCP, sioRSQ, sioEXP, sioLOG, sioLIT, sioFRC, sioABS, sioNRM,
		sioMOVA, sioEXPP, sioLOGP, sioSGN, sioDCL, sioTEXCOORD, sioTEX:
		return 2
	case sioADD, sioSUB, sioMUL, sioDP3, sioDP4, sioMIN, sioMAX, sioSLT,
		sioSGE, sioDST, sioPOW, sioM4x4, sioM4x3, sioM3x4, sioM3x3, sioM3x2:
		return 3
	case sioMAD, sioLRP, sioCND, sioCMP, sioDP2ADD, sioCRS:
		return 4
	case sioDEF, sioDEFI:
		return 5
	default:
		return 3
	}
}

func f32bits(u uint32) float32 {
	return math.Float32frombits(u)
}
