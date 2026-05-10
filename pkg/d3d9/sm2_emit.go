//go:build guest_windows

package d3d9

import (
	"fmt"
	"sort"
)

// Emitter for Direct3D 9 shader-model 1.x VERTEX shaders. It walks the parsed
// token stream (see sm2_parser.go) and produces a SPIR-V vertex shader module.
//
// The output layout follows the SPIR-V logical-layout rules (SPIR-V spec 2.4)
// so that the module validates with spirv-val:
//   Capability -> ExtInstImport -> MemoryModel -> EntryPoint -> Decorations ->
//   Types/Constants/GlobalVariables -> Function.
//
// Register model:
//   r#  temp   -> private vec4 (Function storage) variables
//   v#  input  -> input attribute at location = register index (loaded as vec4)
//   c#  const  -> uniform block { vec4 c[N]; } at set 0, binding 0
//   oPos       -> gl_Position (via gl_PerVertex block)
//   oD#/oT#    -> output vec4 locations (only emitted when actually written)
//
// Every value is computed in vec4; source swizzles and the negate modifier are
// applied per-lane, and the destination write mask merges only the masked lanes.

// SPIR-V opcode / decoration values not aliased in spirv.go.
const (
	smOpTypeArray           = 28
	smDecorationArrayStride = 6
	smStorageClassUniform   = 2
)

// GLSL.std.450 extended-instruction opcodes.
const (
	smGlslFMin        = 37
	smGlslFMax        = 40
	smGlslInverseSqrt = 32
)

// EmitVertexSPIRV translates a parsed SM1.x vertex shader into a SPIR-V module
// (a little-endian []byte word stream, the same type CreateShaderModule and
// GenerateFFPVertexShader use). It returns an error for any opcode, register
// type, or source modifier it does not know how to translate, rather than
// emitting incorrect code.
func EmitVertexSPIRV(sh *Shader) ([]byte, error) {
	if sh == nil {
		return nil, fmt.Errorf("d3d9: nil shader")
	}
	if sh.Kind != ShaderVertex {
		return nil, fmt.Errorf("d3d9: EmitVertexSPIRV requires a vertex shader, got kind %d", sh.Kind)
	}

	// Prescan: discover which registers are referenced and validate opcodes,
	// register types, and source modifiers before emitting anything.
	tempSet := map[int]bool{}
	inputSet := map[int]bool{}
	constSet := map[int]bool{}
	attrOut := map[int]bool{}
	texOut := map[int]bool{}
	usePos := false

	recordSrc := func(s SrcParam) error {
		switch s.RegType {
		case regTemp:
			tempSet[s.RegNum] = true
		case regInput:
			inputSet[s.RegNum] = true
		case regConst:
			constSet[s.RegNum] = true
		default:
			return fmt.Errorf("d3d9: unsupported source register type %d", s.RegType)
		}
		if s.Modifier != 0 && s.Modifier != 1 {
			return fmt.Errorf("d3d9: unsupported source modifier %d", s.Modifier)
		}
		if s.Relative {
			return fmt.Errorf("d3d9: relative addressing is not supported")
		}
		return nil
	}
	recordDst := func(d *DstParam) error {
		if d == nil {
			return fmt.Errorf("d3d9: instruction is missing a destination")
		}
		switch d.RegType {
		case regTemp:
			tempSet[d.RegNum] = true
		case regRastOut:
			if d.RegNum != 0 {
				return fmt.Errorf("d3d9: unsupported rastout register oReg%d (only oPos)", d.RegNum)
			}
			usePos = true
		case regAttrOut:
			attrOut[d.RegNum] = true
		case regTexCrdOut:
			texOut[d.RegNum] = true
		default:
			return fmt.Errorf("d3d9: unsupported destination register type %d", d.RegType)
		}
		return nil
	}

	for _, in := range sh.Instrs {
		switch in.Op {
		case sioNOP:
			continue
		case sioDCL:
			if in.Dst != nil && in.Dst.RegType == regInput {
				inputSet[in.Dst.RegNum] = true
			}
			continue
		case sioMOV, sioADD, sioSUB, sioMUL, sioMAD, sioDP3, sioDP4,
			sioRSQ, sioRCP, sioMIN, sioMAX, sioM4x4, sioM3x3:
			// translatable below
		default:
			return nil, fmt.Errorf("d3d9: unsupported opcode %d", in.Op)
		}
		if err := recordDst(in.Dst); err != nil {
			return nil, err
		}
		nsrc := opSrcCount(in.Op)
		if len(in.Src) < nsrc {
			return nil, fmt.Errorf("d3d9: opcode %d needs %d sources, got %d", in.Op, nsrc, len(in.Src))
		}
		for _, s := range in.Src {
			if err := recordSrc(s); err != nil {
				return nil, err
			}
		}
		// Matrix ops read a run of constant registers starting at src1.
		if in.Op == sioM4x4 || in.Op == sioM3x3 {
			rows := 4
			if in.Op == sioM3x3 {
				rows = 3
			}
			base := in.Src[1].RegNum
			for r := 0; r < rows; r++ {
				constSet[base+r] = true
			}
		}
	}

	hasConst := len(constSet) > 0
	maxConst := 0
	for k := range constSet {
		if k > maxConst {
			maxConst = k
		}
	}
	arraySize := maxConst + 1
	if arraySize < 1 {
		arraySize = 1
	}

	inputRegs := sortedKeys(inputSet)
	attrRegs := sortedKeys(attrOut)
	texRegs := sortedKeys(texOut)
	tempRegs := sortedKeys(tempSet)
	constRegs := sortedKeys(constSet)

	b := NewBuilder()
	b.Capability(spvCapabilityShader)
	glsl := b.ExtInstImport("GLSL.std.450")
	b.MemoryModel(spvAddressingModelLogical, spvMemoryModelGLSL450)

	// Pre-allocate result IDs so EntryPoint and the decoration section can
	// forward-reference variables/types that are defined further down.
	mainID := b.AllocID()

	inputVar := map[int]uint32{}
	for _, r := range inputRegs {
		inputVar[r] = b.AllocID()
	}
	var perVertexType, outPosVar uint32
	if usePos {
		perVertexType = b.AllocID()
		outPosVar = b.AllocID()
	}
	attrVar := map[int]uint32{}
	for _, r := range attrRegs {
		attrVar[r] = b.AllocID()
	}
	texVar := map[int]uint32{}
	for _, r := range texRegs {
		texVar[r] = b.AllocID()
	}
	var uboArrayType, uboStructType, uboVar uint32
	if hasConst {
		uboArrayType = b.AllocID()
		uboStructType = b.AllocID()
		uboVar = b.AllocID()
	}

	// Entry point interface: all Input and Output variables (SPIR-V 1.0).
	var iface []uint32
	for _, r := range inputRegs {
		iface = append(iface, inputVar[r])
	}
	if usePos {
		iface = append(iface, outPosVar)
	}
	for _, r := range attrRegs {
		iface = append(iface, attrVar[r])
	}
	for _, r := range texRegs {
		iface = append(iface, texVar[r])
	}
	b.EntryPoint(spvExecutionModelVertex, mainID, "main", iface...)

	// Decorations.
	if usePos {
		b.Decorate(perVertexType, spvDecorationBlock)
		b.MemberDecorate(perVertexType, 0, spvDecorationBuiltIn, spvBuiltInPosition)
	}
	for _, r := range inputRegs {
		b.Decorate(inputVar[r], spvDecorationLocation, uint32(r))
	}
	for _, r := range attrRegs {
		b.Decorate(attrVar[r], spvDecorationLocation, uint32(r))
	}
	for _, r := range texRegs {
		// Offset texcoord outputs past the color outputs to avoid clashes.
		b.Decorate(texVar[r], spvDecorationLocation, uint32(4+r))
	}
	if hasConst {
		b.Decorate(uboArrayType, smDecorationArrayStride, 16)
		b.Decorate(uboStructType, spvDecorationBlock)
		b.MemberDecorate(uboStructType, 0, spvDecorationOffset, 0)
		b.Decorate(uboVar, spvDecorationDescriptor, 0)
		b.Decorate(uboVar, spvDecorationBinding, 0)
	}

	// Types.
	voidType := b.TypeVoid()
	floatType := b.TypeFloat(32)
	intType := b.TypeInt(32, 1)
	vec3Type := b.TypeVector(floatType, 3)
	vec4Type := b.TypeVector(floatType, 4)

	// Constants (all constants must live in the global section, never inside
	// the function body).
	float0 := b.Float32Constant(floatType, 0)
	float1 := b.Float32Constant(floatType, 1)
	intConst := map[int]uint32{}
	mkInt := func(k int) uint32 {
		if id, ok := intConst[k]; ok {
			return id
		}
		id := b.Constant(intType, uint32(k))
		intConst[k] = id
		return id
	}
	mkInt(0) // struct-member / gl_Position member index
	for _, k := range constRegs {
		mkInt(k)
	}
	var lengthConst uint32
	if hasConst {
		lengthConst = b.Constant(intType, uint32(arraySize))
	}

	if usePos {
		b.Op(spvOpTypeStruct, perVertexType, vec4Type)
	}
	if hasConst {
		b.Op(smOpTypeArray, uboArrayType, vec4Type, lengthConst)
		b.Op(spvOpTypeStruct, uboStructType, uboArrayType)
	}

	inVec4Ptr := b.TypePointer(spvStorageClassInput, vec4Type)
	outVec4Ptr := b.TypePointer(spvStorageClassOutput, vec4Type)
	var outPerVertexPtr uint32
	if usePos {
		outPerVertexPtr = b.TypePointer(spvStorageClassOutput, perVertexType)
	}
	var uboStructPtr, uboVec4Ptr uint32
	if hasConst {
		uboStructPtr = b.TypePointer(smStorageClassUniform, uboStructType)
		uboVec4Ptr = b.TypePointer(smStorageClassUniform, vec4Type)
	}
	tempPtr := b.TypePointer(spvStorageClassFunction, vec4Type)

	// Global variables.
	for _, r := range inputRegs {
		b.Op(spvOpVariable, inVec4Ptr, inputVar[r], spvStorageClassInput)
	}
	if usePos {
		b.Op(spvOpVariable, outPerVertexPtr, outPosVar, spvStorageClassOutput)
	}
	for _, r := range attrRegs {
		b.Op(spvOpVariable, outVec4Ptr, attrVar[r], spvStorageClassOutput)
	}
	for _, r := range texRegs {
		b.Op(spvOpVariable, outVec4Ptr, texVar[r], spvStorageClassOutput)
	}
	if hasConst {
		b.Op(spvOpVariable, uboStructPtr, uboVar, smStorageClassUniform)
	}

	fnType := b.TypeFunction(voidType)

	// Function.
	b.Function(voidType, mainID, fnType)
	b.Label()

	// Temp variables must be the first instructions of the entry block.
	tempVar := map[int]uint32{}
	for _, r := range tempRegs {
		tempVar[r] = b.Variable(tempPtr, spvStorageClassFunction)
	}

	// Helpers over the emitted types.
	broadcast := func(f uint32) uint32 {
		return b.CompositeConstruct(vec4Type, f, f, f, f)
	}
	toVec3 := func(v uint32) uint32 {
		x := b.CompositeExtract(floatType, v, 0)
		y := b.CompositeExtract(floatType, v, 1)
		z := b.CompositeExtract(floatType, v, 2)
		return b.CompositeConstruct(vec3Type, x, y, z)
	}
	extInst := func(rt uint32, op uint32, args ...uint32) uint32 {
		id := b.AllocID()
		operands := []uint32{rt, id, glsl, op}
		operands = append(operands, args...)
		b.Op(spvOpExtInst, operands...)
		return id
	}
	loadConst := func(idx int) uint32 {
		ptr := b.AccessChain(uboVec4Ptr, uboVar, intConst[0], mkIntCached(intConst, idx))
		return b.Load(vec4Type, ptr)
	}
	loadReg := func(regType, regNum int) (uint32, error) {
		switch regType {
		case regTemp:
			return b.Load(vec4Type, tempVar[regNum]), nil
		case regInput:
			return b.Load(vec4Type, inputVar[regNum]), nil
		case regConst:
			return loadConst(regNum), nil
		}
		return 0, fmt.Errorf("d3d9: cannot load register type %d", regType)
	}
	readSrc := func(s SrcParam) (uint32, error) {
		base, err := loadReg(s.RegType, s.RegNum)
		if err != nil {
			return 0, err
		}
		x := b.CompositeExtract(floatType, base, uint32(s.Swizzle[0]))
		y := b.CompositeExtract(floatType, base, uint32(s.Swizzle[1]))
		z := b.CompositeExtract(floatType, base, uint32(s.Swizzle[2]))
		w := b.CompositeExtract(floatType, base, uint32(s.Swizzle[3]))
		v := b.CompositeConstruct(vec4Type, x, y, z, w)
		if s.Modifier == 1 {
			v = b.FNegate(vec4Type, v)
		}
		return v, nil
	}
	dstPointer := func(d *DstParam) uint32 {
		switch d.RegType {
		case regTemp:
			return tempVar[d.RegNum]
		case regRastOut:
			return b.AccessChain(outVec4Ptr, outPosVar, intConst[0])
		case regAttrOut:
			return attrVar[d.RegNum]
		case regTexCrdOut:
			return texVar[d.RegNum]
		}
		return 0
	}
	storeMasked := func(d *DstParam, result uint32) {
		ptr := dstPointer(d)
		mask := d.WriteMask
		if mask == 0xF {
			b.Store(ptr, result)
			return
		}
		cur := b.Load(vec4Type, ptr)
		var comps [4]uint32
		for i := 0; i < 4; i++ {
			src := cur
			if mask&(1<<uint(i)) != 0 {
				src = result
			}
			comps[i] = b.CompositeExtract(floatType, src, uint32(i))
		}
		nv := b.CompositeConstruct(vec4Type, comps[0], comps[1], comps[2], comps[3])
		b.Store(ptr, nv)
	}

	// Body.
	for _, in := range sh.Instrs {
		switch in.Op {
		case sioNOP, sioDCL:
			continue
		case sioMOV:
			s0, err := readSrc(in.Src[0])
			if err != nil {
				return nil, err
			}
			storeMasked(in.Dst, s0)
		case sioADD, sioSUB, sioMUL, sioMIN, sioMAX:
			s0, err := readSrc(in.Src[0])
			if err != nil {
				return nil, err
			}
			s1, err := readSrc(in.Src[1])
			if err != nil {
				return nil, err
			}
			var r uint32
			switch in.Op {
			case sioADD:
				r = b.FAdd(vec4Type, s0, s1)
			case sioSUB:
				r = b.FSub(vec4Type, s0, s1)
			case sioMUL:
				r = b.FMul(vec4Type, s0, s1)
			case sioMIN:
				r = extInst(vec4Type, smGlslFMin, s0, s1)
			case sioMAX:
				r = extInst(vec4Type, smGlslFMax, s0, s1)
			}
			storeMasked(in.Dst, r)
		case sioMAD:
			s0, err := readSrc(in.Src[0])
			if err != nil {
				return nil, err
			}
			s1, err := readSrc(in.Src[1])
			if err != nil {
				return nil, err
			}
			s2, err := readSrc(in.Src[2])
			if err != nil {
				return nil, err
			}
			mul := b.FMul(vec4Type, s0, s1)
			storeMasked(in.Dst, b.FAdd(vec4Type, mul, s2))
		case sioDP3:
			s0, err := readSrc(in.Src[0])
			if err != nil {
				return nil, err
			}
			s1, err := readSrc(in.Src[1])
			if err != nil {
				return nil, err
			}
			d := b.Dot(floatType, toVec3(s0), toVec3(s1))
			storeMasked(in.Dst, broadcast(d))
		case sioDP4:
			s0, err := readSrc(in.Src[0])
			if err != nil {
				return nil, err
			}
			s1, err := readSrc(in.Src[1])
			if err != nil {
				return nil, err
			}
			d := b.Dot(floatType, s0, s1)
			storeMasked(in.Dst, broadcast(d))
		case sioRSQ:
			s0, err := readSrc(in.Src[0])
			if err != nil {
				return nil, err
			}
			scalar := b.CompositeExtract(floatType, s0, 0)
			r := extInst(floatType, smGlslInverseSqrt, scalar)
			storeMasked(in.Dst, broadcast(r))
		case sioRCP:
			s0, err := readSrc(in.Src[0])
			if err != nil {
				return nil, err
			}
			scalar := b.CompositeExtract(floatType, s0, 0)
			r := b.FDiv(floatType, float1, scalar)
			storeMasked(in.Dst, broadcast(r))
		case sioM4x4:
			s0, err := readSrc(in.Src[0])
			if err != nil {
				return nil, err
			}
			base := in.Src[1].RegNum
			var rows [4]uint32
			for i := 0; i < 4; i++ {
				row := loadConst(base + i)
				rows[i] = b.Dot(floatType, s0, row)
			}
			storeMasked(in.Dst, b.CompositeConstruct(vec4Type, rows[0], rows[1], rows[2], rows[3]))
		case sioM3x3:
			s0, err := readSrc(in.Src[0])
			if err != nil {
				return nil, err
			}
			s0xyz := toVec3(s0)
			base := in.Src[1].RegNum
			var rows [3]uint32
			for i := 0; i < 3; i++ {
				row := toVec3(loadConst(base + i))
				rows[i] = b.Dot(floatType, s0xyz, row)
			}
			storeMasked(in.Dst, b.CompositeConstruct(vec4Type, rows[0], rows[1], rows[2], float0))
		default:
			return nil, fmt.Errorf("d3d9: unsupported opcode %d", in.Op)
		}
	}

	b.Return()
	b.FunctionEnd()
	return b.Finalize(), nil
}

// opSrcCount is the number of source operands the emitter reads for op.
func opSrcCount(op int) int {
	switch op {
	case sioMOV, sioRSQ, sioRCP:
		return 1
	case sioADD, sioSUB, sioMUL, sioMIN, sioMAX, sioDP3, sioDP4, sioM4x4, sioM3x3:
		return 2
	case sioMAD:
		return 3
	}
	return 0
}

func sortedKeys(m map[int]bool) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// mkIntCached returns the pre-created int constant id for idx. All indices the
// body can ask for are interned during the types section, so a miss is a bug.
func mkIntCached(intConst map[int]uint32, idx int) uint32 {
	return intConst[idx]
}
