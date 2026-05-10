//go:build guest_windows

package d3d9

import "fmt"

// Emitter for Direct3D 9 shader-model 1.x PIXEL shaders. It walks the parsed
// token stream (see sm2_parser.go) and produces a SPIR-V fragment shader
// module. It is the pixel counterpart of EmitVertexSPIRV (sm2_emit.go) and
// follows the exact same SPIR-V logical-layout ordering so the module
// validates with spirv-val:
//   Capability -> ExtInstImport -> MemoryModel -> EntryPoint -> ExecutionMode
//   -> Decorations -> Types/Constants/GlobalVariables -> Function.
//
// Register model (ps_1_1 .. ps_1_3, the opcode set kkrieger actually uses):
//   r#  temp        -> private vec4 (Function storage) variables
//   v#  color input -> input attribute at location = register index (iterated
//                      diffuse/specular; matches the vertex emitter's oD#).
//   c#  const       -> uniform block { vec4 c[N]; } (the pixel constants)
//   t#  texcoord    -> input attribute at location = 4 + register index
//                      (matches the vertex emitter's oT# texcoord outputs). A
//                      per-t# private vec4 holds the register value; it starts
//                      as the iterated texcoord and, after `tex tN`, holds the
//                      sampled texel (so later instructions can read tN).
//   oC0 color out   -> the fragment output at location 0.
//
// DESCRIPTOR BINDINGS (must match the renderer wiring):
//   - Pixel constants c[]: descriptor set 0, binding 0 (a uniform block
//     "vec4 c[N]", array stride 16, the SAME scheme as the vertex emitter).
//   - Texture samplers: one combined image+sampler per texture stage N, at
//     descriptor set 1, binding N (UniformConstant, sampled 2D float image).
//     Stage N is sampled by `tex tN` using texcoord set N.
//
// Every value is computed in vec4; source swizzles and the negate modifier are
// applied per-lane, and the destination write mask merges only the masked
// lanes, identically to the vertex emitter.
//
// Supported opcodes: nop, mov, add, sub, mul, mad (s0*s1+s2), dp3 (dot3
// broadcast), lrp (d = s2 + s0*(s1-s2), i.e. lerp(s2,s1,s0)), and tex/texld
// (the ps_1_x implicit form `tex tN`). Any other opcode, register type, or
// source modifier is rejected with an error rather than miscompiled.

// texcoordLocationBase offsets t# texcoord inputs past the v# color inputs so a
// pixel shader that uses both v0/v1 and t0.. never collides on a location. It
// mirrors the vertex emitter, which places texcoord outputs at location 4+r.
const texcoordLocationBase = 4

// isTexcoordReg reports whether a register type denotes a ps_1_x texture
// coordinate register (t#). The token stream encodes t# either as the address
// register file (regAddr) or the texcoord-out file (regTexCrdOut) depending on
// the assembler, so accept both.
func isTexcoordReg(regType int) bool {
	return regType == regAddr || regType == regTexCrdOut
}

// EmitPixelSPIRV translates a parsed SM1.x pixel shader into a SPIR-V fragment
// module (a little-endian []byte word stream). It returns an error for any
// opcode, register type, or source modifier it does not know how to translate,
// rather than emitting incorrect code.
func EmitPixelSPIRV(sh *Shader) ([]byte, error) {
	if sh == nil {
		return nil, fmt.Errorf("d3d9: nil shader")
	}
	if sh.Kind != ShaderPixel {
		return nil, fmt.Errorf("d3d9: EmitPixelSPIRV requires a pixel shader, got kind %d", sh.Kind)
	}

	// Prescan: discover referenced registers and validate opcodes, register
	// types, and source modifiers before emitting anything.
	tempSet := map[int]bool{}
	inputSet := map[int]bool{}
	constSet := map[int]bool{}
	texcoordSet := map[int]bool{} // t# registers referenced (need a coord input + holder)
	samplerSet := map[int]bool{}  // texture stages sampled via `tex tN`
	useColorOut := false

	recordSrc := func(s SrcParam) error {
		switch {
		case s.RegType == regTemp:
			tempSet[s.RegNum] = true
		case s.RegType == regInput:
			inputSet[s.RegNum] = true
		case s.RegType == regConst:
			constSet[s.RegNum] = true
		case isTexcoordReg(s.RegType):
			texcoordSet[s.RegNum] = true
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
		switch {
		case d.RegType == regTemp:
			tempSet[d.RegNum] = true
		case d.RegType == regColorOut:
			if d.RegNum != 0 {
				return fmt.Errorf("d3d9: unsupported color-output register oC%d (only oC0)", d.RegNum)
			}
			useColorOut = true
		case isTexcoordReg(d.RegType):
			texcoordSet[d.RegNum] = true
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
			// dcl in a pixel shader declares samplers or texcoord/color inputs.
			// The arithmetic prescan below discovers everything it needs from
			// actual uses, so dcl carries no additional emit state here.
			continue
		case sioTEX:
			// `tex tN`: dst is tN (a texcoord register), sampler = stage N,
			// coords = texcoord set N.
			if err := recordDst(in.Dst); err != nil {
				return nil, err
			}
			if in.Dst == nil || !isTexcoordReg(in.Dst.RegType) {
				return nil, fmt.Errorf("d3d9: tex destination must be a texcoord register")
			}
			samplerSet[in.Dst.RegNum] = true
			// Any explicit source operands are still validated/recorded.
			for _, s := range in.Src {
				if err := recordSrc(s); err != nil {
					return nil, err
				}
			}
			continue
		case sioMOV, sioADD, sioSUB, sioMUL, sioMAD, sioDP3, sioLRP:
			// translatable below
		default:
			return nil, fmt.Errorf("d3d9: unsupported opcode %d", in.Op)
		}
		if err := recordDst(in.Dst); err != nil {
			return nil, err
		}
		nsrc := psOpSrcCount(in.Op)
		if len(in.Src) < nsrc {
			return nil, fmt.Errorf("d3d9: opcode %d needs %d sources, got %d", in.Op, nsrc, len(in.Src))
		}
		for _, s := range in.Src {
			if err := recordSrc(s); err != nil {
				return nil, err
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
	constRegs := sortedKeys(constSet)
	texcoordRegs := sortedKeys(texcoordSet)
	samplerRegs := sortedKeys(samplerSet)
	tempRegs := sortedKeys(tempSet)

	b := NewBuilder()
	b.Capability(spvCapabilityShader)
	// GLSL.std.450 is imported for section-ordering parity with the vertex
	// emitter; the ps_1_x opcode set below needs no extended instructions.
	b.ExtInstImport("GLSL.std.450")
	b.MemoryModel(spvAddressingModelLogical, spvMemoryModelGLSL450)

	// Pre-allocate result IDs so EntryPoint and the decoration section can
	// forward-reference variables/types defined further down.
	mainID := b.AllocID()

	inputVar := map[int]uint32{}
	for _, r := range inputRegs {
		inputVar[r] = b.AllocID()
	}
	texcoordVar := map[int]uint32{}
	for _, r := range texcoordRegs {
		texcoordVar[r] = b.AllocID()
	}
	samplerVar := map[int]uint32{}
	for _, r := range samplerRegs {
		samplerVar[r] = b.AllocID()
	}
	var colorOutVar uint32
	if useColorOut {
		colorOutVar = b.AllocID()
	}
	var uboArrayType, uboStructType, uboVar uint32
	if hasConst {
		uboArrayType = b.AllocID()
		uboStructType = b.AllocID()
		uboVar = b.AllocID()
	}

	// Entry-point interface: all Input and Output variables (SPIR-V 1.0 lists
	// only Input/Output; UniformConstant samplers and the uniform block are
	// excluded, matching the vertex emitter).
	var iface []uint32
	for _, r := range inputRegs {
		iface = append(iface, inputVar[r])
	}
	for _, r := range texcoordRegs {
		iface = append(iface, texcoordVar[r])
	}
	if useColorOut {
		iface = append(iface, colorOutVar)
	}
	b.EntryPoint(spvExecutionModelFragment, mainID, "main", iface...)
	// Fragment shaders require an origin execution mode.
	b.ExecutionMode(mainID, spvExecutionModeOriginUpperLeft)

	// Decorations.
	for _, r := range inputRegs {
		b.Decorate(inputVar[r], spvDecorationLocation, uint32(r))
	}
	for _, r := range texcoordRegs {
		b.Decorate(texcoordVar[r], spvDecorationLocation, uint32(texcoordLocationBase+r))
	}
	for _, r := range samplerRegs {
		// Combined image+sampler per texture stage: set 1, binding = stage.
		b.Decorate(samplerVar[r], spvDecorationDescriptor, 1)
		b.Decorate(samplerVar[r], spvDecorationBinding, uint32(r))
	}
	if useColorOut {
		b.Decorate(colorOutVar, spvDecorationLocation, 0)
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
	vec2Type := b.TypeVector(floatType, 2)
	vec3Type := b.TypeVector(floatType, 3)
	vec4Type := b.TypeVector(floatType, 4)

	// Image / sampled-image types (shared by every sampler stage).
	var imageType, sampledImageType, sampledImagePtr uint32
	if len(samplerRegs) > 0 {
		imageType = b.TypeImage(floatType, spvDim2D, 0, 0, 0, 1, spvImageFormatUnknown)
		sampledImageType = b.TypeSampledImage(imageType)
		sampledImagePtr = b.TypePointer(spvStorageClassUniformConstant, sampledImageType)
	}

	// Constants (all in the global section, never inside the function body).
	intConst := map[int]uint32{}
	mkInt := func(k int) uint32 {
		if id, ok := intConst[k]; ok {
			return id
		}
		id := b.Constant(intType, uint32(k))
		intConst[k] = id
		return id
	}
	mkInt(0) // struct-member index for the uniform block
	for _, k := range constRegs {
		mkInt(k)
	}
	var lengthConst uint32
	if hasConst {
		lengthConst = b.Constant(intType, uint32(arraySize))
	}

	if hasConst {
		b.Op(smOpTypeArray, uboArrayType, vec4Type, lengthConst)
		b.Op(spvOpTypeStruct, uboStructType, uboArrayType)
	}

	inVec4Ptr := b.TypePointer(spvStorageClassInput, vec4Type)
	outVec4Ptr := b.TypePointer(spvStorageClassOutput, vec4Type)
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
	for _, r := range texcoordRegs {
		b.Op(spvOpVariable, inVec4Ptr, texcoordVar[r], spvStorageClassInput)
	}
	for _, r := range samplerRegs {
		b.Op(spvOpVariable, sampledImagePtr, samplerVar[r], spvStorageClassUniformConstant)
	}
	if useColorOut {
		b.Op(spvOpVariable, outVec4Ptr, colorOutVar, spvStorageClassOutput)
	}
	if hasConst {
		b.Op(spvOpVariable, uboStructPtr, uboVar, smStorageClassUniform)
	}

	fnType := b.TypeFunction(voidType)

	// Function.
	b.Function(voidType, mainID, fnType)
	b.Label()

	// Function-storage variables must be the first instructions of the entry
	// block: the r# temps and the per-t# holders.
	tempVar := map[int]uint32{}
	for _, r := range tempRegs {
		tempVar[r] = b.Variable(tempPtr, spvStorageClassFunction)
	}
	texHolder := map[int]uint32{}
	for _, r := range texcoordRegs {
		texHolder[r] = b.Variable(tempPtr, spvStorageClassFunction)
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
	toVec2 := func(v uint32) uint32 {
		x := b.CompositeExtract(floatType, v, 0)
		y := b.CompositeExtract(floatType, v, 1)
		return b.CompositeConstruct(vec2Type, x, y)
	}

	// Seed each t# holder with its iterated texture coordinate.
	for _, r := range texcoordRegs {
		coord := b.Load(vec4Type, texcoordVar[r])
		b.Store(texHolder[r], coord)
	}

	loadConst := func(idx int) uint32 {
		ptr := b.AccessChain(uboVec4Ptr, uboVar, intConst[0], mkIntCached(intConst, idx))
		return b.Load(vec4Type, ptr)
	}
	loadReg := func(regType, regNum int) (uint32, error) {
		switch {
		case regType == regTemp:
			return b.Load(vec4Type, tempVar[regNum]), nil
		case regType == regInput:
			return b.Load(vec4Type, inputVar[regNum]), nil
		case regType == regConst:
			return loadConst(regNum), nil
		case isTexcoordReg(regType):
			return b.Load(vec4Type, texHolder[regNum]), nil
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
	dstPointer := func(d *DstParam) (uint32, error) {
		switch {
		case d.RegType == regTemp:
			return tempVar[d.RegNum], nil
		case d.RegType == regColorOut:
			return colorOutVar, nil
		case isTexcoordReg(d.RegType):
			return texHolder[d.RegNum], nil
		}
		return 0, fmt.Errorf("d3d9: cannot store register type %d", d.RegType)
	}
	storeMasked := func(d *DstParam, result uint32) error {
		ptr, err := dstPointer(d)
		if err != nil {
			return err
		}
		mask := d.WriteMask
		if mask == 0xF || mask == 0 {
			// A zero write mask in ps_1_x means "all channels" for the common
			// implicit forms; treat it as full write.
			b.Store(ptr, result)
			return nil
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
		return nil
	}

	// Body.
	for _, in := range sh.Instrs {
		switch in.Op {
		case sioNOP, sioDCL:
			continue
		case sioTEX:
			stage := in.Dst.RegNum
			img := b.Load(sampledImageType, samplerVar[stage])
			coord4 := b.Load(vec4Type, texHolder[stage])
			coord := toVec2(coord4)
			texel := b.ImageSampleImplicitLod(vec4Type, img, coord)
			b.Store(texHolder[stage], texel)
		case sioMOV:
			s0, err := readSrc(in.Src[0])
			if err != nil {
				return nil, err
			}
			if err := storeMasked(in.Dst, s0); err != nil {
				return nil, err
			}
		case sioADD, sioSUB, sioMUL:
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
			}
			if err := storeMasked(in.Dst, r); err != nil {
				return nil, err
			}
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
			if err := storeMasked(in.Dst, b.FAdd(vec4Type, mul, s2)); err != nil {
				return nil, err
			}
		case sioLRP:
			// lrp d, s0, s1, s2  ->  d = s2 + s0 * (s1 - s2)
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
			diff := b.FSub(vec4Type, s1, s2)
			scaled := b.FMul(vec4Type, s0, diff)
			if err := storeMasked(in.Dst, b.FAdd(vec4Type, s2, scaled)); err != nil {
				return nil, err
			}
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
			if err := storeMasked(in.Dst, broadcast(d)); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("d3d9: unsupported opcode %d", in.Op)
		}
	}

	b.Return()
	b.FunctionEnd()
	return b.Finalize(), nil
}

// psOpSrcCount is the number of source operands the pixel emitter reads for op.
func psOpSrcCount(op int) int {
	switch op {
	case sioMOV:
		return 1
	case sioADD, sioSUB, sioMUL, sioDP3:
		return 2
	case sioMAD, sioLRP:
		return 3
	}
	return 0
}
