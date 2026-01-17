package d3d9

type TextureStageConfig struct {
	ColorOp   uint32
	ColorArg1 uint32
	ColorArg2 uint32
	AlphaOp   uint32
	AlphaArg1 uint32
	AlphaArg2 uint32
}

func GenerateFFPVertexShader(numTexCoords int, lighting bool, numLights int) []byte {
	if numTexCoords < 0 {
		numTexCoords = 0
	}
	if numTexCoords > 4 {
		numTexCoords = 4
	}
	if numLights < 0 {
		numLights = 0
	}
	if numLights > 4 {
		numLights = 4
	}

	b := NewBuilder()
	b.Capability(spvCapabilityShader)
	b.ExtInstImport("GLSL.std.450")
	b.MemoryModel(spvAddressingModelLogical, spvMemoryModelGLSL450)

	voidType := b.TypeVoid()
	boolType := b.TypeBool()
	floatType := b.TypeFloat(32)
	intType := b.TypeInt(32, 1)
	vec2Type := b.TypeVector(floatType, 2)
	vec3Type := b.TypeVector(floatType, 3)
	vec4Type := b.TypeVector(floatType, 4)
	mat4Type := b.TypeMatrix(vec4Type, 4)

	perVertexType := b.TypeStruct(vec4Type)
	b.MemberDecorate(perVertexType, 0, spvDecorationBuiltIn, spvBuiltInPosition)
	b.Decorate(perVertexType, spvDecorationBlock)

	pushConstantsType := b.TypeStruct(
		mat4Type, mat4Type,
		vec4Type, vec4Type, vec4Type, vec4Type,
		vec4Type, vec4Type, vec4Type, vec4Type,
		vec4Type,
	)
	b.Decorate(pushConstantsType, spvDecorationBlock)
	b.MemberDecorate(pushConstantsType, 0, spvDecorationOffset, 0)
	b.MemberDecorate(pushConstantsType, 0, spvDecorationColMajor)
	b.MemberDecorate(pushConstantsType, 0, spvDecorationMatrixStep, 16)
	b.MemberDecorate(pushConstantsType, 1, spvDecorationOffset, 64)
	b.MemberDecorate(pushConstantsType, 1, spvDecorationColMajor)
	b.MemberDecorate(pushConstantsType, 1, spvDecorationMatrixStep, 16)
	offset := uint32(128)
	for member := uint32(2); member <= 10; member++ {
		b.MemberDecorate(pushConstantsType, member, spvDecorationOffset, offset)
		offset += 16
	}

	inVec3Ptr := b.TypePointer(spvStorageClassInput, vec3Type)
	inVec4Ptr := b.TypePointer(spvStorageClassInput, vec4Type)
	inVec2Ptr := b.TypePointer(spvStorageClassInput, vec2Type)
	outVec4Ptr := b.TypePointer(spvStorageClassOutput, vec4Type)
	outVec2Ptr := b.TypePointer(spvStorageClassOutput, vec2Type)
	outPerVertexPtr := b.TypePointer(spvStorageClassOutput, perVertexType)
	pushPtr := b.TypePointer(spvStorageClassPushConstant, pushConstantsType)
	pushMat4Ptr := b.TypePointer(spvStorageClassPushConstant, mat4Type)
	pushVec4Ptr := b.TypePointer(spvStorageClassPushConstant, vec4Type)

	fnType := b.TypeFunction(voidType)
	mainID := b.AllocID()

	inPosition := b.Variable(inVec3Ptr, spvStorageClassInput)
	b.Decorate(inPosition, spvDecorationLocation, 0)
	inNormal := b.Variable(inVec3Ptr, spvStorageClassInput)
	b.Decorate(inNormal, spvDecorationLocation, 1)
	inColor := b.Variable(inVec4Ptr, spvStorageClassInput)
	b.Decorate(inColor, spvDecorationLocation, 2)

	texInputs := make([]uint32, 4)
	for i := range texInputs {
		texInputs[i] = b.Variable(inVec2Ptr, spvStorageClassInput)
		b.Decorate(texInputs[i], spvDecorationLocation, uint32(3+i))
	}

	outPosition := b.Variable(outPerVertexPtr, spvStorageClassOutput)
	outColor := b.Variable(outVec4Ptr, spvStorageClassOutput)
	b.Decorate(outColor, spvDecorationLocation, 0)
	texOutputs := make([]uint32, 4)
	for i := range texOutputs {
		texOutputs[i] = b.Variable(outVec2Ptr, spvStorageClassOutput)
		b.Decorate(texOutputs[i], spvDecorationLocation, uint32(1+i))
	}

	pushConstants := b.Variable(pushPtr, spvStorageClassPushConstant)

	interfaces := []uint32{inPosition, inColor, outPosition, outColor}
	if lighting {
		interfaces = append(interfaces, inNormal)
	}
	interfaces = append(interfaces, texInputs...)
	interfaces = append(interfaces, texOutputs...)
	b.EntryPoint(spvExecutionModelVertex, mainID, "main", interfaces...)

	b.Function(voidType, mainID, fnType)
	b.Label()

	zero := b.Float32Constant(floatType, 0)
	one := b.Float32Constant(floatType, 1)
	zeroVec2 := b.ConstantComposite(vec2Type, zero, zero)
	zeroVec3 := b.ConstantComposite(vec3Type, zero, zero, zero)
	int0 := b.Constant(intType, 0)
	int1 := b.Constant(intType, 1)

	position := b.Load(vec3Type, inPosition)
	px := b.CompositeExtract(floatType, position, 0)
	py := b.CompositeExtract(floatType, position, 1)
	pz := b.CompositeExtract(floatType, position, 2)
	position4 := b.CompositeConstruct(vec4Type, px, py, pz, one)

	wvpPtr := b.AccessChain(pushMat4Ptr, pushConstants, int0)
	wvp := b.Load(mat4Type, wvpPtr)
	clipPosition := b.MatrixTimesVector(vec4Type, wvp, position4)
	glPosPtr := b.AccessChain(outVec4Ptr, outPosition, int0)
	b.Store(glPosPtr, clipPosition)

	vertexColor := b.Load(vec4Type, inColor)
	finalColor := vertexColor
	if lighting && numLights > 0 {
		worldPtr := b.AccessChain(pushMat4Ptr, pushConstants, int1)
		world := b.Load(mat4Type, worldPtr)
		normal := b.Load(vec3Type, inNormal)
		nx := b.CompositeExtract(floatType, normal, 0)
		ny := b.CompositeExtract(floatType, normal, 1)
		nz := b.CompositeExtract(floatType, normal, 2)
		normal4 := b.CompositeConstruct(vec4Type, nx, ny, nz, zero)
		worldNormal4 := b.MatrixTimesVector(vec4Type, world, normal4)
		wnx := b.CompositeExtract(floatType, worldNormal4, 0)
		wny := b.CompositeExtract(floatType, worldNormal4, 1)
		wnz := b.CompositeExtract(floatType, worldNormal4, 2)
		worldNormal := b.CompositeConstruct(vec3Type, wnx, wny, wnz)
		normalDir := b.Normalize(vec3Type, worldNormal)

		ambientPtr := b.AccessChain(pushVec4Ptr, pushConstants, b.Constant(intType, 10))
		lightAccum := b.Load(vec4Type, ambientPtr)

		for i := 0; i < numLights; i++ {
			dirPtr := b.AccessChain(pushVec4Ptr, pushConstants, b.Constant(intType, uint32(2+i)))
			lightDir4 := b.Load(vec4Type, dirPtr)
			ldx := b.CompositeExtract(floatType, lightDir4, 0)
			ldy := b.CompositeExtract(floatType, lightDir4, 1)
			ldz := b.CompositeExtract(floatType, lightDir4, 2)
			lightDir := b.CompositeConstruct(vec3Type, ldx, ldy, ldz)
			negLightDir := b.FSub(vec3Type, zeroVec3, lightDir)
			ndotl := b.Dot(floatType, normalDir, negLightDir)
			isPositive := b.FOrdGreaterThan(boolType, ndotl, zero)
			clamped := b.OpSelect(floatType, isPositive, ndotl, zero)

			colorPtr := b.AccessChain(pushVec4Ptr, pushConstants, b.Constant(intType, uint32(6+i)))
			lightColor := b.Load(vec4Type, colorPtr)
			diffuse := b.VectorTimesScalar(vec4Type, lightColor, clamped)
			lightAccum = b.FAdd(vec4Type, lightAccum, diffuse)
		}

		finalColor = b.FMul(vec4Type, vertexColor, lightAccum)
	}
	b.Store(outColor, finalColor)

	for i := 0; i < 4; i++ {
		if i < numTexCoords {
			texCoord := b.Load(vec2Type, texInputs[i])
			b.Store(texOutputs[i], texCoord)
			continue
		}
		b.Store(texOutputs[i], zeroVec2)
	}

	b.Return()
	b.FunctionEnd()
	return b.Finalize()
}

func GenerateFFPFragmentShader(numTextures int, stages []TextureStageConfig) []byte {
	if numTextures < 0 {
		numTextures = 0
	}
	if numTextures > 8 {
		numTextures = 8
	}

	b := NewBuilder()
	b.Capability(spvCapabilityShader)
	b.MemoryModel(spvAddressingModelLogical, spvMemoryModelGLSL450)

	voidType := b.TypeVoid()
	floatType := b.TypeFloat(32)
	vec2Type := b.TypeVector(floatType, 2)
	vec4Type := b.TypeVector(floatType, 4)
	imageType := b.TypeImage(floatType, spvDim2D, 0, 0, 0, 1, spvImageFormatUnknown)
	sampledImageType := b.TypeSampledImage(imageType)

	inVec4Ptr := b.TypePointer(spvStorageClassInput, vec4Type)
	inVec2Ptr := b.TypePointer(spvStorageClassInput, vec2Type)
	outVec4Ptr := b.TypePointer(spvStorageClassOutput, vec4Type)
	uniformSampledPtr := b.TypePointer(spvStorageClassUniformConstant, sampledImageType)

	fnType := b.TypeFunction(voidType)
	mainID := b.AllocID()

	diffuse := b.Variable(inVec4Ptr, spvStorageClassInput)
	b.Decorate(diffuse, spvDecorationLocation, 0)
	texCoords := make([]uint32, 4)
	for i := range texCoords {
		texCoords[i] = b.Variable(inVec2Ptr, spvStorageClassInput)
		b.Decorate(texCoords[i], spvDecorationLocation, uint32(1+i))
	}
	fragmentColor := b.Variable(outVec4Ptr, spvStorageClassOutput)
	b.Decorate(fragmentColor, spvDecorationLocation, 0)

	samplers := make([]uint32, numTextures)
	for i := range samplers {
		samplers[i] = b.Variable(uniformSampledPtr, spvStorageClassUniformConstant)
		b.Decorate(samplers[i], spvDecorationDescriptor, 0)
		b.Decorate(samplers[i], spvDecorationBinding, uint32(i))
	}

	interfaces := []uint32{diffuse, fragmentColor}
	interfaces = append(interfaces, texCoords...)
	b.EntryPoint(spvExecutionModelFragment, mainID, "main", interfaces...)
	b.ExecutionMode(mainID, spvExecutionModeOriginUpperLeft)

	b.Function(voidType, mainID, fnType)
	b.Label()

	zero := b.Float32Constant(floatType, 0)
	current := b.Load(vec4Type, diffuse)

	for stageIndex, stage := range stages {
		if stage.ColorOp == D3DTOP_DISABLE && stage.AlphaOp == D3DTOP_DISABLE {
			break
		}

		var sampledColor uint32
		if usesTexture(stage) && stageIndex < numTextures {
			sampledImage := b.Load(sampledImageType, samplers[stageIndex])
			coord := b.Load(vec2Type, texCoords[minInt(stageIndex, len(texCoords)-1)])
			sampledColor = b.ImageSampleImplicitLod(vec4Type, sampledImage, coord)
		}

		colorResult := current
		if stage.ColorOp != D3DTOP_DISABLE {
			arg1 := resolveColorArg(b, stage.ColorArg1, current, sampledColor, diffuse, vec4Type)
			arg2 := resolveColorArg(b, stage.ColorArg2, current, sampledColor, diffuse, vec4Type)
			colorResult = applyColorOp(b, stage.ColorOp, vec4Type, arg1, arg2)
		}

		alphaValue := b.CompositeExtract(floatType, current, 3)
		if stage.AlphaOp != D3DTOP_DISABLE {
			alpha1 := b.CompositeExtract(floatType, resolveColorArg(b, stage.AlphaArg1, current, sampledColor, diffuse, vec4Type), 3)
			alpha2 := b.CompositeExtract(floatType, resolveColorArg(b, stage.AlphaArg2, current, sampledColor, diffuse, vec4Type), 3)
			alphaValue = applyAlphaOp(b, stage.AlphaOp, floatType, alpha1, alpha2, zero)
		}

		r := b.CompositeExtract(floatType, colorResult, 0)
		g := b.CompositeExtract(floatType, colorResult, 1)
		bl := b.CompositeExtract(floatType, colorResult, 2)
		current = b.CompositeConstruct(vec4Type, r, g, bl, alphaValue)
	}

	b.Store(fragmentColor, current)
	b.Return()
	b.FunctionEnd()
	return b.Finalize()
}

func usesTexture(stage TextureStageConfig) bool {
	return baseTextureArg(stage.ColorArg1) == D3DTA_TEXTURE ||
		baseTextureArg(stage.ColorArg2) == D3DTA_TEXTURE ||
		baseTextureArg(stage.AlphaArg1) == D3DTA_TEXTURE ||
		baseTextureArg(stage.AlphaArg2) == D3DTA_TEXTURE
}

func baseTextureArg(arg uint32) uint32 {
	return arg & D3DTA_SELECTMASK
}

func resolveColorArg(b *Builder, arg, current, sampledColor, diffuseVar, vec4Type uint32) uint32 {
	switch baseTextureArg(arg) {
	case D3DTA_TEXTURE:
		if sampledColor != 0 {
			return sampledColor
		}
	case D3DTA_CURRENT:
		return current
	case D3DTA_DIFFUSE:
		return b.Load(vec4Type, diffuseVar)
	}
	return current
}

func applyColorOp(b *Builder, op, vec4Type, arg1, arg2 uint32) uint32 {
	switch op {
	case D3DTOP_SELECTARG1:
		return arg1
	case D3DTOP_SELECTARG2:
		return arg2
	case D3DTOP_MODULATE:
		return b.FMul(vec4Type, arg1, arg2)
	case D3DTOP_ADD:
		return b.FAdd(vec4Type, arg1, arg2)
	case D3DTOP_SUBTRACT:
		return b.FSub(vec4Type, arg1, arg2)
	default:
		return arg1
	}
}

func applyAlphaOp(b *Builder, op, floatType, arg1, arg2, zero uint32) uint32 {
	switch op {
	case D3DTOP_SELECTARG1:
		return arg1
	case D3DTOP_SELECTARG2:
		return arg2
	case D3DTOP_MODULATE:
		return b.FMul(floatType, arg1, arg2)
	case D3DTOP_ADD:
		return b.FAdd(floatType, arg1, arg2)
	case D3DTOP_SUBTRACT:
		return b.FSub(floatType, arg1, arg2)
	case D3DTOP_DISABLE:
		return zero
	default:
		return arg1
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
