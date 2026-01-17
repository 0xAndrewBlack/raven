package spirv

import (
	"encoding/binary"
	"math"
)

const (
	MagicNumber = 0x07230203
	Version10   = 0x00010000
)

const (
	OpExtInstImport       = 11
	OpExtInst             = 12
	OpMemoryModel         = 14
	OpEntryPoint          = 15
	OpExecutionMode       = 16
	OpCapability          = 17
	OpTypeVoid            = 19
	OpTypeBool            = 20
	OpTypeInt             = 21
	OpTypeFloat           = 22
	OpTypeVector          = 23
	OpTypeMatrix          = 24
	OpTypeImage           = 25
	OpTypeSampledImage    = 27
	OpTypeStruct          = 30
	OpTypePointer         = 32
	OpTypeFunction        = 33
	OpConstantTrue        = 41
	OpConstantFalse       = 42
	OpConstant            = 43
	OpConstantComposite   = 44
	OpFunction            = 54
	OpFunctionEnd         = 56
	OpFunctionCall        = 57
	OpVariable            = 59
	OpLoad                = 61
	OpStore               = 62
	OpAccessChain         = 65
	OpDecorate            = 71
	OpMemberDecorate      = 72
	OpVectorShuffle       = 79
	OpCompositeConstruct  = 80
	OpCompositeExtract    = 81
	OpCompositeInsert     = 82
	OpCopyObject          = 83
	OpImageSampleImplicit = 87
	OpImageSampleExplicit = 88
	OpFNegate             = 127
	OpFAdd                = 129
	OpFSub                = 131
	OpFMul                = 133
	OpFDiv                = 136
	OpVectorTimesScalar   = 142
	OpMatrixTimesVector   = 145
	OpDot                 = 148
	OpSelect              = 169
	OpFOrdNotEqual        = 182
	OpFOrdGreaterThan     = 186
	OpLoopMerge           = 246
	OpSelectionMerge      = 247
	OpLabel               = 248
	OpBranch              = 249
	OpBranchConditional   = 250
	OpReturn              = 253
)

const (
	CapabilityShader = 1
)

const (
	AddressingModelLogical = 0
	MemoryModelGLSL450     = 1
)

const (
	ExecutionModelVertex   = 0
	ExecutionModelFragment = 4
)

const (
	ExecutionModeOriginUpperLeft = 7
)

const (
	StorageClassUniformConstant = 0
	StorageClassInput           = 1
	StorageClassUniform         = 2
	StorageClassOutput          = 3
	StorageClassFunction        = 7
	StorageClassPushConstant    = 9
)

const (
	DecorationBlock         = 2
	DecorationColMajor      = 5
	DecorationMatrixStride  = 7
	DecorationBuiltIn       = 11
	DecorationLocation      = 30
	DecorationBinding       = 33
	DecorationDescriptorSet = 34
	DecorationOffset        = 35
)

const (
	BuiltInPosition    = 0
	BuiltInFragCoord   = 15
	BuiltInVertexIndex = 42
)

const (
	FunctionControlNone  = 0
	SelectionControlNone = 0
	LoopControlNone      = 0
)

const (
	Dim2D = 1
)

const (
	ImageFormatUnknown = 0
)

const (
	ImageOperandsLodMask = 0x2
)

const (
	GlslStd450Normalize = 69
)

type Builder struct {
	words    []uint32
	nextID   uint32
	glsl450  uint32
	boolType uint32
}

func NewBuilder() *Builder {
	return &Builder{nextID: 1}
}

func (b *Builder) AllocID() uint32 {
	id := b.nextID
	b.nextID++
	return id
}

func (b *Builder) Op(opcode uint16, operands ...uint32) {
	wordCount := uint32(len(operands) + 1)
	b.words = append(b.words, (wordCount<<16)|uint32(opcode))
	b.words = append(b.words, operands...)
}

func (b *Builder) Capability(capability uint32) {
	b.Op(OpCapability, capability)
}

func (b *Builder) ExtInstImport(name string) uint32 {
	if name == "GLSL.std.450" && b.glsl450 != 0 {
		return b.glsl450
	}
	id := b.AllocID()
	operands := []uint32{id}
	operands = append(operands, stringWords(name)...)
	b.Op(OpExtInstImport, operands...)
	if name == "GLSL.std.450" {
		b.glsl450 = id
	}
	return id
}

func (b *Builder) MemoryModel(addressingModel, memoryModel uint32) {
	b.Op(OpMemoryModel, addressingModel, memoryModel)
}

func (b *Builder) EntryPoint(executionModel, fn uint32, name string, interfaces ...uint32) {
	operands := []uint32{executionModel, fn}
	operands = append(operands, stringWords(name)...)
	operands = append(operands, interfaces...)
	b.Op(OpEntryPoint, operands...)
}

func (b *Builder) ExecutionMode(fn, mode uint32, literals ...uint32) {
	operands := []uint32{fn, mode}
	operands = append(operands, literals...)
	b.Op(OpExecutionMode, operands...)
}

func (b *Builder) Decorate(target, decoration uint32, extras ...uint32) {
	operands := []uint32{target, decoration}
	operands = append(operands, extras...)
	b.Op(OpDecorate, operands...)
}

func (b *Builder) MemberDecorate(target, member, decoration uint32, extras ...uint32) {
	operands := []uint32{target, member, decoration}
	operands = append(operands, extras...)
	b.Op(OpMemberDecorate, operands...)
}

func (b *Builder) TypeVoid() uint32 {
	id := b.AllocID()
	b.Op(OpTypeVoid, id)
	return id
}

func (b *Builder) TypeBool() uint32 {
	if b.boolType != 0 {
		return b.boolType
	}
	b.boolType = b.AllocID()
	b.Op(OpTypeBool, b.boolType)
	return b.boolType
}

func (b *Builder) TypeFloat(width uint32) uint32 {
	id := b.AllocID()
	b.Op(OpTypeFloat, id, width)
	return id
}

func (b *Builder) TypeInt(width, signedness uint32) uint32 {
	id := b.AllocID()
	b.Op(OpTypeInt, id, width, signedness)
	return id
}

func (b *Builder) TypeVector(componentType, count uint32) uint32 {
	id := b.AllocID()
	b.Op(OpTypeVector, id, componentType, count)
	return id
}

func (b *Builder) TypeMatrix(columnType, count uint32) uint32 {
	id := b.AllocID()
	b.Op(OpTypeMatrix, id, columnType, count)
	return id
}

func (b *Builder) TypePointer(storageClass, typ uint32) uint32 {
	id := b.AllocID()
	b.Op(OpTypePointer, id, storageClass, typ)
	return id
}

func (b *Builder) TypeFunction(returnType uint32, parameterTypes ...uint32) uint32 {
	id := b.AllocID()
	operands := []uint32{id, returnType}
	operands = append(operands, parameterTypes...)
	b.Op(OpTypeFunction, operands...)
	return id
}

func (b *Builder) TypeStruct(memberTypes ...uint32) uint32 {
	id := b.AllocID()
	operands := []uint32{id}
	operands = append(operands, memberTypes...)
	b.Op(OpTypeStruct, operands...)
	return id
}

func (b *Builder) TypeImage(sampledType, dim, depth, arrayed, multisampled, sampled, format uint32) uint32 {
	id := b.AllocID()
	b.Op(OpTypeImage, id, sampledType, dim, depth, arrayed, multisampled, sampled, format)
	return id
}

func (b *Builder) TypeSampledImage(imageType uint32) uint32 {
	id := b.AllocID()
	b.Op(OpTypeSampledImage, id, imageType)
	return id
}

func (b *Builder) Variable(pointerType, storageClass uint32, initializer ...uint32) uint32 {
	id := b.AllocID()
	operands := []uint32{pointerType, id, storageClass}
	operands = append(operands, initializer...)
	b.Op(OpVariable, operands...)
	return id
}

func (b *Builder) Constant(typ, literal uint32) uint32 {
	id := b.AllocID()
	b.Op(OpConstant, typ, id, literal)
	return id
}

func (b *Builder) ConstantTrue(typ uint32) uint32 {
	id := b.AllocID()
	b.Op(OpConstantTrue, typ, id)
	return id
}

func (b *Builder) ConstantFalse(typ uint32) uint32 {
	id := b.AllocID()
	b.Op(OpConstantFalse, typ, id)
	return id
}

func (b *Builder) ConstantComposite(typ uint32, constituents ...uint32) uint32 {
	id := b.AllocID()
	operands := []uint32{typ, id}
	operands = append(operands, constituents...)
	b.Op(OpConstantComposite, operands...)
	return id
}

func (b *Builder) Load(resultType, pointer uint32) uint32 {
	id := b.AllocID()
	b.Op(OpLoad, resultType, id, pointer)
	return id
}

func (b *Builder) Store(pointer, object uint32) {
	b.Op(OpStore, pointer, object)
}

func (b *Builder) MatrixTimesVector(resultType, matrix, vector uint32) uint32 {
	id := b.AllocID()
	b.Op(OpMatrixTimesVector, resultType, id, matrix, vector)
	return id
}

func (b *Builder) VectorTimesScalar(resultType, vector, scalar uint32) uint32 {
	id := b.AllocID()
	b.Op(OpVectorTimesScalar, resultType, id, vector, scalar)
	return id
}

func (b *Builder) FMul(resultType, x, y uint32) uint32 {
	id := b.AllocID()
	b.Op(OpFMul, resultType, id, x, y)
	return id
}

func (b *Builder) FAdd(resultType, x, y uint32) uint32 {
	id := b.AllocID()
	b.Op(OpFAdd, resultType, id, x, y)
	return id
}

func (b *Builder) FSub(resultType, x, y uint32) uint32 {
	id := b.AllocID()
	b.Op(OpFSub, resultType, id, x, y)
	return id
}

func (b *Builder) FDiv(resultType, x, y uint32) uint32 {
	id := b.AllocID()
	b.Op(OpFDiv, resultType, id, x, y)
	return id
}

func (b *Builder) FNegate(resultType, value uint32) uint32 {
	id := b.AllocID()
	b.Op(OpFNegate, resultType, id, value)
	return id
}

func (b *Builder) Dot(resultType, x, y uint32) uint32 {
	id := b.AllocID()
	b.Op(OpDot, resultType, id, x, y)
	return id
}

func (b *Builder) Normalize(resultType, value uint32) uint32 {
	if b.glsl450 == 0 {
		b.ExtInstImport("GLSL.std.450")
	}
	id := b.AllocID()
	b.Op(OpExtInst, resultType, id, b.glsl450, GlslStd450Normalize, value)
	return id
}

func (b *Builder) OpSelect(resultType, cond, trueValue, falseValue uint32) uint32 {
	id := b.AllocID()
	b.Op(OpSelect, resultType, id, cond, trueValue, falseValue)
	return id
}

func (b *Builder) CompositeConstruct(resultType uint32, constituents ...uint32) uint32 {
	id := b.AllocID()
	operands := []uint32{resultType, id}
	operands = append(operands, constituents...)
	b.Op(OpCompositeConstruct, operands...)
	return id
}

func (b *Builder) CompositeExtract(resultType, composite uint32, indexes ...uint32) uint32 {
	id := b.AllocID()
	operands := []uint32{resultType, id, composite}
	operands = append(operands, indexes...)
	b.Op(OpCompositeExtract, operands...)
	return id
}

func (b *Builder) CompositeInsert(resultType, object, composite uint32, indexes ...uint32) uint32 {
	id := b.AllocID()
	operands := []uint32{resultType, id, object, composite}
	operands = append(operands, indexes...)
	b.Op(OpCompositeInsert, operands...)
	return id
}

func (b *Builder) VectorShuffle(resultType, vector1, vector2 uint32, components ...uint32) uint32 {
	id := b.AllocID()
	operands := []uint32{resultType, id, vector1, vector2}
	operands = append(operands, components...)
	b.Op(OpVectorShuffle, operands...)
	return id
}

func (b *Builder) CopyObject(resultType, object uint32) uint32 {
	id := b.AllocID()
	b.Op(OpCopyObject, resultType, id, object)
	return id
}

func (b *Builder) AccessChain(resultType, base uint32, indexes ...uint32) uint32 {
	id := b.AllocID()
	operands := []uint32{resultType, id, base}
	operands = append(operands, indexes...)
	b.Op(OpAccessChain, operands...)
	return id
}

func (b *Builder) FunctionCall(resultType, fn uint32, args ...uint32) uint32 {
	id := b.AllocID()
	operands := []uint32{resultType, id, fn}
	operands = append(operands, args...)
	b.Op(OpFunctionCall, operands...)
	return id
}

func (b *Builder) FOrdGreaterThan(resultType, x, y uint32) uint32 {
	id := b.AllocID()
	b.Op(OpFOrdGreaterThan, resultType, id, x, y)
	return id
}

func (b *Builder) FOrdNotEqual(resultType, x, y uint32) uint32 {
	id := b.AllocID()
	b.Op(OpFOrdNotEqual, resultType, id, x, y)
	return id
}

func (b *Builder) ImageSampleImplicitLod(resultType, sampledImage, coordinate uint32) uint32 {
	id := b.AllocID()
	b.Op(OpImageSampleImplicit, resultType, id, sampledImage, coordinate)
	return id
}

func (b *Builder) ImageSampleExplicitLod(resultType, sampledImage, coordinate, lod uint32) uint32 {
	id := b.AllocID()
	b.Op(OpImageSampleExplicit, resultType, id, sampledImage, coordinate, ImageOperandsLodMask, lod)
	return id
}

func (b *Builder) Function(resultType, fn, fnType uint32) {
	b.Op(OpFunction, resultType, fn, FunctionControlNone, fnType)
}

func (b *Builder) Label() uint32 {
	id := b.AllocID()
	b.Op(OpLabel, id)
	return id
}

func (b *Builder) LabelID(id uint32) {
	b.Op(OpLabel, id)
}

func (b *Builder) SelectionMerge(merge, control uint32) {
	b.Op(OpSelectionMerge, merge, control)
}

func (b *Builder) LoopMerge(merge, cont, control uint32) {
	b.Op(OpLoopMerge, merge, cont, control)
}

func (b *Builder) Branch(target uint32) {
	b.Op(OpBranch, target)
}

func (b *Builder) BranchConditional(cond, trueLabel, falseLabel uint32) {
	b.Op(OpBranchConditional, cond, trueLabel, falseLabel)
}

func (b *Builder) Return() {
	b.Op(OpReturn)
}

func (b *Builder) FunctionEnd() {
	b.Op(OpFunctionEnd)
}

func (b *Builder) Finalize() []byte {
	words := make([]uint32, 0, len(b.words)+5)
	words = append(words, MagicNumber, Version10, 0, b.nextID, 0)
	words = append(words, b.words...)

	data := make([]byte, len(words)*4)
	for i, word := range words {
		binary.LittleEndian.PutUint32(data[i*4:], word)
	}
	return data
}

func (b *Builder) Float32Constant(typ uint32, value float32) uint32 {
	return b.Constant(typ, math.Float32bits(value))
}

func stringWords(s string) []uint32 {
	data := append([]byte(s), 0)
	words := make([]uint32, (len(data)+3)/4)
	for i, v := range data {
		words[i/4] |= uint32(v) << (8 * (i % 4))
	}
	return words
}
