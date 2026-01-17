package dxbc

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/mirkobrombin/Raven/pkg/spirv"
)

type compiler struct {
	shader *Shader
	b      *spirv.Builder

	voidType         uint32
	boolType         uint32
	floatType        uint32
	intType          uint32
	vec2Type         uint32
	vec3Type         uint32
	vec4Type         uint32
	imageType        uint32
	sampledImageType uint32

	ptrInputVec4           uint32
	ptrInputInt            uint32
	ptrOutputVec4          uint32
	ptrFunctionVec4        uint32
	ptrUniformVec4         uint32
	ptrUniformStruct       map[uint32]uint32
	ptrUniformSampledImage uint32

	mainID uint32
	fnType uint32

	entryInterfaces []uint32
	inputs          map[uint32]uint32
	outputs         map[uint32]uint32
	temps           map[uint32]uint32
	cbuffers        map[uint32]cbBinding
	resources       map[uint32]resourceBinding

	intConstants      map[uint32]uint32
	floatConstants    map[uint32]uint32
	vecConstants      map[string]uint32
	zeroVec4          uint32
	zeroFloat         uint32
	currentTerminated bool
	ifStack           []ifFrame
	loopStack         []loopFrame
}

type cbBinding struct {
	varID    uint32
	structTy uint32
	members  uint32
	binding  uint32
}

type resourceBinding struct {
	varID   uint32
	binding uint32
}

type ifFrame struct {
	elseLabel  uint32
	mergeLabel uint32
	inElse     bool
}

type loopFrame struct {
	headerLabel   uint32
	continueLabel uint32
	mergeLabel    uint32
}

func Compile(shader *Shader) ([]byte, error) {
	if shader == nil {
		return nil, errors.New("dxbc: nil shader")
	}
	c := &compiler{
		shader:           shader,
		b:                spirv.NewBuilder(),
		ptrUniformStruct: map[uint32]uint32{},
		inputs:           map[uint32]uint32{},
		outputs:          map[uint32]uint32{},
		temps:            map[uint32]uint32{},
		cbuffers:         map[uint32]cbBinding{},
		resources:        map[uint32]resourceBinding{},
		intConstants:     map[uint32]uint32{},
		floatConstants:   map[uint32]uint32{},
		vecConstants:     map[string]uint32{},
	}
	return c.compile()
}

func (c *compiler) compile() ([]byte, error) {
	c.b.Capability(spirv.CapabilityShader)
	c.b.MemoryModel(spirv.AddressingModelLogical, spirv.MemoryModelGLSL450)
	c.defineTypes()
	c.declareInterfaces()
	c.declareConstantBuffers()
	c.declareResources()

	c.mainID = c.b.AllocID()
	c.b.EntryPoint(c.executionModel(), c.mainID, "main", c.entryInterfaces...)
	if c.shader.Stage == ProgramTypePixel {
		c.b.ExecutionMode(c.mainID, spirv.ExecutionModeOriginUpperLeft)
	}

	c.fnType = c.b.TypeFunction(c.voidType)
	c.b.Function(c.voidType, c.mainID, c.fnType)
	c.b.Label()
	c.declareTemps()
	for _, inst := range c.shader.Instructions {
		if err := c.emitInstruction(inst); err != nil {
			return nil, err
		}
	}
	if !c.currentTerminated {
		c.b.Return()
	}
	c.b.FunctionEnd()
	return c.b.Finalize(), nil
}

func (c *compiler) defineTypes() {
	c.voidType = c.b.TypeVoid()
	c.boolType = c.b.TypeBool()
	c.floatType = c.b.TypeFloat(32)
	c.intType = c.b.TypeInt(32, 1)
	c.vec2Type = c.b.TypeVector(c.floatType, 2)
	c.vec3Type = c.b.TypeVector(c.floatType, 3)
	c.vec4Type = c.b.TypeVector(c.floatType, 4)
	c.imageType = c.b.TypeImage(c.floatType, spirv.Dim2D, 0, 0, 0, 1, spirv.ImageFormatUnknown)
	c.sampledImageType = c.b.TypeSampledImage(c.imageType)

	c.ptrInputVec4 = c.b.TypePointer(spirv.StorageClassInput, c.vec4Type)
	c.ptrInputInt = c.b.TypePointer(spirv.StorageClassInput, c.intType)
	c.ptrOutputVec4 = c.b.TypePointer(spirv.StorageClassOutput, c.vec4Type)
	c.ptrFunctionVec4 = c.b.TypePointer(spirv.StorageClassFunction, c.vec4Type)
	c.ptrUniformVec4 = c.b.TypePointer(spirv.StorageClassUniform, c.vec4Type)
	c.ptrUniformSampledImage = c.b.TypePointer(spirv.StorageClassUniformConstant, c.sampledImageType)

	c.zeroFloat = c.floatConst(0)
	c.zeroVec4 = c.vectorConst(0, 0, 0, 0)
}

func (c *compiler) executionModel() uint32 {
	if c.shader.Stage == ProgramTypePixel {
		return spirv.ExecutionModelFragment
	}
	return spirv.ExecutionModelVertex
}

func (c *compiler) declareInterfaces() {
	inputSigs := c.shader.Inputs
	if len(inputSigs) == 0 {
		inputSigs = c.fallbackSignatures(D3D10SBOpcodeDclInput)
	}
	for _, sig := range inputSigs {
		varID := c.b.Variable(c.inputPointerFor(sig), spirv.StorageClassInput)
		c.decorateSignature(varID, sig, true)
		c.inputs[sig.Register] = varID
		c.entryInterfaces = append(c.entryInterfaces, varID)
	}

	outputSigs := c.shader.Outputs
	if len(outputSigs) == 0 {
		outputSigs = c.fallbackSignatures(D3D10SBOpcodeDclOutput)
	}
	for _, sig := range outputSigs {
		varID := c.b.Variable(c.ptrOutputVec4, spirv.StorageClassOutput)
		c.decorateSignature(varID, sig, false)
		c.outputs[sig.Register] = varID
		c.entryInterfaces = append(c.entryInterfaces, varID)
	}
}

func (c *compiler) declareConstantBuffers() {
	for slot, cb := range c.constantBuffersBySlot() {
		members := maxUint32(1, uint32((cb.Size+15)/16))
		memberTypes := make([]uint32, members)
		for i := range memberTypes {
			memberTypes[i] = c.vec4Type
		}
		structTy := c.b.TypeStruct(memberTypes...)
		c.b.Decorate(structTy, spirv.DecorationBlock)
		for i := uint32(0); i < members; i++ {
			c.b.MemberDecorate(structTy, i, spirv.DecorationOffset, i*16)
		}
		ptrStruct := c.b.TypePointer(spirv.StorageClassUniform, structTy)
		varID := c.b.Variable(ptrStruct, spirv.StorageClassUniform)
		c.b.Decorate(varID, spirv.DecorationDescriptorSet, 0)
		c.b.Decorate(varID, spirv.DecorationBinding, cb.BindPoint)
		c.cbuffers[slot] = cbBinding{varID: varID, structTy: structTy, members: members, binding: cb.BindPoint}
		c.ptrUniformStruct[slot] = ptrStruct
	}
}

func (c *compiler) declareResources() {
	for slot, res := range c.resourcesBySlot() {
		varID := c.b.Variable(c.ptrUniformSampledImage, spirv.StorageClassUniformConstant)
		c.b.Decorate(varID, spirv.DecorationDescriptorSet, 0)
		c.b.Decorate(varID, spirv.DecorationBinding, res.BindPoint)
		c.resources[slot] = resourceBinding{varID: varID, binding: res.BindPoint}
	}
}

func (c *compiler) declareTemps() {
	count := c.tempCount()
	for i := uint32(0); i < count; i++ {
		varID := c.b.Variable(c.ptrFunctionVec4, spirv.StorageClassFunction)
		c.temps[i] = varID
		c.b.Store(varID, c.zeroVec4)
	}
}

func (c *compiler) emitInstruction(inst Instruction) error {
	switch inst.Opcode {
	case D3D10SBOpcodeDclInput, D3D10SBOpcodeDclOutput, D3D10SBOpcodeDclTemps, D3D10SBOpcodeDclConstantBuffer, D3D10SBOpcodeDclResource, D3D10SBOpcodeDclSampler:
		return nil
	case D3D10SBOpcodeMov:
		value, _, err := c.resolveSource(inst.Operands[1], c.maskWidth(inst.Operands[0]))
		if err != nil {
			return err
		}
		c.assign(inst.Operands[0], value)
	case D3D10SBOpcodeAdd:
		return c.emitBinary(inst, c.b.FAdd)
	case D3D10SBOpcodeMul:
		return c.emitBinary(inst, c.b.FMul)
	case D3D10SBOpcodeDiv:
		return c.emitBinary(inst, c.b.FDiv)
	case D3D10SBOpcodeMad:
		width := c.maskWidth(inst.Operands[0])
		a, aType, err := c.resolveSource(inst.Operands[1], width)
		if err != nil {
			return err
		}
		b, _, err := c.resolveSource(inst.Operands[2], width)
		if err != nil {
			return err
		}
		d, _, err := c.resolveSource(inst.Operands[3], width)
		if err != nil {
			return err
		}
		mul := c.b.FMul(aType, a, b)
		c.assign(inst.Operands[0], c.b.FAdd(aType, mul, d))
	case D3D10SBOpcodeDp3:
		a, _, err := c.resolveSource(inst.Operands[1], 3)
		if err != nil {
			return err
		}
		b, _, err := c.resolveSource(inst.Operands[2], 3)
		if err != nil {
			return err
		}
		c.assign(inst.Operands[0], c.b.Dot(c.floatType, a, b))
	case D3D10SBOpcodeDp4:
		a, _, err := c.resolveSource(inst.Operands[1], 4)
		if err != nil {
			return err
		}
		b, _, err := c.resolveSource(inst.Operands[2], 4)
		if err != nil {
			return err
		}
		c.assign(inst.Operands[0], c.b.Dot(c.floatType, a, b))
	case D3D10SBOpcodeSample:
		return c.emitSample(inst, false)
	case D3D10SBOpcodeSampleL:
		return c.emitSample(inst, true)
	case D3D10SBOpcodeIf:
		return c.emitIf(inst.Operands[0])
	case D3D10SBOpcodeElse:
		return c.emitElse()
	case D3D10SBOpcodeEndIf:
		return c.emitEndIf()
	case D3D10SBOpcodeLoop:
		return c.emitLoop()
	case D3D10SBOpcodeEndLoop:
		return c.emitEndLoop()
	case D3D10SBOpcodeBreak:
		return c.emitBreak()
	case D3D10SBOpcodeBreakC:
		return c.emitBreakC(inst.Operands[0])
	case D3D10SBOpcodeRet:
		c.b.Return()
		c.currentTerminated = true
	default:
		return fmt.Errorf("dxbc: unsupported opcode %d", inst.Opcode)
	}
	return nil
}

func (c *compiler) emitBinary(inst Instruction, op func(uint32, uint32, uint32) uint32) error {
	width := c.maskWidth(inst.Operands[0])
	a, typ, err := c.resolveSource(inst.Operands[1], width)
	if err != nil {
		return err
	}
	b, _, err := c.resolveSource(inst.Operands[2], width)
	if err != nil {
		return err
	}
	c.assign(inst.Operands[0], op(typ, a, b))
	return nil
}

func (c *compiler) emitSample(inst Instruction, explicitLod bool) error {
	coord, _, err := c.resolveSource(inst.Operands[1], 2)
	if err != nil {
		return err
	}
	res, err := c.lookupResource(inst.Operands[2].Index)
	if err != nil {
		return err
	}
	sampled := c.b.Load(c.sampledImageType, res.varID)
	var value uint32
	if explicitLod {
		lod, _, err := c.resolveSource(inst.Operands[4], 1)
		if err != nil {
			return err
		}
		value = c.b.ImageSampleExplicitLod(c.vec4Type, sampled, coord, lod)
	} else {
		value = c.b.ImageSampleImplicitLod(c.vec4Type, sampled, coord)
	}
	c.assign(inst.Operands[0], value)
	return nil
}

func (c *compiler) emitIf(condOperand Operand) error {
	cond, err := c.condition(condOperand)
	if err != nil {
		return err
	}
	thenLabel := c.b.AllocID()
	elseLabel := c.b.AllocID()
	mergeLabel := c.b.AllocID()
	c.b.SelectionMerge(mergeLabel, spirv.SelectionControlNone)
	c.b.BranchConditional(cond, thenLabel, elseLabel)
	c.currentTerminated = false
	c.b.LabelID(thenLabel)
	c.ifStack = append(c.ifStack, ifFrame{elseLabel: elseLabel, mergeLabel: mergeLabel})
	return nil
}

func (c *compiler) emitElse() error {
	if len(c.ifStack) == 0 {
		return errors.New("dxbc: ELSE without IF")
	}
	frame := &c.ifStack[len(c.ifStack)-1]
	c.branchIfNeeded(frame.mergeLabel)
	c.b.LabelID(frame.elseLabel)
	frame.inElse = true
	return nil
}

func (c *compiler) emitEndIf() error {
	if len(c.ifStack) == 0 {
		return errors.New("dxbc: ENDIF without IF")
	}
	frame := c.ifStack[len(c.ifStack)-1]
	c.ifStack = c.ifStack[:len(c.ifStack)-1]
	if !frame.inElse {
		c.branchIfNeeded(frame.mergeLabel)
		c.b.LabelID(frame.elseLabel)
		c.b.Branch(frame.mergeLabel)
	} else {
		c.branchIfNeeded(frame.mergeLabel)
	}
	c.b.LabelID(frame.mergeLabel)
	c.currentTerminated = false
	return nil
}

func (c *compiler) emitLoop() error {
	header := c.b.AllocID()
	body := c.b.AllocID()
	cont := c.b.AllocID()
	merge := c.b.AllocID()
	c.b.Branch(header)
	c.b.LabelID(header)
	c.b.LoopMerge(merge, cont, spirv.LoopControlNone)
	c.b.Branch(body)
	c.b.LabelID(body)
	c.loopStack = append(c.loopStack, loopFrame{headerLabel: header, continueLabel: cont, mergeLabel: merge})
	c.currentTerminated = false
	return nil
}

func (c *compiler) emitEndLoop() error {
	if len(c.loopStack) == 0 {
		return errors.New("dxbc: ENDLOOP without LOOP")
	}
	frame := c.loopStack[len(c.loopStack)-1]
	c.loopStack = c.loopStack[:len(c.loopStack)-1]
	c.branchIfNeeded(frame.continueLabel)
	c.b.LabelID(frame.continueLabel)
	c.b.Branch(frame.headerLabel)
	c.b.LabelID(frame.mergeLabel)
	c.currentTerminated = false
	return nil
}

func (c *compiler) emitBreak() error {
	if len(c.loopStack) == 0 {
		return errors.New("dxbc: BREAK outside loop")
	}
	c.b.Branch(c.loopStack[len(c.loopStack)-1].mergeLabel)
	c.currentTerminated = true
	return nil
}

func (c *compiler) emitBreakC(op Operand) error {
	if len(c.loopStack) == 0 {
		return errors.New("dxbc: BREAKC outside loop")
	}
	cond, err := c.condition(op)
	if err != nil {
		return err
	}
	next := c.b.AllocID()
	merge := c.loopStack[len(c.loopStack)-1].mergeLabel
	c.b.BranchConditional(cond, merge, next)
	c.b.LabelID(next)
	c.currentTerminated = false
	return nil
}

func (c *compiler) condition(op Operand) (uint32, error) {
	value, _, err := c.resolveSource(op, 1)
	if err != nil {
		return 0, err
	}
	return c.b.FOrdNotEqual(c.boolType, value, c.zeroFloat), nil
}

func (c *compiler) branchIfNeeded(target uint32) {
	if c.currentTerminated {
		return
	}
	c.b.Branch(target)
	c.currentTerminated = true
}

func (c *compiler) assign(dst Operand, value uint32) {
	ptr := c.lookupDest(dst)
	if ptr == 0 {
		return
	}
	mask := dst.Mask
	if mask == 0 {
		mask = 0xF
	}
	current := c.b.Load(c.vec4Type, ptr)
	currentComps := [4]uint32{}
	for i := range currentComps {
		currentComps[i] = c.b.CompositeExtract(c.floatType, current, uint32(i))
	}
	valueComps := c.extractComponents(value)
	if len(valueComps) == 0 {
		valueComps = []uint32{value}
	}
	idx := 0
	for i := 0; i < 4; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		src := valueComps[minInt(idx, len(valueComps)-1)]
		currentComps[i] = src
		idx++
	}
	updated := c.b.CompositeConstruct(c.vec4Type, currentComps[:]...)
	c.b.Store(ptr, updated)
}

func (c *compiler) resolveSource(op Operand, width int) (uint32, uint32, error) {
	if width <= 0 {
		width = maxInt(1, op.ComponentCount)
	}
	switch op.Type {
	case OperandTypeTemp:
		ptr := c.lookupTemp(op.Index)
		return c.applySourceModifiers(c.loadAndSelect(ptr, op, width), c.typeForWidth(width), op), c.typeForWidth(width), nil
	case OperandTypeInput:
		ptr, ok := c.inputs[op.Index]
		if !ok {
			return 0, 0, fmt.Errorf("dxbc: input register v%d not declared", op.Index)
		}
		return c.applySourceModifiers(c.loadAndSelect(ptr, op, width), c.typeForWidth(width), op), c.typeForWidth(width), nil
	case OperandTypeOutput:
		ptr, ok := c.outputs[op.Index]
		if !ok {
			return 0, 0, fmt.Errorf("dxbc: output register o%d not declared", op.Index)
		}
		return c.applySourceModifiers(c.loadAndSelect(ptr, op, width), c.typeForWidth(width), op), c.typeForWidth(width), nil
	case OperandTypeConstantBuffer:
		binding, err := c.lookupConstantBuffer(op.Index)
		if err != nil {
			return 0, 0, err
		}
		member := uint32(0)
		if len(op.Indices) > 1 {
			member = op.Indices[1]
		}
		if member >= binding.members {
			member = binding.members - 1
		}
		ptr := c.b.AccessChain(c.ptrUniformVec4, binding.varID, c.intConst(member))
		return c.applySourceModifiers(c.selectValue(c.b.Load(c.vec4Type, ptr), op, width), c.typeForWidth(width), op), c.typeForWidth(width), nil
	case OperandTypeImmediate32:
		return c.applySourceModifiers(c.immediateValue(op, width), c.typeForWidth(width), op), c.typeForWidth(width), nil
	default:
		return 0, 0, fmt.Errorf("dxbc: unsupported operand type %d", op.Type)
	}
}

func (c *compiler) applySourceModifiers(value, typ uint32, op Operand) uint32 {
	if op.Abs {
		// Not implemented as GLSL ext abs isn't currently needed; preserve magnitude.
	}
	if op.Negate {
		return c.b.FNegate(typ, value)
	}
	return value
}

func (c *compiler) loadAndSelect(ptr uint32, op Operand, width int) uint32 {
	return c.selectValue(c.b.Load(c.vec4Type, ptr), op, width)
}

func (c *compiler) selectValue(value uint32, op Operand, width int) uint32 {
	width = maxInt(1, width)
	if width == 1 {
		return c.b.CompositeExtract(c.floatType, value, uint32(op.Swizzle[0]))
	}
	components := make([]uint32, width)
	for i := 0; i < width; i++ {
		components[i] = uint32(op.Swizzle[minInt(i, 3)])
	}
	return c.b.VectorShuffle(c.typeForWidth(width), value, value, components...)
}

func (c *compiler) immediateValue(op Operand, width int) uint32 {
	vals := op.Immediate
	if len(vals) == 0 {
		vals = []uint32{0, 0, 0, 0}
	}
	if len(vals) == 1 {
		vals = []uint32{vals[0], vals[0], vals[0], vals[0]}
	}
	selected := make([]float32, width)
	for i := 0; i < width; i++ {
		idx := int(op.Swizzle[minInt(i, 3)])
		idx = minInt(idx, len(vals)-1)
		selected[i] = math.Float32frombits(vals[idx])
	}
	if width == 1 {
		return c.floatConst(selected[0])
	}
	return c.vectorConst(selected...)
}

func (c *compiler) extractComponents(value uint32) []uint32 {
	return []uint32{c.b.CompositeExtract(c.floatType, value, 0), c.b.CompositeExtract(c.floatType, value, 1), c.b.CompositeExtract(c.floatType, value, 2), c.b.CompositeExtract(c.floatType, value, 3)}
}

func (c *compiler) typeForWidth(width int) uint32 {
	switch width {
	case 1:
		return c.floatType
	case 2:
		return c.vec2Type
	case 3:
		return c.vec3Type
	default:
		return c.vec4Type
	}
}

func (c *compiler) maskWidth(op Operand) int {
	if op.Mask == 0 {
		return 4
	}
	return bitsCount(op.Mask)
}

func (c *compiler) lookupDest(op Operand) uint32 {
	switch op.Type {
	case OperandTypeTemp:
		return c.lookupTemp(op.Index)
	case OperandTypeOutput:
		if ptr, ok := c.outputs[op.Index]; ok {
			return ptr
		}
	}
	return 0
}

func (c *compiler) lookupTemp(index uint32) uint32 {
	if ptr, ok := c.temps[index]; ok {
		return ptr
	}
	ptr := c.b.Variable(c.ptrFunctionVec4, spirv.StorageClassFunction)
	c.temps[index] = ptr
	c.b.Store(ptr, c.zeroVec4)
	return ptr
}

func (c *compiler) lookupConstantBuffer(slot uint32) (cbBinding, error) {
	if binding, ok := c.cbuffers[slot]; ok {
		return binding, nil
	}
	generic := ConstantBuffer{Name: fmt.Sprintf("cbuffer_%d", slot), Size: 16, BindPoint: slot}
	c.shader.ConstantBuffers = append(c.shader.ConstantBuffers, generic)
	c.declareConstantBuffers()
	binding, ok := c.cbuffers[slot]
	if !ok {
		return cbBinding{}, fmt.Errorf("dxbc: constant buffer %d unavailable", slot)
	}
	return binding, nil
}

func (c *compiler) lookupResource(slot uint32) (resourceBinding, error) {
	if res, ok := c.resources[slot]; ok {
		return res, nil
	}
	generic := ResourceBinding{Name: fmt.Sprintf("texture_%d", slot), Type: ShaderInputTypeTexture, BindPoint: slot, BindCount: 1}
	c.shader.Resources = append(c.shader.Resources, generic)
	c.declareResources()
	res, ok := c.resources[slot]
	if !ok {
		return resourceBinding{}, fmt.Errorf("dxbc: resource %d unavailable", slot)
	}
	return res, nil
}

func (c *compiler) inputPointerFor(sig Signature) uint32 {
	if strings.EqualFold(sig.Semantic, "SV_VertexID") {
		return c.ptrInputInt
	}
	return c.ptrInputVec4
}

func (c *compiler) decorateSignature(varID uint32, sig Signature, input bool) {
	semantic := strings.ToUpper(sig.Semantic)
	switch {
	case !input && semantic == "SV_POSITION":
		c.b.Decorate(varID, spirv.DecorationBuiltIn, spirv.BuiltInPosition)
	case input && c.shader.Stage == ProgramTypePixel && semantic == "SV_POSITION":
		c.b.Decorate(varID, spirv.DecorationBuiltIn, spirv.BuiltInFragCoord)
	case input && semantic == "SV_VERTEXID":
		c.b.Decorate(varID, spirv.DecorationBuiltIn, spirv.BuiltInVertexIndex)
	case !input && strings.HasPrefix(semantic, "SV_TARGET"):
		c.b.Decorate(varID, spirv.DecorationLocation, sig.SemanticIndex)
	default:
		c.b.Decorate(varID, spirv.DecorationLocation, sig.Register)
	}
}

func (c *compiler) fallbackSignatures(opcode Opcode) []Signature {
	seen := map[uint32]bool{}
	var regs []uint32
	for _, inst := range c.shader.Instructions {
		if inst.Opcode != opcode || len(inst.Operands) == 0 {
			continue
		}
		reg := inst.Operands[0].Index
		if !seen[reg] {
			seen[reg] = true
			regs = append(regs, reg)
		}
	}
	sort.Slice(regs, func(i, j int) bool { return regs[i] < regs[j] })
	out := make([]Signature, 0, len(regs))
	for _, reg := range regs {
		name := "TEXCOORD"
		if opcode == D3D10SBOpcodeDclOutput && c.shader.Stage == ProgramTypeVertex && reg == 0 {
			name = "SV_Position"
		}
		if opcode == D3D10SBOpcodeDclOutput && c.shader.Stage == ProgramTypePixel && reg == 0 {
			name = "SV_Target"
		}
		out = append(out, Signature{Semantic: name, Register: reg, Mask: 0xF, RWMask: 0xF})
	}
	return out
}

func (c *compiler) constantBuffersBySlot() map[uint32]ConstantBuffer {
	out := map[uint32]ConstantBuffer{}
	for i, cb := range c.shader.ConstantBuffers {
		slot := cb.BindPoint
		if slot == 0 && len(c.shader.ConstantBuffers) == 1 {
			slot = 0
		}
		out[slot] = c.shader.ConstantBuffers[i]
	}
	for _, inst := range c.shader.Instructions {
		if inst.Opcode == D3D10SBOpcodeDclConstantBuffer && len(inst.Operands) > 0 {
			slot := inst.Operands[0].Index
			if _, ok := out[slot]; !ok {
				out[slot] = ConstantBuffer{Name: fmt.Sprintf("cbuffer_%d", slot), Size: 16, BindPoint: slot}
			}
		}
	}
	return out
}

func (c *compiler) resourcesBySlot() map[uint32]ResourceBinding {
	out := map[uint32]ResourceBinding{}
	for _, res := range c.shader.Resources {
		out[res.BindPoint] = res
	}
	for _, inst := range c.shader.Instructions {
		if inst.Opcode == D3D10SBOpcodeDclResource && len(inst.Operands) > 0 {
			slot := inst.Operands[0].Index
			if _, ok := out[slot]; !ok {
				out[slot] = ResourceBinding{Name: fmt.Sprintf("texture_%d", slot), Type: ShaderInputTypeTexture, BindPoint: slot, BindCount: 1}
			}
		}
	}
	return out
}

func (c *compiler) tempCount() uint32 {
	var count uint32
	for _, inst := range c.shader.Instructions {
		if inst.Opcode == D3D10SBOpcodeDclTemps && len(inst.ExtraTokens) != 0 {
			if inst.ExtraTokens[0] > count {
				count = inst.ExtraTokens[0]
			}
		}
		for _, op := range inst.Operands {
			if op.Type == OperandTypeTemp && op.Index+1 > count {
				count = op.Index + 1
			}
		}
	}
	return count
}

func (c *compiler) intConst(v uint32) uint32 {
	if id, ok := c.intConstants[v]; ok {
		return id
	}
	id := c.b.Constant(c.intType, v)
	c.intConstants[v] = id
	return id
}

func (c *compiler) floatConst(v float32) uint32 {
	key := math.Float32bits(v)
	if id, ok := c.floatConstants[key]; ok {
		return id
	}
	id := c.b.Float32Constant(c.floatType, v)
	c.floatConstants[key] = id
	return id
}

func (c *compiler) vectorConst(values ...float32) uint32 {
	width := len(values)
	if width == 0 {
		width = 4
		values = []float32{0, 0, 0, 0}
	}
	key := fmt.Sprint(width, ":", values)
	if id, ok := c.vecConstants[key]; ok {
		return id
	}
	consts := make([]uint32, width)
	for i, v := range values[:width] {
		consts[i] = c.floatConst(v)
	}
	id := c.b.ConstantComposite(c.typeForWidth(width), consts...)
	c.vecConstants[key] = id
	return id
}

func bitsCount(mask uint8) int {
	count := 0
	for mask != 0 {
		count += int(mask & 1)
		mask >>= 1
	}
	if count == 0 {
		return 4
	}
	return count
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxUint32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
