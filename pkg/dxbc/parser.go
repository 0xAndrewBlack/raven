//go:build guest_windows

package dxbc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"strings"
)

func Parse(data []byte) (*Shader, error) {
	if len(data) < 32 {
		return nil, errors.New("dxbc: container too small")
	}
	if string(data[:4]) != "DXBC" {
		return nil, errors.New("dxbc: invalid magic")
	}
	shader := &Shader{}
	copy(shader.Checksum[:], data[4:20])
	totalSize := binary.LittleEndian.Uint32(data[24:28])
	if totalSize != 0 && totalSize <= uint32(len(data)) {
		data = data[:totalSize]
	}
	chunkCount := int(binary.LittleEndian.Uint32(data[28:32]))
	if len(data) < 32+chunkCount*4 {
		return nil, errors.New("dxbc: truncated chunk table")
	}

	bufferBindings := map[string]uint32{}
	for i := 0; i < chunkCount; i++ {
		off := binary.LittleEndian.Uint32(data[32+i*4:])
		if off+8 > uint32(len(data)) {
			return nil, fmt.Errorf("dxbc: chunk %d offset out of range", i)
		}
		chunkType := string(data[off : off+4])
		size := binary.LittleEndian.Uint32(data[off+4:])
		if off+8+size > uint32(len(data)) {
			return nil, fmt.Errorf("dxbc: chunk %s truncated", chunkType)
		}
		payload := append([]byte(nil), data[off+8:off+8+size]...)
		shader.Chunks = append(shader.Chunks, Chunk{Type: chunkType, Offset: off, Data: payload})
		switch chunkType {
		case ChunkISGN:
			inputs, err := parseSignatureChunk(payload)
			if err != nil {
				return nil, err
			}
			shader.Inputs = inputs
		case ChunkOSGN:
			outputs, err := parseSignatureChunk(payload)
			if err != nil {
				return nil, err
			}
			shader.Outputs = outputs
		case ChunkRDEF:
			cbs, resources, samplers, bindings, err := parseRDEFChunk(payload)
			if err != nil {
				return nil, err
			}
			shader.ConstantBuffers = cbs
			shader.Resources = resources
			shader.Samplers = samplers
			bufferBindings = bindings
		case ChunkSHDR, ChunkSHEX:
			stage, major, minor, instructions, err := parseShaderChunk(payload)
			if err != nil {
				return nil, err
			}
			shader.Stage, shader.MajorVersion, shader.MinorVersion = stage, major, minor
			shader.Instructions = instructions
		}
	}
	for i := range shader.ConstantBuffers {
		if bind, ok := bufferBindings[shader.ConstantBuffers[i].Name]; ok {
			shader.ConstantBuffers[i].BindPoint = bind
		}
	}
	return shader, nil
}

func parseSignatureChunk(data []byte) ([]Signature, error) {
	if len(data) < 8 {
		return nil, errors.New("dxbc: signature chunk too small")
	}
	count := int(binary.LittleEndian.Uint32(data[:4]))
	base := 8
	entrySize := 24
	if len(data) < base+count*entrySize {
		return nil, errors.New("dxbc: signature chunk truncated")
	}
	out := make([]Signature, 0, count)
	for i := 0; i < count; i++ {
		off := base + i*entrySize
		nameOffset := int(binary.LittleEndian.Uint32(data[off:]))
		out = append(out, Signature{
			Semantic:      readCString(data, nameOffset),
			SemanticIndex: binary.LittleEndian.Uint32(data[off+4:]),
			SystemValue:   binary.LittleEndian.Uint32(data[off+8:]),
			ComponentType: binary.LittleEndian.Uint32(data[off+12:]),
			Register:      binary.LittleEndian.Uint32(data[off+16:]),
			Mask:          data[off+20],
			RWMask:        data[off+21],
		})
	}
	return out, nil
}

func parseRDEFChunk(data []byte) ([]ConstantBuffer, []ResourceBinding, []ResourceBinding, map[string]uint32, error) {
	if len(data) < 24 {
		return nil, nil, nil, nil, errors.New("dxbc: rdef chunk too small")
	}
	cbCount := int(binary.LittleEndian.Uint32(data[:4]))
	resCount := int(binary.LittleEndian.Uint32(data[4:]))
	cbOffset := int(binary.LittleEndian.Uint32(data[8:]))
	resOffset := int(binary.LittleEndian.Uint32(data[12:]))
	cbs := make([]ConstantBuffer, 0, cbCount)
	if cbOffset != 0 {
		for i := 0; i < cbCount; i++ {
			off := cbOffset + i*24
			if off+24 > len(data) {
				return nil, nil, nil, nil, errors.New("dxbc: constant buffer table truncated")
			}
			nameOffset := int(binary.LittleEndian.Uint32(data[off:]))
			varCount := int(binary.LittleEndian.Uint32(data[off+4:]))
			varOffset := int(binary.LittleEndian.Uint32(data[off+8:]))
			cb := ConstantBuffer{
				Name: readCString(data, nameOffset),
				Size: binary.LittleEndian.Uint32(data[off+12:]),
			}
			for j := 0; j < varCount; j++ {
				voff := varOffset + j*24
				if voff+24 > len(data) {
					return nil, nil, nil, nil, errors.New("dxbc: constant buffer variable table truncated")
				}
				cb.Variables = append(cb.Variables, Variable{
					Name:        readCString(data, int(binary.LittleEndian.Uint32(data[voff:]))),
					StartOffset: binary.LittleEndian.Uint32(data[voff+4:]),
					Size:        binary.LittleEndian.Uint32(data[voff+8:]),
				})
			}
			cbs = append(cbs, cb)
		}
	}
	resources := []ResourceBinding{}
	samplers := []ResourceBinding{}
	bufferBindings := map[string]uint32{}
	if resOffset != 0 {
		for i := 0; i < resCount; i++ {
			off := resOffset + i*32
			if off+32 > len(data) {
				return nil, nil, nil, nil, errors.New("dxbc: resource binding table truncated")
			}
			binding := ResourceBinding{
				Name:      readCString(data, int(binary.LittleEndian.Uint32(data[off:]))),
				Type:      binary.LittleEndian.Uint32(data[off+4:]),
				BindPoint: binary.LittleEndian.Uint32(data[off+20:]),
				BindCount: binary.LittleEndian.Uint32(data[off+24:]),
			}
			switch binding.Type {
			case ShaderInputTypeTexture:
				resources = append(resources, binding)
			case ShaderInputTypeSampler:
				samplers = append(samplers, binding)
			default:
				bufferBindings[binding.Name] = binding.BindPoint
			}
		}
	}
	return cbs, resources, samplers, bufferBindings, nil
}

func parseShaderChunk(data []byte) (uint32, uint32, uint32, []Instruction, error) {
	if len(data) < 8 {
		return 0, 0, 0, nil, errors.New("dxbc: shader chunk too small")
	}
	words := bytesToWords(data)
	version := words[0]
	stage := (version >> 16) & 0xffff
	major := (version >> 4) & 0xf
	minor := version & 0xf
	length := int(words[1])
	if length == 0 || length > len(words) {
		length = len(words)
	}
	instructions := []Instruction{}
	for pc := 2; pc < length; {
		inst, next, err := decodeInstruction(words, pc, length)
		if err != nil {
			return 0, 0, 0, nil, err
		}
		instructions = append(instructions, inst)
		pc = next
	}
	return stage, major, minor, instructions, nil
}

func decodeInstruction(words []uint32, pc, limit int) (Instruction, int, error) {
	if pc >= limit {
		return Instruction{}, pc, ioErr("unexpected end of instruction stream")
	}
	start := pc
	token := words[pc]
	pc++
	opcode := Opcode(token & 0x7ff)
	length := int((token >> 24) & 0x7f)
	if length <= 0 {
		return Instruction{}, pc, fmt.Errorf("dxbc: invalid instruction length for opcode %d", opcode)
	}
	end := start + length
	if end > limit {
		return Instruction{}, pc, fmt.Errorf("dxbc: instruction opcode %d truncated", opcode)
	}
	for hasExt := token>>31 != 0; hasExt; {
		if pc >= end {
			return Instruction{}, pc, errors.New("dxbc: truncated extended opcode")
		}
		token = words[pc]
		pc++
		hasExt = token>>31 != 0
	}
	inst := Instruction{Opcode: opcode, Length: uint32(length), RawTokens: append([]uint32(nil), words[start:end]...)}
	operandCount := expectedOperandCount(opcode)
	if opcode == D3D10SBOpcodeDclTemps && pc < end {
		inst.ExtraTokens = append(inst.ExtraTokens, words[pc])
		pc++
	}
	if operandCount >= 0 {
		for i := 0; i < operandCount && pc < end; i++ {
			op, used, err := decodeOperand(words[pc:end])
			if err != nil {
				return Instruction{}, pc, err
			}
			inst.Operands = append(inst.Operands, op)
			pc += used
		}
	}
	for pc < end {
		op, used, err := decodeOperand(words[pc:end])
		if err == nil && used > 0 {
			inst.Operands = append(inst.Operands, op)
			pc += used
			continue
		}
		inst.ExtraTokens = append(inst.ExtraTokens, words[pc])
		pc++
	}
	return inst, end, nil
}

func expectedOperandCount(opcode Opcode) int {
	switch opcode {
	case D3D10SBOpcodeAdd, D3D10SBOpcodeMul, D3D10SBOpcodeDiv, D3D10SBOpcodeDp3, D3D10SBOpcodeDp4:
		return 3
	case D3D10SBOpcodeMov, D3D10SBOpcodeIf, D3D10SBOpcodeBreakC, D3D10SBOpcodeDclInput, D3D10SBOpcodeDclOutput, D3D10SBOpcodeDclConstantBuffer, D3D10SBOpcodeDclResource, D3D10SBOpcodeDclSampler:
		return 1 + btoi(opcode == D3D10SBOpcodeMov)
	case D3D10SBOpcodeMad:
		return 4
	case D3D10SBOpcodeSample:
		return 4
	case D3D10SBOpcodeSampleL:
		return 5
	case D3D10SBOpcodeElse, D3D10SBOpcodeEndIf, D3D10SBOpcodeLoop, D3D10SBOpcodeEndLoop, D3D10SBOpcodeBreak, D3D10SBOpcodeRet:
		return 0
	default:
		return -1
	}
}

func decodeOperand(words []uint32) (Operand, int, error) {
	if len(words) == 0 {
		return Operand{}, 0, errors.New("dxbc: missing operand token")
	}
	token := words[0]
	operand := Operand{
		Type:           OperandType((token >> 12) & 0xff),
		Mask:           0xF,
		ComponentCount: 4,
		Swizzle:        [4]byte{0, 1, 2, 3},
	}
	used := 1
	numComponents := token & 0x3
	selectionMode := (token >> 2) & 0x3
	selectors := byte((token >> 4) & 0xff)
	switch numComponents {
	case 1:
		operand.ComponentCount = 1
	case 2:
		operand.ComponentCount = 4
	default:
		operand.ComponentCount = 4
	}
	switch selectionMode {
	case 0:
		operand.Mask = selectors & 0xF
		operand.ComponentCount = bits.OnesCount8(operand.Mask)
	case 1:
		operand.Swizzle[0] = selectors & 0x3
		operand.Swizzle[1] = (selectors >> 2) & 0x3
		operand.Swizzle[2] = (selectors >> 4) & 0x3
		operand.Swizzle[3] = (selectors >> 6) & 0x3
	case 2:
		v := selectors & 0x3
		operand.Swizzle = [4]byte{v, v, v, v}
		operand.ComponentCount = 1
	}
	indexDims := int((token >> 20) & 0x3)
	for i := 0; i < indexDims; i++ {
		repr := (token >> (22 + i*3)) & 0x7
		switch repr {
		case 0:
			if used >= len(words) {
				return Operand{}, 0, errors.New("dxbc: truncated operand index")
			}
			operand.Indices = append(operand.Indices, words[used])
			used++
		case 3:
			if used >= len(words) {
				return Operand{}, 0, errors.New("dxbc: truncated operand index")
			}
			operand.Indices = append(operand.Indices, words[used])
			used++
			_, relUsed, err := decodeOperand(words[used:])
			if err != nil {
				return Operand{}, 0, err
			}
			used += relUsed
		case 2:
			operand.Indices = append(operand.Indices, 0)
			_, relUsed, err := decodeOperand(words[used:])
			if err != nil {
				return Operand{}, 0, err
			}
			used += relUsed
		default:
			return Operand{}, 0, fmt.Errorf("dxbc: unsupported operand index representation %d", repr)
		}
	}
	if len(operand.Indices) != 0 {
		operand.Index = operand.Indices[0]
	}
	for hasExt := token>>31 != 0; hasExt; {
		if used >= len(words) {
			return Operand{}, 0, errors.New("dxbc: truncated operand modifier")
		}
		ext := words[used]
		used++
		mod := (ext >> 6) & 0xff
		switch mod {
		case 1:
			operand.Negate = true
		case 2:
			operand.Abs = true
		case 3:
			operand.Abs = true
			operand.Negate = true
		}
		hasExt = ext>>31 != 0
	}
	if operand.Type == OperandTypeImmediate32 {
		count := operand.ComponentCount
		if count <= 0 {
			count = 4
		}
		if used+count > len(words) {
			return Operand{}, 0, errors.New("dxbc: truncated immediate operand")
		}
		operand.Immediate = append([]uint32(nil), words[used:used+count]...)
		used += count
	}
	return operand, used, nil
}

func bytesToWords(data []byte) []uint32 {
	words := make([]uint32, len(data)/4)
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(data[i*4:])
	}
	return words
}

func readCString(data []byte, off int) string {
	if off < 0 || off >= len(data) {
		return ""
	}
	end := off
	for end < len(data) && data[end] != 0 {
		end++
	}
	return strings.TrimSpace(string(data[off:end]))
}

func ioErr(msg string) error { return errors.New("dxbc: " + msg) }
func btoi(v bool) int {
	if v {
		return 1
	}
	return 0
}
