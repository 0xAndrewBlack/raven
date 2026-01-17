package dxbc

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/spirv"
)

func TestParseAndCompileMinimalVertexShader(t *testing.T) {
	blob := buildMinimalVertexDXBC(t)
	shader, err := Parse(blob)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if shader.Stage != ProgramTypeVertex {
		t.Fatalf("unexpected shader stage: %d", shader.Stage)
	}
	if len(shader.Instructions) == 0 {
		t.Fatal("expected instructions")
	}
	spv, err := Compile(shader)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	if len(spv) < 20 {
		t.Fatalf("compiled spir-v too small: %d", len(spv))
	}
	if got := binary.LittleEndian.Uint32(spv[:4]); got != spirv.MagicNumber {
		t.Fatalf("unexpected spir-v magic: 0x%x", got)
	}
}

func buildMinimalVertexDXBC(t *testing.T) []byte {
	t.Helper()
	isgn := buildSignatureChunk([]sigDesc{{semantic: "POSITION", reg: 0}})
	osgn := buildSignatureChunk([]sigDesc{{semantic: "SV_Position", reg: 0}})
	shdr := buildShaderChunk(ProgramTypeVertex, [][]uint32{
		instr(D3D10SBOpcodeDclInput, operandToken(OperandTypeInput, 0xF, 1), 0),
		instr(D3D10SBOpcodeDclOutput, operandToken(OperandTypeOutput, 0xF, 1), 0),
		instr(D3D10SBOpcodeMov,
			operandToken(OperandTypeOutput, 0xF, 1), 0,
			operandToken(OperandTypeInput, 0xE4, 1), 0,
		),
		instr(D3D10SBOpcodeRet),
	})
	return buildContainer([]chunkSpec{{ChunkISGN, isgn}, {ChunkOSGN, osgn}, {ChunkSHDR, shdr}})
}

type sigDesc struct {
	semantic string
	reg      uint32
}

type chunkSpec struct {
	typ  string
	data []byte
}

func buildSignatureChunk(sigs []sigDesc) []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, uint32(len(sigs)))
	binary.Write(buf, binary.LittleEndian, uint32(8))
	entrySize := 24
	stringBase := 8 + len(sigs)*entrySize
	stringOffset := stringBase
	stringsBuf := &bytes.Buffer{}
	for _, sig := range sigs {
		binary.Write(buf, binary.LittleEndian, uint32(stringOffset))
		binary.Write(buf, binary.LittleEndian, uint32(0))
		binary.Write(buf, binary.LittleEndian, uint32(0))
		binary.Write(buf, binary.LittleEndian, uint32(3))
		binary.Write(buf, binary.LittleEndian, sig.reg)
		buf.WriteByte(0x0F)
		buf.WriteByte(0x0F)
		binary.Write(buf, binary.LittleEndian, uint16(0))
		stringsBuf.WriteString(sig.semantic)
		stringsBuf.WriteByte(0)
		stringOffset += len(sig.semantic) + 1
	}
	buf.Write(stringsBuf.Bytes())
	return buf.Bytes()
}

func buildShaderChunk(stage uint32, instructions [][]uint32) []byte {
	words := []uint32{(stage << 16) | (5 << 4), 0}
	for _, inst := range instructions {
		words = append(words, inst...)
	}
	words[1] = uint32(len(words))
	buf := &bytes.Buffer{}
	for _, word := range words {
		binary.Write(buf, binary.LittleEndian, word)
	}
	return buf.Bytes()
}

func instr(op Opcode, operands ...uint32) []uint32 {
	length := uint32(len(operands) + 1)
	words := []uint32{(length << 24) | uint32(op)}
	return append(words, operands...)
}

func operandToken(kind OperandType, selector uint32, indexDims uint32) uint32 {
	return 2 | (1 << 2) | (selector << 4) | (uint32(kind) << 12) | (indexDims << 20)
}

func buildContainer(chunks []chunkSpec) []byte {
	headerSize := 32 + len(chunks)*4
	offsets := make([]uint32, len(chunks))
	offset := headerSize
	for i, chunk := range chunks {
		offsets[i] = uint32(offset)
		offset += 8 + len(chunk.data)
	}
	buf := &bytes.Buffer{}
	buf.WriteString("DXBC")
	buf.Write(make([]byte, 16))
	binary.Write(buf, binary.LittleEndian, uint32(1))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	binary.Write(buf, binary.LittleEndian, uint32(len(chunks)))
	for _, off := range offsets {
		binary.Write(buf, binary.LittleEndian, off)
	}
	for _, chunk := range chunks {
		buf.WriteString(chunk.typ)
		binary.Write(buf, binary.LittleEndian, uint32(len(chunk.data)))
		buf.Write(chunk.data)
	}
	return buf.Bytes()
}
