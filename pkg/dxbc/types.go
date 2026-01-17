package dxbc

const (
	ChunkRDEF = "RDEF"
	ChunkISGN = "ISGN"
	ChunkOSGN = "OSGN"
	ChunkSHDR = "SHDR"
	ChunkSHEX = "SHEX"
)

const (
	ProgramTypePixel  = 0
	ProgramTypeVertex = 1
)

const (
	D3D10SBOpcodeAdd               Opcode = 0
	D3D10SBOpcodeMov               Opcode = 1
	D3D10SBOpcodeMul               Opcode = 2
	D3D10SBOpcodeDiv               Opcode = 3
	D3D10SBOpcodeMad               Opcode = 4
	D3D10SBOpcodeDp3               Opcode = 16
	D3D10SBOpcodeDp4               Opcode = 17
	D3D10SBOpcodeIf                Opcode = 18
	D3D10SBOpcodeElse              Opcode = 19
	D3D10SBOpcodeBreak             Opcode = 22
	D3D10SBOpcodeBreakC            Opcode = 23
	D3D10SBOpcodeLoop              Opcode = 48
	D3D10SBOpcodeEndLoop           Opcode = 49
	D3D10SBOpcodeRet               Opcode = 62
	D3D10SBOpcodeSample            Opcode = 69
	D3D10SBOpcodeSampleL           Opcode = 72
	D3D10SBOpcodeDclConstantBuffer Opcode = 89
	D3D10SBOpcodeDclResource       Opcode = 88
	D3D10SBOpcodeDclSampler        Opcode = 90
	D3D10SBOpcodeDclInput          Opcode = 95
	D3D10SBOpcodeDclOutput         Opcode = 101
	D3D10SBOpcodeDclTemps          Opcode = 104
	D3D10SBOpcodeEndIf             Opcode = 21
)

const (
	OperandTypeTemp           OperandType = 0
	OperandTypeInput          OperandType = 1
	OperandTypeOutput         OperandType = 2
	OperandTypeConstantBuffer OperandType = 4
	OperandTypeImmediate32    OperandType = 5
	OperandTypeSampler        OperandType = 6
	OperandTypeResource       OperandType = 7
)

const (
	ShaderInputTypeTexture = 2
	ShaderInputTypeSampler = 3
)

type Opcode uint32

type OperandType uint32

type Shader struct {
	Checksum        [16]byte
	Chunks          []Chunk
	Inputs          []Signature
	Outputs         []Signature
	ConstantBuffers []ConstantBuffer
	Resources       []ResourceBinding
	Samplers        []ResourceBinding
	Instructions    []Instruction
	Stage           uint32
	MajorVersion    uint32
	MinorVersion    uint32
}

type Chunk struct {
	Type   string
	Offset uint32
	Data   []byte
}

type Signature struct {
	Semantic      string
	SemanticIndex uint32
	Register      uint32
	SystemValue   uint32
	ComponentType uint32
	Mask          uint8
	RWMask        uint8
}

type ConstantBuffer struct {
	Name      string
	Size      uint32
	Variables []Variable
	BindPoint uint32
}

type Variable struct {
	Name        string
	StartOffset uint32
	Size        uint32
}

type ResourceBinding struct {
	Name      string
	Type      uint32
	BindPoint uint32
	BindCount uint32
}

type Instruction struct {
	Opcode      Opcode
	Length      uint32
	Operands    []Operand
	ExtraTokens []uint32
	RawTokens   []uint32
}

type Operand struct {
	Type           OperandType
	Index          uint32
	Indices        []uint32
	Swizzle        [4]byte
	Mask           uint8
	Negate         bool
	Abs            bool
	Immediate      []uint32
	ComponentCount int
}
