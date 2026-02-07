//go:build guest_windows

package d3d9

import shared "github.com/mirkobrombin/Raven/pkg/spirv"

const (
	spvMagicNumber = shared.MagicNumber
	spvVersion10   = shared.Version10
)

const (
	spvOpExtInstImport       = shared.OpExtInstImport
	spvOpExtInst             = shared.OpExtInst
	spvOpMemoryModel         = shared.OpMemoryModel
	spvOpEntryPoint          = shared.OpEntryPoint
	spvOpExecutionMode       = shared.OpExecutionMode
	spvOpCapability          = shared.OpCapability
	spvOpTypeVoid            = shared.OpTypeVoid
	spvOpTypeBool            = shared.OpTypeBool
	spvOpTypeInt             = shared.OpTypeInt
	spvOpTypeFloat           = shared.OpTypeFloat
	spvOpTypeVector          = shared.OpTypeVector
	spvOpTypeMatrix          = shared.OpTypeMatrix
	spvOpTypeImage           = shared.OpTypeImage
	spvOpTypeSampledImage    = shared.OpTypeSampledImage
	spvOpTypeStruct          = shared.OpTypeStruct
	spvOpTypePointer         = shared.OpTypePointer
	spvOpTypeFunction        = shared.OpTypeFunction
	spvOpConstant            = shared.OpConstant
	spvOpConstantComposite   = shared.OpConstantComposite
	spvOpVariable            = shared.OpVariable
	spvOpLoad                = shared.OpLoad
	spvOpStore               = shared.OpStore
	spvOpAccessChain         = shared.OpAccessChain
	spvOpDecorate            = shared.OpDecorate
	spvOpMemberDecorate      = shared.OpMemberDecorate
	spvOpCompositeConstruct  = shared.OpCompositeConstruct
	spvOpCompositeExtract    = shared.OpCompositeExtract
	spvOpImageSampleImplicit = shared.OpImageSampleImplicit
	spvOpFAdd                = shared.OpFAdd
	spvOpFSub                = shared.OpFSub
	spvOpFMul                = shared.OpFMul
	spvOpFDiv                = shared.OpFDiv
	spvOpVectorTimesScalar   = shared.OpVectorTimesScalar
	spvOpMatrixTimesVector   = shared.OpMatrixTimesVector
	spvOpDot                 = shared.OpDot
	spvOpSelect              = shared.OpSelect
	spvOpFOrdGreaterThan     = shared.OpFOrdGreaterThan
	spvOpFunction            = shared.OpFunction
	spvOpFunctionCall        = shared.OpFunctionCall
	spvOpLabel               = shared.OpLabel
	spvOpReturn              = shared.OpReturn
	spvOpFunctionEnd         = shared.OpFunctionEnd
)

const (
	spvCapabilityShader = shared.CapabilityShader
)

const (
	spvAddressingModelLogical = shared.AddressingModelLogical
	spvMemoryModelGLSL450     = shared.MemoryModelGLSL450
)

const (
	spvExecutionModelVertex   = shared.ExecutionModelVertex
	spvExecutionModelFragment = shared.ExecutionModelFragment
)

const (
	spvExecutionModeOriginUpperLeft = shared.ExecutionModeOriginUpperLeft
)

const (
	spvStorageClassUniformConstant = shared.StorageClassUniformConstant
	spvStorageClassInput           = shared.StorageClassInput
	spvStorageClassOutput          = shared.StorageClassOutput
	spvStorageClassFunction        = shared.StorageClassFunction
	spvStorageClassPushConstant    = shared.StorageClassPushConstant
)

const (
	spvDecorationBlock      = shared.DecorationBlock
	spvDecorationBuiltIn    = shared.DecorationBuiltIn
	spvDecorationLocation   = shared.DecorationLocation
	spvDecorationBinding    = shared.DecorationBinding
	spvDecorationDescriptor = shared.DecorationDescriptorSet
	spvDecorationOffset     = shared.DecorationOffset
	spvDecorationColMajor   = shared.DecorationColMajor
	spvDecorationMatrixStep = shared.DecorationMatrixStride
)

const (
	spvBuiltInPosition = shared.BuiltInPosition
)

const (
	spvFunctionControlNone = shared.FunctionControlNone
)

const (
	spvDim2D = shared.Dim2D
)

const (
	spvImageFormatUnknown = shared.ImageFormatUnknown
)

const (
	glslStd450Normalize = shared.GlslStd450Normalize
)

type Builder = shared.Builder

var NewBuilder = shared.NewBuilder
