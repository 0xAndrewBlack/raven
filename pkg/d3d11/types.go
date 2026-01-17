package d3d11

const (
	D3D11_FORMAT_UNKNOWN            uint32 = 0
	D3D11_FORMAT_R16G16B16A16_FLOAT uint32 = 10
	D3D11_FORMAT_R10G10B10A2_UNORM  uint32 = 24
	D3D11_FORMAT_R8G8B8A8_UNORM     uint32 = 28
	D3D11_FORMAT_R32_FLOAT          uint32 = 41
	D3D11_FORMAT_D24_UNORM_S8_UINT  uint32 = 45
	D3D11_FORMAT_B8G8R8A8_UNORM     uint32 = 87
	D3D11_FORMAT_B8G8R8X8_UNORM     uint32 = 88
)

const (
	D3D11_USAGE_DEFAULT   uint32 = 0
	D3D11_USAGE_IMMUTABLE uint32 = 1
	D3D11_USAGE_DYNAMIC   uint32 = 2
	D3D11_USAGE_STAGING   uint32 = 3
)

const (
	D3D11_BIND_VERTEX_BUFFER    uint32 = 0x1
	D3D11_BIND_INDEX_BUFFER     uint32 = 0x2
	D3D11_BIND_CONSTANT_BUFFER  uint32 = 0x4
	D3D11_BIND_SHADER_RESOURCE  uint32 = 0x8
	D3D11_BIND_RENDER_TARGET    uint32 = 0x20
	D3D11_BIND_DEPTH_STENCIL    uint32 = 0x40
	D3D11_BIND_UNORDERED_ACCESS uint32 = 0x80
)

const (
	D3D11_CPU_ACCESS_WRITE uint32 = 0x10000
	D3D11_CPU_ACCESS_READ  uint32 = 0x20000
)

const (
	D3D11_INPUT_PER_VERTEX_DATA   uint32 = 0
	D3D11_INPUT_PER_INSTANCE_DATA uint32 = 1
)

const (
	D3D11_PRIMITIVE_TOPOLOGY_UNDEFINED     uint32 = 0
	D3D11_PRIMITIVE_TOPOLOGY_POINTLIST     uint32 = 1
	D3D11_PRIMITIVE_TOPOLOGY_LINELIST      uint32 = 2
	D3D11_PRIMITIVE_TOPOLOGY_LINESTRIP     uint32 = 3
	D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST  uint32 = 4
	D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP uint32 = 5
)

const (
	D3D11_MAP_READ               uint32 = 1
	D3D11_MAP_WRITE              uint32 = 2
	D3D11_MAP_READ_WRITE         uint32 = 3
	D3D11_MAP_WRITE_DISCARD      uint32 = 4
	D3D11_MAP_WRITE_NO_OVERWRITE uint32 = 5
)

const (
	D3D11_CLEAR_DEPTH   uint32 = 0x1
	D3D11_CLEAR_STENCIL uint32 = 0x2
)

const (
	D3D11_RTV_DIMENSION_TEXTURE2D uint32 = 3
	D3D11_DSV_DIMENSION_TEXTURE2D uint32 = 3
	D3D11_SRV_DIMENSION_TEXTURE2D uint32 = 3
)

type D3D11_BUFFER_DESC struct {
	ByteWidth           uint32
	Usage               uint32
	BindFlags           uint32
	CPUAccessFlags      uint32
	MiscFlags           uint32
	StructureByteStride uint32
}

type D3D11_TEXTURE2D_DESC struct {
	Width          uint32
	Height         uint32
	MipLevels      uint32
	ArraySize      uint32
	Format         uint32
	SampleCount    uint32
	SampleQuality  uint32
	Usage          uint32
	BindFlags      uint32
	CPUAccessFlags uint32
	MiscFlags      uint32
}

type D3D11_SUBRESOURCE_DATA struct {
	PSysMem          uint64
	SysMemPitch      uint32
	SysMemSlicePitch uint32
}

type D3D11_BOX struct {
	Left   uint32
	Top    uint32
	Front  uint32
	Right  uint32
	Bottom uint32
	Back   uint32
}

type D3D11_VIEWPORT struct {
	TopLeftX float32
	TopLeftY float32
	Width    float32
	Height   float32
	MinDepth float32
	MaxDepth float32
}

type D3D11_RECT struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

type D3D11_INPUT_ELEMENT_DESC struct {
	SemanticName         uint64
	SemanticIndex        uint32
	Format               uint32
	InputSlot            uint32
	AlignedByteOffset    uint32
	InputSlotClass       uint32
	InstanceDataStepRate uint32
}

type D3D11_SAMPLER_DESC struct {
	Filter         uint32
	AddressU       uint32
	AddressV       uint32
	AddressW       uint32
	MipLODBias     float32
	MaxAnisotropy  uint32
	ComparisonFunc uint32
	BorderColor    [4]float32
	MinLOD         float32
	MaxLOD         float32
}

type D3D11_RENDER_TARGET_BLEND_DESC struct {
	BlendEnable           uint32
	SrcBlend              uint32
	DestBlend             uint32
	BlendOp               uint32
	SrcBlendAlpha         uint32
	DestBlendAlpha        uint32
	BlendOpAlpha          uint32
	RenderTargetWriteMask uint8
	_                     [3]byte
}

type D3D11_BLEND_DESC struct {
	AlphaToCoverageEnable  uint32
	IndependentBlendEnable uint32
	RenderTarget           [8]D3D11_RENDER_TARGET_BLEND_DESC
}

type D3D11_RASTERIZER_DESC struct {
	FillMode              uint32
	CullMode              uint32
	FrontCounterClockwise uint32
	DepthBias             int32
	DepthBiasClamp        float32
	SlopeScaledDepthBias  float32
	DepthClipEnable       uint32
	ScissorEnable         uint32
	MultisampleEnable     uint32
	AntialiasedLineEnable uint32
}

type D3D11_DEPTH_STENCILOP_DESC struct {
	StencilFailOp      uint32
	StencilDepthFailOp uint32
	StencilPassOp      uint32
	StencilFunc        uint32
}

type D3D11_DEPTH_STENCIL_DESC struct {
	DepthEnable      uint32
	DepthWriteMask   uint32
	DepthFunc        uint32
	StencilEnable    uint32
	StencilReadMask  uint8
	StencilWriteMask uint8
	_                [2]byte
	FrontFace        D3D11_DEPTH_STENCILOP_DESC
	BackFace         D3D11_DEPTH_STENCILOP_DESC
}

type D3D11_RENDER_TARGET_VIEW_DESC struct {
	Format        uint32
	ViewDimension uint32
	MipSlice      uint32
}

type D3D11_DEPTH_STENCIL_VIEW_DESC struct {
	Format        uint32
	ViewDimension uint32
	Flags         uint32
	MipSlice      uint32
}

type D3D11_SHADER_RESOURCE_VIEW_DESC struct {
	Format          uint32
	ViewDimension   uint32
	MostDetailedMip uint32
	MipLevels       uint32
}

type D3D11_MAPPED_SUBRESOURCE struct {
	PData      uint64
	RowPitch   uint32
	DepthPitch uint32
}
