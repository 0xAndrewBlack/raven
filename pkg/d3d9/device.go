//go:build guest_windows

package d3d9

import "math"

type Device struct {
	RenderStates       map[uint32]uint32
	TextureStageStates [8]map[uint32]uint32
	SamplerStates      [16]map[uint32]uint32
	Transforms         map[uint32][16]float32
	Viewport           Viewport
	ScissorRect        Rect
	VertexDeclaration  []VertexElement
	CurrentVertexDecl  *VertexDeclaration
	FVF                uint32
	CurrentTextures    [8]*Texture
	StreamSources      [16]StreamSource
	IndexBuffer        *IndexBuffer
	Material           D3DMATERIAL9
	Lights             map[uint32]D3DLIGHT9
	LightEnabled       map[uint32]bool
	ClipPlanes         [6][4]float32
	SceneActive        bool
	ClearColor         uint32
	ClearFlags         uint32
	ClearDepth         float32
	ClearStencil       uint32

	// Programmable-shader state (SM1.x/2.0). VSConstants holds the c#
	// float constant registers set via SetVertexShaderConstantF; a bound
	// vertex shader (CurrentVertexShader != nil) makes the renderer use the
	// translated SPIR-V module and feed VSConstants instead of the fixed
	// transform pipeline.
	VSConstants        [256][4]float32
	PSConstants        [256][4]float32
	CurrentVertexShader *ShaderProgram
	CurrentPixelShader  *ShaderProgram
}

// ShaderProgram is a translated D3D9 programmable shader: the parsed SM
// program plus its compiled SPIR-V and (lazily) its Vulkan module handle.
type ShaderProgram struct {
	Parsed   *Shader
	SPIRV    []byte
	VkModule uint64 // vk.ShaderModule handle, 0 until created
}

func NewDevice() *Device {
	d := &Device{
		RenderStates: make(map[uint32]uint32),
		Transforms:   make(map[uint32][16]float32),
		Viewport:     Viewport{MinZ: 0, MaxZ: 1},
		Material: D3DMATERIAL9{
			Diffuse:  ColorValue{R: 1, G: 1, B: 1, A: 1},
			Ambient:  ColorValue{R: 1, G: 1, B: 1, A: 1},
			Specular: ColorValue{R: 0, G: 0, B: 0, A: 1},
			Emissive: ColorValue{R: 0, G: 0, B: 0, A: 1},
			Power:    0,
		},
		Lights:       make(map[uint32]D3DLIGHT9),
		LightEnabled: make(map[uint32]bool),
		ClearDepth:   1,
	}

	d.RenderStates[D3DRS_ZENABLE] = D3DZB_TRUE
	d.RenderStates[D3DRS_FILLMODE] = D3DFILL_SOLID
	d.RenderStates[D3DRS_SHADEMODE] = D3DSHADE_GOURAUD
	d.RenderStates[D3DRS_ZWRITEENABLE] = 1
	d.RenderStates[D3DRS_ALPHATESTENABLE] = 0
	d.RenderStates[D3DRS_LASTPIXEL] = 1
	d.RenderStates[D3DRS_SRCBLEND] = D3DBLEND_ONE
	d.RenderStates[D3DRS_DESTBLEND] = D3DBLEND_ZERO
	d.RenderStates[D3DRS_CULLMODE] = D3DCULL_CCW
	d.RenderStates[D3DRS_ZFUNC] = D3DCMP_LESSEQUAL
	d.RenderStates[D3DRS_ALPHAREF] = 0
	d.RenderStates[D3DRS_ALPHAFUNC] = D3DCMP_ALWAYS
	d.RenderStates[D3DRS_DITHERENABLE] = 0
	d.RenderStates[D3DRS_ALPHABLENDENABLE] = 0
	d.RenderStates[D3DRS_FOGENABLE] = 0
	d.RenderStates[D3DRS_SPECULARENABLE] = 0
	d.RenderStates[D3DRS_FOGCOLOR] = 0
	d.RenderStates[D3DRS_FOGTABLEMODE] = D3DFOG_NONE
	d.RenderStates[D3DRS_FOGSTART] = math.Float32bits(0)
	d.RenderStates[D3DRS_FOGEND] = math.Float32bits(1)
	d.RenderStates[D3DRS_FOGDENSITY] = math.Float32bits(1)
	d.RenderStates[D3DRS_RANGEFOGENABLE] = 0
	d.RenderStates[D3DRS_STENCILENABLE] = 0
	d.RenderStates[D3DRS_STENCILFAIL] = D3DSTENCILOP_KEEP
	d.RenderStates[D3DRS_STENCILZFAIL] = D3DSTENCILOP_KEEP
	d.RenderStates[D3DRS_STENCILPASS] = D3DSTENCILOP_KEEP
	d.RenderStates[D3DRS_STENCILFUNC] = D3DCMP_ALWAYS
	d.RenderStates[D3DRS_STENCILREF] = 0
	d.RenderStates[D3DRS_STENCILMASK] = 0xffffffff
	d.RenderStates[D3DRS_STENCILWRITEMASK] = 0xffffffff
	d.RenderStates[D3DRS_TEXTUREFACTOR] = 0xffffffff
	d.RenderStates[D3DRS_CLIPPING] = 1
	d.RenderStates[D3DRS_LIGHTING] = 1
	d.RenderStates[D3DRS_AMBIENT] = 0
	d.RenderStates[D3DRS_FOGVERTEXMODE] = D3DFOG_NONE
	d.RenderStates[D3DRS_COLORVERTEX] = 1
	d.RenderStates[D3DRS_LOCALVIEWER] = 1
	d.RenderStates[D3DRS_NORMALIZENORMALS] = 0
	d.RenderStates[D3DRS_DIFFUSEMATERIALSOURCE] = D3DMCS_COLOR1
	d.RenderStates[D3DRS_SPECULARMATERIALSOURCE] = D3DMCS_COLOR2
	d.RenderStates[D3DRS_AMBIENTMATERIALSOURCE] = D3DMCS_MATERIAL
	d.RenderStates[D3DRS_EMISSIVEMATERIALSOURCE] = D3DMCS_MATERIAL
	d.RenderStates[D3DRS_VERTEXBLEND] = 0
	d.RenderStates[D3DRS_CLIPPLANEENABLE] = 0
	d.RenderStates[D3DRS_POINTSIZE] = math.Float32bits(1)
	d.RenderStates[D3DRS_POINTSIZE_MIN] = math.Float32bits(1)
	d.RenderStates[D3DRS_POINTSPRITEENABLE] = 0
	d.RenderStates[D3DRS_POINTSCALEENABLE] = 0
	d.RenderStates[D3DRS_POINTSCALE_A] = math.Float32bits(1)
	d.RenderStates[D3DRS_POINTSCALE_B] = 0
	d.RenderStates[D3DRS_POINTSCALE_C] = 0
	d.RenderStates[D3DRS_MULTISAMPLEANTIALIAS] = 1
	d.RenderStates[D3DRS_MULTISAMPLEMASK] = 0xffffffff
	d.RenderStates[D3DRS_PATCHEDGESTYLE] = 0
	d.RenderStates[D3DRS_POINTSIZE_MAX] = math.Float32bits(64)
	d.RenderStates[D3DRS_INDEXEDVERTEXBLENDENABLE] = 0
	d.RenderStates[D3DRS_COLORWRITEENABLE] = 0x0f
	d.RenderStates[D3DRS_TWEENFACTOR] = 0
	d.RenderStates[D3DRS_BLENDOP] = D3DBLENDOP_ADD
	d.RenderStates[D3DRS_SCISSORTESTENABLE] = 0
	d.RenderStates[D3DRS_SLOPESCALEDEPTHBIAS] = 0
	d.RenderStates[D3DRS_ANTIALIASEDLINEENABLE] = 0
	d.RenderStates[D3DRS_MINTESSELLATIONLEVEL] = math.Float32bits(1)
	d.RenderStates[D3DRS_MAXTESSELLATIONLEVEL] = math.Float32bits(1)
	d.RenderStates[D3DRS_ENABLEADAPTIVETESSELLATION] = 0
	d.RenderStates[D3DRS_TWOSIDEDSTENCILMODE] = 0
	d.RenderStates[D3DRS_CCW_STENCILFAIL] = D3DSTENCILOP_KEEP
	d.RenderStates[D3DRS_CCW_STENCILZFAIL] = D3DSTENCILOP_KEEP
	d.RenderStates[D3DRS_CCW_STENCILPASS] = D3DSTENCILOP_KEEP
	d.RenderStates[D3DRS_CCW_STENCILFUNC] = D3DCMP_ALWAYS
	d.RenderStates[D3DRS_COLORWRITEENABLE1] = 0x0f
	d.RenderStates[D3DRS_COLORWRITEENABLE2] = 0x0f
	d.RenderStates[D3DRS_COLORWRITEENABLE3] = 0x0f
	d.RenderStates[D3DRS_BLENDFACTOR] = 0xffffffff
	d.RenderStates[D3DRS_SRGBWRITEENABLE] = 0
	d.RenderStates[D3DRS_DEPTHBIAS] = 0
	d.RenderStates[D3DRS_SEPARATEALPHABLENDENABLE] = 0
	d.RenderStates[D3DRS_SRCBLENDALPHA] = D3DBLEND_ONE
	d.RenderStates[D3DRS_DESTBLENDALPHA] = D3DBLEND_ZERO
	d.RenderStates[D3DRS_BLENDOPALPHA] = D3DBLENDOP_ADD

	for i := range d.TextureStageStates {
		stage := map[uint32]uint32{
			D3DTSS_COLORARG1:             D3DTA_TEXTURE,
			D3DTSS_COLORARG2:             D3DTA_CURRENT,
			D3DTSS_ALPHAARG1:             D3DTA_TEXTURE,
			D3DTSS_ALPHAARG2:             D3DTA_CURRENT,
			D3DTSS_TEXCOORDINDEX:         uint32(i),
			D3DTSS_TEXTURETRANSFORMFLAGS: 0,
			D3DTSS_COLORARG0:             D3DTA_CURRENT,
			D3DTSS_ALPHAARG0:             D3DTA_CURRENT,
			D3DTSS_RESULTARG:             D3DTA_CURRENT,
			D3DTSS_CONSTANT:              0,
		}
		if i == 0 {
			stage[D3DTSS_COLOROP] = D3DTOP_MODULATE
			stage[D3DTSS_ALPHAOP] = D3DTOP_SELECTARG1
		} else {
			stage[D3DTSS_COLOROP] = D3DTOP_DISABLE
			stage[D3DTSS_ALPHAOP] = D3DTOP_DISABLE
		}
		d.TextureStageStates[i] = stage
	}

	for i := range d.SamplerStates {
		d.SamplerStates[i] = map[uint32]uint32{
			D3DSAMP_ADDRESSU:      D3DTADDRESS_WRAP,
			D3DSAMP_ADDRESSV:      D3DTADDRESS_WRAP,
			D3DSAMP_ADDRESSW:      D3DTADDRESS_WRAP,
			D3DSAMP_BORDERCOLOR:   0,
			D3DSAMP_MAGFILTER:     D3DTEXF_POINT,
			D3DSAMP_MINFILTER:     D3DTEXF_POINT,
			D3DSAMP_MIPFILTER:     D3DTEXF_NONE,
			D3DSAMP_MIPMAPLODBIAS: 0,
			D3DSAMP_MAXMIPLEVEL:   0,
			D3DSAMP_MAXANISOTROPY: 1,
			D3DSAMP_SRGBTEXTURE:   0,
			D3DSAMP_ELEMENTINDEX:  0,
			D3DSAMP_DMAPOFFSET:    0,
		}
	}

	identity := [16]float32{
		1, 0, 0, 0,
		0, 1, 0, 0,
		0, 0, 1, 0,
		0, 0, 0, 1,
	}
	for _, transform := range []uint32{
		D3DTS_WORLD, D3DTS_WORLD1, D3DTS_WORLD2, D3DTS_WORLD3,
		D3DTS_VIEW, D3DTS_PROJECTION,
		D3DTS_TEXTURE0, D3DTS_TEXTURE1, D3DTS_TEXTURE2, D3DTS_TEXTURE3,
		D3DTS_TEXTURE4, D3DTS_TEXTURE5, D3DTS_TEXTURE6, D3DTS_TEXTURE7,
	} {
		d.Transforms[transform] = identity
	}

	return d
}

func (d *Device) SetRenderState(state, value uint32) {
	d.RenderStates[state] = value
}

func (d *Device) GetRenderState(state uint32) uint32 {
	return d.RenderStates[state]
}

func (d *Device) SetTextureStageState(stage, typ, value uint32) {
	if stage >= uint32(len(d.TextureStageStates)) {
		return
	}
	if d.TextureStageStates[stage] == nil {
		d.TextureStageStates[stage] = make(map[uint32]uint32)
	}
	d.TextureStageStates[stage][typ] = value
}

func (d *Device) SetSamplerState(sampler, typ, value uint32) {
	if sampler >= uint32(len(d.SamplerStates)) {
		return
	}
	if d.SamplerStates[sampler] == nil {
		d.SamplerStates[sampler] = make(map[uint32]uint32)
	}
	d.SamplerStates[sampler][typ] = value
}

func (d *Device) SetTransform(typ uint32, matrix [16]float32) {
	d.Transforms[typ] = matrix
}

func (d *Device) SetViewport(vp Viewport) {
	d.Viewport = vp
}
