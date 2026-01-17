package d3d9

const (
	D3DCLEAR_TARGET  uint32 = 0x00000001
	D3DCLEAR_ZBUFFER uint32 = 0x00000002
	D3DCLEAR_STENCIL uint32 = 0x00000004
)

const (
	D3DZB_FALSE uint32 = 0
	D3DZB_TRUE  uint32 = 1
	D3DZB_USEW  uint32 = 2
)

const (
	D3DFILL_POINT     uint32 = 1
	D3DFILL_WIREFRAME uint32 = 2
	D3DFILL_SOLID     uint32 = 3
)

const (
	D3DSHADE_FLAT    uint32 = 1
	D3DSHADE_GOURAUD uint32 = 2
	D3DSHADE_PHONG   uint32 = 3
)

const (
	D3DBLEND_ZERO            uint32 = 1
	D3DBLEND_ONE             uint32 = 2
	D3DBLEND_SRCCOLOR        uint32 = 3
	D3DBLEND_INVSRCCOLOR     uint32 = 4
	D3DBLEND_SRCALPHA        uint32 = 5
	D3DBLEND_INVSRCALPHA     uint32 = 6
	D3DBLEND_DESTALPHA       uint32 = 7
	D3DBLEND_INVDESTALPHA    uint32 = 8
	D3DBLEND_DESTCOLOR       uint32 = 9
	D3DBLEND_INVDESTCOLOR    uint32 = 10
	D3DBLEND_SRCALPHASAT     uint32 = 11
	D3DBLEND_BOTHSRCALPHA    uint32 = 12
	D3DBLEND_BOTHINVSRCALPHA uint32 = 13
	D3DBLEND_BLENDFACTOR     uint32 = 14
	D3DBLEND_INVBLENDFACTOR  uint32 = 15
	D3DBLEND_SRCCOLOR2       uint32 = 16
	D3DBLEND_INVSRCCOLOR2    uint32 = 17
)

const (
	D3DBLENDOP_ADD         uint32 = 1
	D3DBLENDOP_SUBTRACT    uint32 = 2
	D3DBLENDOP_REVSUBTRACT uint32 = 3
	D3DBLENDOP_MIN         uint32 = 4
	D3DBLENDOP_MAX         uint32 = 5
)

const (
	D3DCULL_NONE uint32 = 1
	D3DCULL_CW   uint32 = 2
	D3DCULL_CCW  uint32 = 3
)

const (
	D3DCMP_NEVER        uint32 = 1
	D3DCMP_LESS         uint32 = 2
	D3DCMP_EQUAL        uint32 = 3
	D3DCMP_LESSEQUAL    uint32 = 4
	D3DCMP_GREATER      uint32 = 5
	D3DCMP_NOTEQUAL     uint32 = 6
	D3DCMP_GREATEREQUAL uint32 = 7
	D3DCMP_ALWAYS       uint32 = 8
)

const (
	D3DFOG_NONE   uint32 = 0
	D3DFOG_EXP    uint32 = 1
	D3DFOG_EXP2   uint32 = 2
	D3DFOG_LINEAR uint32 = 3
)

const (
	D3DSTENCILOP_KEEP    uint32 = 1
	D3DSTENCILOP_ZERO    uint32 = 2
	D3DSTENCILOP_REPLACE uint32 = 3
	D3DSTENCILOP_INCRSAT uint32 = 4
	D3DSTENCILOP_DECRSAT uint32 = 5
	D3DSTENCILOP_INVERT  uint32 = 6
	D3DSTENCILOP_INCR    uint32 = 7
	D3DSTENCILOP_DECR    uint32 = 8
)

const (
	D3DMCS_MATERIAL uint32 = 0
	D3DMCS_COLOR1   uint32 = 1
	D3DMCS_COLOR2   uint32 = 2
)

const (
	D3DTADDRESS_WRAP       uint32 = 1
	D3DTADDRESS_MIRROR     uint32 = 2
	D3DTADDRESS_CLAMP      uint32 = 3
	D3DTADDRESS_BORDER     uint32 = 4
	D3DTADDRESS_MIRRORONCE uint32 = 5
)

const (
	D3DTEXF_NONE            uint32 = 0
	D3DTEXF_POINT           uint32 = 1
	D3DTEXF_LINEAR          uint32 = 2
	D3DTEXF_ANISOTROPIC     uint32 = 3
	D3DTEXF_FLATCUBIC       uint32 = 4
	D3DTEXF_GAUSSIANCUBIC   uint32 = 5
	D3DTEXF_PYRAMIDALQUAD   uint32 = 6
	D3DTEXF_GAUSSIANQUAD    uint32 = 7
	D3DTEXF_CONVOLUTIONMONO uint32 = 8
)

const (
	D3DTOP_DISABLE                   uint32 = 1
	D3DTOP_SELECTARG1                uint32 = 2
	D3DTOP_SELECTARG2                uint32 = 3
	D3DTOP_MODULATE                  uint32 = 4
	D3DTOP_MODULATE2X                uint32 = 5
	D3DTOP_MODULATE4X                uint32 = 6
	D3DTOP_ADD                       uint32 = 7
	D3DTOP_ADDSIGNED                 uint32 = 8
	D3DTOP_ADDSIGNED2X               uint32 = 9
	D3DTOP_SUBTRACT                  uint32 = 10
	D3DTOP_ADDSMOOTH                 uint32 = 11
	D3DTOP_BLENDDIFFUSEALPHA         uint32 = 12
	D3DTOP_BLENDTEXTUREALPHA         uint32 = 13
	D3DTOP_BLENDFACTORALPHA          uint32 = 14
	D3DTOP_BLENDTEXTUREALPHAPM       uint32 = 15
	D3DTOP_BLENDCURRENTALPHA         uint32 = 16
	D3DTOP_PREMODULATE               uint32 = 17
	D3DTOP_MODULATEALPHA_ADDCOLOR    uint32 = 18
	D3DTOP_MODULATECOLOR_ADDALPHA    uint32 = 19
	D3DTOP_MODULATEINVALPHA_ADDCOLOR uint32 = 20
	D3DTOP_MODULATEINVCOLOR_ADDALPHA uint32 = 21
	D3DTOP_BUMPENVMAP                uint32 = 22
	D3DTOP_BUMPENVMAPLUMINANCE       uint32 = 23
	D3DTOP_DOTPRODUCT3               uint32 = 24
	D3DTOP_MULTIPLYADD               uint32 = 25
	D3DTOP_LERP                      uint32 = 26
)

const (
	D3DTA_SELECTMASK     uint32 = 0x0000000f
	D3DTA_DIFFUSE        uint32 = 0x00000000
	D3DTA_CURRENT        uint32 = 0x00000001
	D3DTA_TEXTURE        uint32 = 0x00000002
	D3DTA_TFACTOR        uint32 = 0x00000003
	D3DTA_SPECULAR       uint32 = 0x00000004
	D3DTA_TEMP           uint32 = 0x00000005
	D3DTA_CONSTANT       uint32 = 0x00000006
	D3DTA_COMPLEMENT     uint32 = 0x00000010
	D3DTA_ALPHAREPLICATE uint32 = 0x00000020
)

const (
	D3DRTYPE_SURFACE       uint32 = 1
	D3DRTYPE_VOLUME        uint32 = 2
	D3DRTYPE_TEXTURE       uint32 = 3
	D3DRTYPE_VOLUMETEXTURE uint32 = 4
	D3DRTYPE_CUBETEXTURE   uint32 = 5
	D3DRTYPE_VERTEXBUFFER  uint32 = 6
	D3DRTYPE_INDEXBUFFER   uint32 = 7
)

const (
	D3DRS_ZENABLE                    uint32 = 7
	D3DRS_FILLMODE                   uint32 = 8
	D3DRS_SHADEMODE                  uint32 = 9
	D3DRS_ZWRITEENABLE               uint32 = 14
	D3DRS_ALPHATESTENABLE            uint32 = 15
	D3DRS_LASTPIXEL                  uint32 = 16
	D3DRS_SRCBLEND                   uint32 = 19
	D3DRS_DESTBLEND                  uint32 = 20
	D3DRS_CULLMODE                   uint32 = 22
	D3DRS_ZFUNC                      uint32 = 23
	D3DRS_ALPHAREF                   uint32 = 24
	D3DRS_ALPHAFUNC                  uint32 = 25
	D3DRS_DITHERENABLE               uint32 = 26
	D3DRS_ALPHABLENDENABLE           uint32 = 27
	D3DRS_FOGENABLE                  uint32 = 28
	D3DRS_SPECULARENABLE             uint32 = 29
	D3DRS_FOGCOLOR                   uint32 = 34
	D3DRS_FOGTABLEMODE               uint32 = 35
	D3DRS_FOGSTART                   uint32 = 36
	D3DRS_FOGEND                     uint32 = 37
	D3DRS_FOGDENSITY                 uint32 = 38
	D3DRS_RANGEFOGENABLE             uint32 = 48
	D3DRS_STENCILENABLE              uint32 = 52
	D3DRS_STENCILFAIL                uint32 = 53
	D3DRS_STENCILZFAIL               uint32 = 54
	D3DRS_STENCILPASS                uint32 = 55
	D3DRS_STENCILFUNC                uint32 = 56
	D3DRS_STENCILREF                 uint32 = 57
	D3DRS_STENCILMASK                uint32 = 58
	D3DRS_STENCILWRITEMASK           uint32 = 59
	D3DRS_TEXTUREFACTOR              uint32 = 60
	D3DRS_WRAP0                      uint32 = 128
	D3DRS_WRAP1                      uint32 = 129
	D3DRS_WRAP2                      uint32 = 130
	D3DRS_WRAP3                      uint32 = 131
	D3DRS_WRAP4                      uint32 = 132
	D3DRS_WRAP5                      uint32 = 133
	D3DRS_WRAP6                      uint32 = 134
	D3DRS_WRAP7                      uint32 = 135
	D3DRS_CLIPPING                   uint32 = 136
	D3DRS_LIGHTING                   uint32 = 137
	D3DRS_AMBIENT                    uint32 = 139
	D3DRS_FOGVERTEXMODE              uint32 = 140
	D3DRS_COLORVERTEX                uint32 = 141
	D3DRS_LOCALVIEWER                uint32 = 142
	D3DRS_NORMALIZENORMALS           uint32 = 143
	D3DRS_DIFFUSEMATERIALSOURCE      uint32 = 145
	D3DRS_SPECULARMATERIALSOURCE     uint32 = 146
	D3DRS_AMBIENTMATERIALSOURCE      uint32 = 147
	D3DRS_EMISSIVEMATERIALSOURCE     uint32 = 148
	D3DRS_VERTEXBLEND                uint32 = 151
	D3DRS_CLIPPLANEENABLE            uint32 = 152
	D3DRS_POINTSIZE                  uint32 = 154
	D3DRS_POINTSIZE_MIN              uint32 = 155
	D3DRS_POINTSPRITEENABLE          uint32 = 156
	D3DRS_POINTSCALEENABLE           uint32 = 157
	D3DRS_POINTSCALE_A               uint32 = 158
	D3DRS_POINTSCALE_B               uint32 = 159
	D3DRS_POINTSCALE_C               uint32 = 160
	D3DRS_MULTISAMPLEANTIALIAS       uint32 = 161
	D3DRS_MULTISAMPLEMASK            uint32 = 162
	D3DRS_PATCHEDGESTYLE             uint32 = 163
	D3DRS_DEBUGMONITORTOKEN          uint32 = 165
	D3DRS_POINTSIZE_MAX              uint32 = 166
	D3DRS_INDEXEDVERTEXBLENDENABLE   uint32 = 167
	D3DRS_COLORWRITEENABLE           uint32 = 168
	D3DRS_TWEENFACTOR                uint32 = 170
	D3DRS_BLENDOP                    uint32 = 171
	D3DRS_POSITIONDEGREE             uint32 = 172
	D3DRS_NORMALDEGREE               uint32 = 173
	D3DRS_SCISSORTESTENABLE          uint32 = 174
	D3DRS_SLOPESCALEDEPTHBIAS        uint32 = 175
	D3DRS_ANTIALIASEDLINEENABLE      uint32 = 176
	D3DRS_MINTESSELLATIONLEVEL       uint32 = 178
	D3DRS_MAXTESSELLATIONLEVEL       uint32 = 179
	D3DRS_ADAPTIVETESS_X             uint32 = 180
	D3DRS_ADAPTIVETESS_Y             uint32 = 181
	D3DRS_ADAPTIVETESS_Z             uint32 = 182
	D3DRS_ADAPTIVETESS_W             uint32 = 183
	D3DRS_ENABLEADAPTIVETESSELLATION uint32 = 184
	D3DRS_TWOSIDEDSTENCILMODE        uint32 = 185
	D3DRS_CCW_STENCILFAIL            uint32 = 186
	D3DRS_CCW_STENCILZFAIL           uint32 = 187
	D3DRS_CCW_STENCILPASS            uint32 = 188
	D3DRS_CCW_STENCILFUNC            uint32 = 189
	D3DRS_COLORWRITEENABLE1          uint32 = 190
	D3DRS_COLORWRITEENABLE2          uint32 = 191
	D3DRS_COLORWRITEENABLE3          uint32 = 192
	D3DRS_BLENDFACTOR                uint32 = 193
	D3DRS_SRGBWRITEENABLE            uint32 = 194
	D3DRS_DEPTHBIAS                  uint32 = 195
	D3DRS_WRAP8                      uint32 = 198
	D3DRS_WRAP9                      uint32 = 199
	D3DRS_WRAP10                     uint32 = 200
	D3DRS_WRAP11                     uint32 = 201
	D3DRS_WRAP12                     uint32 = 202
	D3DRS_WRAP13                     uint32 = 203
	D3DRS_WRAP14                     uint32 = 204
	D3DRS_WRAP15                     uint32 = 205
	D3DRS_SEPARATEALPHABLENDENABLE   uint32 = 206
	D3DRS_SRCBLENDALPHA              uint32 = 207
	D3DRS_DESTBLENDALPHA             uint32 = 208
	D3DRS_BLENDOPALPHA               uint32 = 209
)

const (
	D3DTSS_COLOROP               uint32 = 1
	D3DTSS_COLORARG1             uint32 = 2
	D3DTSS_COLORARG2             uint32 = 3
	D3DTSS_ALPHAOP               uint32 = 4
	D3DTSS_ALPHAARG1             uint32 = 5
	D3DTSS_ALPHAARG2             uint32 = 6
	D3DTSS_BUMPENVMAT00          uint32 = 7
	D3DTSS_BUMPENVMAT01          uint32 = 8
	D3DTSS_BUMPENVMAT10          uint32 = 9
	D3DTSS_BUMPENVMAT11          uint32 = 10
	D3DTSS_TEXCOORDINDEX         uint32 = 11
	D3DTSS_BUMPENVLSCALE         uint32 = 22
	D3DTSS_BUMPENVLOFFSET        uint32 = 23
	D3DTSS_TEXTURETRANSFORMFLAGS uint32 = 24
	D3DTSS_COLORARG0             uint32 = 26
	D3DTSS_ALPHAARG0             uint32 = 27
	D3DTSS_RESULTARG             uint32 = 28
	D3DTSS_CONSTANT              uint32 = 32
	D3DTSS_TCI_PASSTHRU          uint32 = 0x00000
)

const (
	D3DSAMP_ADDRESSU      uint32 = 1
	D3DSAMP_ADDRESSV      uint32 = 2
	D3DSAMP_ADDRESSW      uint32 = 3
	D3DSAMP_BORDERCOLOR   uint32 = 4
	D3DSAMP_MAGFILTER     uint32 = 5
	D3DSAMP_MINFILTER     uint32 = 6
	D3DSAMP_MIPFILTER     uint32 = 7
	D3DSAMP_MIPMAPLODBIAS uint32 = 8
	D3DSAMP_MAXMIPLEVEL   uint32 = 9
	D3DSAMP_MAXANISOTROPY uint32 = 10
	D3DSAMP_SRGBTEXTURE   uint32 = 11
	D3DSAMP_ELEMENTINDEX  uint32 = 12
	D3DSAMP_DMAPOFFSET    uint32 = 13
)

const (
	D3DTS_VIEW       uint32 = 2
	D3DTS_PROJECTION uint32 = 3
	D3DTS_TEXTURE0   uint32 = 16
	D3DTS_TEXTURE1   uint32 = 17
	D3DTS_TEXTURE2   uint32 = 18
	D3DTS_TEXTURE3   uint32 = 19
	D3DTS_TEXTURE4   uint32 = 20
	D3DTS_TEXTURE5   uint32 = 21
	D3DTS_TEXTURE6   uint32 = 22
	D3DTS_TEXTURE7   uint32 = 23
	D3DTS_WORLD      uint32 = 256
	D3DTS_WORLD1     uint32 = 257
	D3DTS_WORLD2     uint32 = 258
	D3DTS_WORLD3     uint32 = 259
)

const (
	D3DFMT_UNKNOWN             uint32 = 0
	D3DFMT_R8G8B8              uint32 = 20
	D3DFMT_A8R8G8B8            uint32 = 21
	D3DFMT_X8R8G8B8            uint32 = 22
	D3DFMT_R5G6B5              uint32 = 23
	D3DFMT_X1R5G5B5            uint32 = 24
	D3DFMT_A1R5G5B5            uint32 = 25
	D3DFMT_A4R4G4B4            uint32 = 26
	D3DFMT_R3G3B2              uint32 = 27
	D3DFMT_A8                  uint32 = 28
	D3DFMT_A8R3G3B2            uint32 = 29
	D3DFMT_X4R4G4B4            uint32 = 30
	D3DFMT_A2B10G10R10         uint32 = 31
	D3DFMT_A8B8G8R8            uint32 = 32
	D3DFMT_X8B8G8R8            uint32 = 33
	D3DFMT_G16R16              uint32 = 34
	D3DFMT_A2R10G10B10         uint32 = 35
	D3DFMT_A16B16G16R16        uint32 = 36
	D3DFMT_A8P8                uint32 = 40
	D3DFMT_P8                  uint32 = 41
	D3DFMT_L8                  uint32 = 50
	D3DFMT_A8L8                uint32 = 51
	D3DFMT_A4L4                uint32 = 52
	D3DFMT_V8U8                uint32 = 60
	D3DFMT_L6V5U5              uint32 = 61
	D3DFMT_X8L8V8U8            uint32 = 62
	D3DFMT_Q8W8V8U8            uint32 = 63
	D3DFMT_V16U16              uint32 = 64
	D3DFMT_A2W10V10U10         uint32 = 67
	D3DFMT_UYVY                uint32 = uint32('U') | uint32('Y')<<8 | uint32('V')<<16 | uint32('Y')<<24
	D3DFMT_YUY2                uint32 = uint32('Y') | uint32('U')<<8 | uint32('Y')<<16 | uint32('2')<<24
	D3DFMT_DXT1                uint32 = uint32('D') | uint32('X')<<8 | uint32('T')<<16 | uint32('1')<<24
	D3DFMT_DXT2                uint32 = uint32('D') | uint32('X')<<8 | uint32('T')<<16 | uint32('2')<<24
	D3DFMT_DXT3                uint32 = uint32('D') | uint32('X')<<8 | uint32('T')<<16 | uint32('3')<<24
	D3DFMT_DXT4                uint32 = uint32('D') | uint32('X')<<8 | uint32('T')<<16 | uint32('4')<<24
	D3DFMT_DXT5                uint32 = uint32('D') | uint32('X')<<8 | uint32('T')<<16 | uint32('5')<<24
	D3DFMT_MULTI2_ARGB8        uint32 = uint32('M') | uint32('E')<<8 | uint32('T')<<16 | uint32('1')<<24
	D3DFMT_G8R8_G8B8           uint32 = uint32('G') | uint32('R')<<8 | uint32('G')<<16 | uint32('B')<<24
	D3DFMT_R8G8_B8G8           uint32 = uint32('R') | uint32('G')<<8 | uint32('B')<<16 | uint32('G')<<24
	D3DFMT_D16_LOCKABLE        uint32 = 70
	D3DFMT_D32                 uint32 = 71
	D3DFMT_D15S1               uint32 = 73
	D3DFMT_D24S8               uint32 = 75
	D3DFMT_D24X8               uint32 = 77
	D3DFMT_D24X4S4             uint32 = 79
	D3DFMT_D16                 uint32 = 80
	D3DFMT_L16                 uint32 = 81
	D3DFMT_D32F_LOCKABLE       uint32 = 82
	D3DFMT_D24FS8              uint32 = 83
	D3DFMT_D32_LOCKABLE        uint32 = 84
	D3DFMT_S8_LOCKABLE         uint32 = 85
	D3DFMT_VERTEXDATA          uint32 = 100
	D3DFMT_INDEX16             uint32 = 101
	D3DFMT_INDEX32             uint32 = 102
	D3DFMT_Q16W16V16U16        uint32 = 110
	D3DFMT_R16F                uint32 = 111
	D3DFMT_G16R16F             uint32 = 112
	D3DFMT_A16B16G16R16F       uint32 = 113
	D3DFMT_R32F                uint32 = 114
	D3DFMT_G32R32F             uint32 = 115
	D3DFMT_A32B32G32R32F       uint32 = 116
	D3DFMT_CxV8U8              uint32 = 117
	D3DFMT_A1                  uint32 = 118
	D3DFMT_A2B10G10R10_XR_BIAS uint32 = 119
	D3DFMT_BINARYBUFFER        uint32 = 199
	D3DFMT_FORCE_DWORD         uint32 = 0xFFFFFFFF
)

const (
	D3DPOOL_DEFAULT   uint32 = 0
	D3DPOOL_MANAGED   uint32 = 1
	D3DPOOL_SYSTEMMEM uint32 = 2
	D3DPOOL_SCRATCH   uint32 = 3
)

const (
	D3DUSAGE_RENDERTARGET                    uint32 = 0x00000001
	D3DUSAGE_DEPTHSTENCIL                    uint32 = 0x00000002
	D3DUSAGE_WRITEONLY                       uint32 = 0x00000008
	D3DUSAGE_SOFTWAREPROCESSING              uint32 = 0x00000010
	D3DUSAGE_DONOTCLIP                       uint32 = 0x00000020
	D3DUSAGE_POINTS                          uint32 = 0x00000040
	D3DUSAGE_RTPATCHES                       uint32 = 0x00000080
	D3DUSAGE_NPATCHES                        uint32 = 0x00000100
	D3DUSAGE_DYNAMIC                         uint32 = 0x00000200
	D3DUSAGE_AUTOGENMIPMAP                   uint32 = 0x00000400
	D3DUSAGE_RESTRICTED_CONTENT              uint32 = 0x00000800
	D3DUSAGE_RESTRICT_SHARED_RESOURCE_DRIVER uint32 = 0x00001000
	D3DUSAGE_RESTRICT_SHARED_RESOURCE        uint32 = 0x00002000
	D3DUSAGE_DMAP                            uint32 = 0x00004000
	D3DUSAGE_QUERY_LEGACYBUMPMAP             uint32 = 0x00008000
	D3DUSAGE_QUERY_SRGBREAD                  uint32 = 0x00010000
	D3DUSAGE_QUERY_FILTER                    uint32 = 0x00020000
	D3DUSAGE_QUERY_SRGBWRITE                 uint32 = 0x00040000
	D3DUSAGE_QUERY_POSTPIXELSHADER_BLENDING  uint32 = 0x00080000
	D3DUSAGE_QUERY_VERTEXTEXTURE             uint32 = 0x00100000
	D3DUSAGE_QUERY_WRAPANDMIP                uint32 = 0x00200000
	D3DUSAGE_NONSECURE                       uint32 = 0x00800000
	D3DUSAGE_TEXTAPI                         uint32 = 0x10000000
)

const (
	D3DPT_POINTLIST     uint32 = 1
	D3DPT_LINELIST      uint32 = 2
	D3DPT_LINESTRIP     uint32 = 3
	D3DPT_TRIANGLELIST  uint32 = 4
	D3DPT_TRIANGLESTRIP uint32 = 5
	D3DPT_TRIANGLEFAN   uint32 = 6
)

const (
	D3DDECLUSAGE_POSITION     uint8 = 0
	D3DDECLUSAGE_BLENDWEIGHT  uint8 = 1
	D3DDECLUSAGE_BLENDINDICES uint8 = 2
	D3DDECLUSAGE_NORMAL       uint8 = 3
	D3DDECLUSAGE_PSIZE        uint8 = 4
	D3DDECLUSAGE_TEXCOORD     uint8 = 5
	D3DDECLUSAGE_TANGENT      uint8 = 6
	D3DDECLUSAGE_BINORMAL     uint8 = 7
	D3DDECLUSAGE_TESSFACTOR   uint8 = 8
	D3DDECLUSAGE_POSITIONT    uint8 = 9
	D3DDECLUSAGE_COLOR        uint8 = 10
	D3DDECLUSAGE_FOG          uint8 = 11
	D3DDECLUSAGE_DEPTH        uint8 = 12
	D3DDECLUSAGE_SAMPLE       uint8 = 13
)

const (
	D3DDECLMETHOD_DEFAULT          uint8 = 0
	D3DDECLMETHOD_PARTIALU         uint8 = 1
	D3DDECLMETHOD_PARTIALV         uint8 = 2
	D3DDECLMETHOD_CROSSUV          uint8 = 3
	D3DDECLMETHOD_UV               uint8 = 4
	D3DDECLMETHOD_LOOKUP           uint8 = 5
	D3DDECLMETHOD_LOOKUPPRESAMPLED uint8 = 6
)

const (
	D3DDECLTYPE_FLOAT1    uint8 = 0
	D3DDECLTYPE_FLOAT2    uint8 = 1
	D3DDECLTYPE_FLOAT3    uint8 = 2
	D3DDECLTYPE_FLOAT4    uint8 = 3
	D3DDECLTYPE_D3DCOLOR  uint8 = 4
	D3DDECLTYPE_UBYTE4    uint8 = 5
	D3DDECLTYPE_SHORT2    uint8 = 6
	D3DDECLTYPE_SHORT4    uint8 = 7
	D3DDECLTYPE_UBYTE4N   uint8 = 8
	D3DDECLTYPE_SHORT2N   uint8 = 9
	D3DDECLTYPE_SHORT4N   uint8 = 10
	D3DDECLTYPE_USHORT2N  uint8 = 11
	D3DDECLTYPE_USHORT4N  uint8 = 12
	D3DDECLTYPE_UDEC3     uint8 = 13
	D3DDECLTYPE_DEC3N     uint8 = 14
	D3DDECLTYPE_FLOAT16_2 uint8 = 15
	D3DDECLTYPE_FLOAT16_4 uint8 = 16
	D3DDECLTYPE_UNUSED    uint8 = 17
)

type Rect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

type ColorValue struct {
	R float32
	G float32
	B float32
	A float32
}

type Vector3 struct {
	X float32
	Y float32
	Z float32
}

type D3DCAPS9 struct {
	DeviceType                        uint32
	AdapterOrdinal                    uint32
	Caps                              uint32
	Caps2                             uint32
	Caps3                             uint32
	PresentationIntervals             uint32
	CursorCaps                        uint32
	DevCaps                           uint32
	PrimitiveMiscCaps                 uint32
	RasterCaps                        uint32
	ZCmpCaps                          uint32
	SrcBlendCaps                      uint32
	DestBlendCaps                     uint32
	AlphaCmpCaps                      uint32
	ShadeCaps                         uint32
	TextureCaps                       uint32
	TextureFilterCaps                 uint32
	CubeTextureFilterCaps             uint32
	VolumeTextureFilterCaps           uint32
	TextureAddressCaps                uint32
	VolumeTextureAddressCaps          uint32
	LineCaps                          uint32
	MaxTextureWidth                   uint32
	MaxTextureHeight                  uint32
	MaxVolumeExtent                   uint32
	MaxTextureRepeat                  uint32
	MaxTextureAspectRatio             uint32
	MaxAnisotropy                     uint32
	MaxVertexW                        float32
	GuardBandLeft                     float32
	GuardBandTop                      float32
	GuardBandRight                    float32
	GuardBandBottom                   float32
	ExtentsAdjust                     float32
	StencilCaps                       uint32
	FVFCaps                           uint32
	TextureOpCaps                     uint32
	MaxTextureBlendStages             uint32
	MaxSimultaneousTextures           uint32
	VertexProcessingCaps              uint32
	MaxActiveLights                   uint32
	MaxUserClipPlanes                 uint32
	MaxVertexBlendMatrices            uint32
	MaxVertexBlendMatrixIndex         uint32
	MaxPointSize                      float32
	MaxPrimitiveCount                 uint32
	MaxVertexIndex                    uint32
	MaxStreams                        uint32
	MaxStreamStride                   uint32
	VertexShaderVersion               uint32
	MaxVertexShaderConst              uint32
	PixelShaderVersion                uint32
	PixelShader1xMaxValue             float32
	DevCaps2                          uint32
	MaxNpatchTessellationLevel        float32
	Reserved5                         uint32
	MasterAdapterOrdinal              uint32
	AdapterOrdinalInGroup             uint32
	NumberOfAdaptersInGroup           uint32
	DeclTypes                         uint32
	NumSimultaneousRTs                uint32
	StretchRectFilterCaps             uint32
	VS20Caps                          Shader20Caps
	PS20Caps                          Shader20Caps
	VertexTextureFilterCaps           uint32
	MaxVShaderInstructionsExecuted    uint32
	MaxPShaderInstructionsExecuted    uint32
	MaxVertexShader30InstructionSlots uint32
	MaxPixelShader30InstructionSlots  uint32
}

type Shader20Caps struct {
	Caps                    uint32
	DynamicFlowControlDepth uint32
	NumTemps                uint32
	StaticFlowControlDepth  uint32
}

type D3DPRESENT_PARAMETERS struct {
	BackBufferWidth           uint32
	BackBufferHeight          uint32
	BackBufferFormat          uint32
	BackBufferCount           uint32
	MultiSampleType           uint32
	MultiSampleQuality        uint32
	SwapEffect                uint32
	HDeviceWindow             uint64
	Windowed                  uint32
	EnableAutoDepthStencil    uint32
	AutoDepthStencilFormat    uint32
	Flags                     uint32
	FullScreenRefreshRateInHz uint32
	PresentationInterval      uint32
}

type D3DMATERIAL9 struct {
	Diffuse  ColorValue
	Ambient  ColorValue
	Specular ColorValue
	Emissive ColorValue
	Power    float32
}

type D3DLIGHT9 struct {
	Type         uint32
	Diffuse      ColorValue
	Specular     ColorValue
	Ambient      ColorValue
	Position     Vector3
	Direction    Vector3
	Range        float32
	Falloff      float32
	Attenuation0 float32
	Attenuation1 float32
	Attenuation2 float32
	Theta        float32
	Phi          float32
}

type D3DVIEWPORT9 struct {
	X      uint32
	Y      uint32
	Width  uint32
	Height uint32
	MinZ   float32
	MaxZ   float32
}

type Viewport = D3DVIEWPORT9

type VertexElement struct {
	Stream     uint16
	Offset     uint16
	Type       uint8
	Method     uint8
	Usage      uint8
	UsageIndex uint8
}

type VertexDeclaration struct {
	Elements []VertexElement
}

type StreamSource struct {
	Buffer *VertexBuffer
	Offset uint32
	Stride uint32
}
