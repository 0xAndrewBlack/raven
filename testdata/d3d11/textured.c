/* Independent Direct3D 11 workload: two overlapping textured quads with a sampler, a constant buffer updated between draws and a depth
 * buffer that hides the far quad behind the near one although it is drawn last. The pixels are read back into C:\textured.raw and
 * C:\textured.txt holds OK or the first failing step. The shaders are tex.hlsl compiled for vs_5_0 and ps_5_0. */
#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include "tex_shaders.h"

#define SIZE 256

struct vertex { float x, y, z, u, v; };

static void report(const char *text)
{
	HANDLE f = CreateFileW(L"C:\\textured.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD n;
	WriteFile(f, text, lstrlenA(text), &n, NULL);
	CloseHandle(f);
}

static void fail(const char *step, HRESULT hr)
{
	char text[96];
	int length = 0;
	const char *prefix = "FAIL ";
	while (*prefix)
		text[length++] = *prefix++;
	while (*step && length < 70)
		text[length++] = *step++;
	text[length++] = ' ';
	for (int shift = 28; shift >= 0; shift -= 4)
		text[length++] = "0123456789abcdef"[((unsigned)hr >> shift) & 15];
	text[length] = 0;
	report(text);
	ExitProcess(1);
}

#define CHECK(step, call) do { HRESULT result_ = (call); if (FAILED(result_)) fail(step, result_); } while (0)

static void quad(struct vertex *out, float x0, float y0, float x1, float y1, float z)
{
	/* y1 is the top edge: v is 0 there and 1 at y0. */
	const struct vertex corners[4] = {{x0, y1, z, 0, 0}, {x1, y1, z, 1, 0}, {x1, y0, z, 1, 1}, {x0, y0, z, 0, 1}};
	const int order[6] = {0, 1, 2, 0, 2, 3};
	for (int index = 0; index < 6; ++index)
		out[index] = corners[order[index]];
}

void __stdcall entry(void)
{
	ID3D11Device *device = NULL;
	ID3D11DeviceContext *context = NULL;
	D3D_FEATURE_LEVEL level = 0;
	CHECK("device", D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, NULL, 0, D3D11_SDK_VERSION, &device, &level, &context));

	D3D11_TEXTURE2D_DESC td = {SIZE, SIZE, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0}, D3D11_USAGE_DEFAULT, D3D11_BIND_RENDER_TARGET, 0, 0};
	ID3D11Texture2D *target = NULL, *staging = NULL, *depth = NULL;
	CHECK("target", ID3D11Device_CreateTexture2D(device, &td, NULL, &target));
	td.Usage = D3D11_USAGE_STAGING;
	td.BindFlags = 0;
	td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
	CHECK("staging", ID3D11Device_CreateTexture2D(device, &td, NULL, &staging));
	td.Usage = D3D11_USAGE_DEFAULT;
	td.CPUAccessFlags = 0;
	td.Format = DXGI_FORMAT_D32_FLOAT;
	td.BindFlags = D3D11_BIND_DEPTH_STENCIL;
	CHECK("depth", ID3D11Device_CreateTexture2D(device, &td, NULL, &depth));
	ID3D11RenderTargetView *rtv = NULL;
	ID3D11DepthStencilView *dsv = NULL;
	CHECK("render target view", ID3D11Device_CreateRenderTargetView(device, (ID3D11Resource *)target, NULL, &rtv));
	CHECK("depth view", ID3D11Device_CreateDepthStencilView(device, (ID3D11Resource *)depth, NULL, &dsv));

	/* An 8 by 8 checkerboard texture. */
	unsigned char texels[8 * 8 * 4];
	for (int row = 0; row < 8; ++row)
		for (int column = 0; column < 8; ++column) {
			unsigned char *texel = texels + (row * 8 + column) * 4;
			const int red = ((row + column) & 1) == 0;
			texel[0] = red ? 255 : 240;
			texel[1] = red ? 64 : 240;
			texel[2] = red ? 64 : 240;
			texel[3] = 255;
		}
	D3D11_TEXTURE2D_DESC checker = {8, 8, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0}, D3D11_USAGE_IMMUTABLE, D3D11_BIND_SHADER_RESOURCE, 0, 0};
	D3D11_SUBRESOURCE_DATA checker_data = {texels, 8 * 4, 0};
	ID3D11Texture2D *texture = NULL;
	CHECK("texture", ID3D11Device_CreateTexture2D(device, &checker, &checker_data, &texture));
	ID3D11ShaderResourceView *view = NULL;
	CHECK("texture view", ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)texture, NULL, &view));
	D3D11_SAMPLER_DESC sampler_desc = {D3D11_FILTER_MIN_MAG_MIP_POINT, D3D11_TEXTURE_ADDRESS_CLAMP, D3D11_TEXTURE_ADDRESS_CLAMP, D3D11_TEXTURE_ADDRESS_CLAMP,
		0, 1, D3D11_COMPARISON_NEVER, {0, 0, 0, 0}, 0, D3D11_FLOAT32_MAX};
	ID3D11SamplerState *sampler = NULL;
	CHECK("sampler", ID3D11Device_CreateSamplerState(device, &sampler_desc, &sampler));

	D3D11_BUFFER_DESC cb_desc = {16, D3D11_USAGE_DEFAULT, D3D11_BIND_CONSTANT_BUFFER, 0, 0, 0};
	ID3D11Buffer *constants = NULL;
	CHECK("constant buffer", ID3D11Device_CreateBuffer(device, &cb_desc, NULL, &constants));

	struct vertex vertices[12];
	quad(vertices, -0.6f, -0.4f, 0.2f, 0.6f, 0.2f);
	quad(vertices + 6, -0.2f, -0.7f, 0.7f, 0.3f, 0.7f);
	D3D11_BUFFER_DESC vb_desc = {sizeof vertices, D3D11_USAGE_IMMUTABLE, D3D11_BIND_VERTEX_BUFFER, 0, 0, 0};
	D3D11_SUBRESOURCE_DATA vb_data = {vertices, 0, 0};
	ID3D11Buffer *buffer = NULL;
	CHECK("vertex buffer", ID3D11Device_CreateBuffer(device, &vb_desc, &vb_data, &buffer));

	ID3D11VertexShader *vs = NULL;
	ID3D11PixelShader *ps = NULL;
	CHECK("vertex shader", ID3D11Device_CreateVertexShader(device, tex_vs, sizeof(tex_vs), NULL, &vs));
	CHECK("pixel shader", ID3D11Device_CreatePixelShader(device, tex_ps, sizeof(tex_ps), NULL, &ps));
	D3D11_INPUT_ELEMENT_DESC elements[] = {
		{"POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
		{"TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 12, D3D11_INPUT_PER_VERTEX_DATA, 0},
	};
	ID3D11InputLayout *layout = NULL;
	CHECK("layout", ID3D11Device_CreateInputLayout(device, elements, 2, tex_vs, sizeof(tex_vs), &layout));

	D3D11_DEPTH_STENCIL_DESC depth_desc = {0};
	depth_desc.DepthEnable = TRUE;
	depth_desc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL;
	depth_desc.DepthFunc = D3D11_COMPARISON_LESS;
	ID3D11DepthStencilState *depth_state = NULL;
	CHECK("depth state", ID3D11Device_CreateDepthStencilState(device, &depth_desc, &depth_state));
	D3D11_RASTERIZER_DESC raster_desc = {0};
	raster_desc.FillMode = D3D11_FILL_SOLID;
	raster_desc.CullMode = D3D11_CULL_NONE;
	raster_desc.DepthClipEnable = TRUE;
	ID3D11RasterizerState *raster = NULL;
	CHECK("rasterizer state", ID3D11Device_CreateRasterizerState(device, &raster_desc, &raster));

	const float clear[4] = {0.1f, 0.1f, 0.3f, 1.0f};
	D3D11_VIEWPORT viewport = {0, 0, SIZE, SIZE, 0, 1};
	UINT stride = sizeof(struct vertex), offset = 0;
	ID3D11DeviceContext_OMSetRenderTargets(context, 1, &rtv, dsv);
	ID3D11DeviceContext_ClearRenderTargetView(context, rtv, clear);
	ID3D11DeviceContext_ClearDepthStencilView(context, dsv, D3D11_CLEAR_DEPTH, 1.0f, 0);
	ID3D11DeviceContext_RSSetViewports(context, 1, &viewport);
	ID3D11DeviceContext_RSSetState(context, raster);
	ID3D11DeviceContext_OMSetDepthStencilState(context, depth_state, 0);
	ID3D11DeviceContext_IASetInputLayout(context, layout);
	ID3D11DeviceContext_IASetVertexBuffers(context, 0, 1, &buffer, &stride, &offset);
	ID3D11DeviceContext_IASetPrimitiveTopology(context, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
	ID3D11DeviceContext_VSSetShader(context, vs, NULL, 0);
	ID3D11DeviceContext_PSSetShader(context, ps, NULL, 0);
	ID3D11DeviceContext_PSSetShaderResources(context, 0, 1, &view);
	ID3D11DeviceContext_PSSetSamplers(context, 0, 1, &sampler);
	ID3D11DeviceContext_PSSetConstantBuffers(context, 0, 1, &constants);

	/* The near quad first, plain; the far quad second with a blue tint: depth testing, not draw order, decides what shows. */
	const float near_tint[4] = {1.0f, 1.0f, 1.0f, 1.0f};
	const float far_tint[4] = {0.3f, 0.8f, 1.0f, 1.0f};
	ID3D11DeviceContext_UpdateSubresource(context, (ID3D11Resource *)constants, 0, NULL, near_tint, 0, 0);
	ID3D11DeviceContext_Draw(context, 6, 0);
	ID3D11DeviceContext_UpdateSubresource(context, (ID3D11Resource *)constants, 0, NULL, far_tint, 0, 0);
	ID3D11DeviceContext_Draw(context, 6, 6);
	ID3D11DeviceContext_CopyResource(context, (ID3D11Resource *)staging, (ID3D11Resource *)target);

	D3D11_MAPPED_SUBRESOURCE mapped;
	CHECK("map", ID3D11DeviceContext_Map(context, (ID3D11Resource *)staging, 0, D3D11_MAP_READ, 0, &mapped));
	HANDLE f = CreateFileW(L"C:\\textured.raw", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD n;
	for (int row = 0; row < SIZE; ++row)
		WriteFile(f, (const BYTE *)mapped.pData + (size_t)row * mapped.RowPitch, SIZE * 4, &n, NULL);
	CloseHandle(f);
	ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)staging, 0);
	report("OK");
	ExitProcess(0);
}
