/* Direct3D 11 workload for features the other workloads leave out: an indirect instanced draw of two quads built from the vertex number, two
 * render targets of which the first is blended over its clear colour, a constant buffer rewritten with Map and DISCARD, a texture whose
 * mip chain the GPU generates (the pixel shader reads its smallest level), and an occlusion query around the draw. The two targets are
 * copied to staging textures and written to C:\features0.raw and C:\features1.raw as RGBA bytes; the number of samples that passed is
 * written to C:\features_samples.raw as a 64-bit value; C:\features.txt holds OK or the first failing step. */
#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include "features_shaders.h"

#define SIZE 256

static void report(const char *text)
{
	HANDLE f = CreateFileW(L"C:\\features.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
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

static void write_file(const wchar_t *path, const void *data, DWORD size)
{
	HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD n;
	WriteFile(f, data, size, &n, NULL);
	CloseHandle(f);
}

static void save_target(ID3D11Device *device, ID3D11DeviceContext *context, ID3D11Texture2D *target, const wchar_t *path)
{
	D3D11_TEXTURE2D_DESC desc = {SIZE, SIZE, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0}, D3D11_USAGE_STAGING, 0, D3D11_CPU_ACCESS_READ, 0};
	ID3D11Texture2D *staging = NULL;
	CHECK("staging texture", ID3D11Device_CreateTexture2D(device, &desc, NULL, &staging));
	ID3D11DeviceContext_CopyResource(context, (ID3D11Resource *)staging, (ID3D11Resource *)target);
	D3D11_MAPPED_SUBRESOURCE mapped;
	CHECK("map target", ID3D11DeviceContext_Map(context, (ID3D11Resource *)staging, 0, D3D11_MAP_READ, 0, &mapped));
	static unsigned char pixels[SIZE * SIZE * 4];
	for (int row = 0; row < SIZE; ++row)
		for (int byte = 0; byte < SIZE * 4; ++byte)
			pixels[row * SIZE * 4 + byte] = ((const unsigned char *)mapped.pData)[row * mapped.RowPitch + byte];
	ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)staging, 0);
	write_file(path, pixels, sizeof pixels);
	ID3D11Texture2D_Release(staging);
}

void __stdcall entry(void)
{
	ID3D11Device *device = NULL;
	ID3D11DeviceContext *context = NULL;
	D3D_FEATURE_LEVEL level = 0;
	CHECK("device", D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, NULL, 0, D3D11_SDK_VERSION, &device, &level, &context));

	D3D11_TEXTURE2D_DESC target_desc = {SIZE, SIZE, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0}, D3D11_USAGE_DEFAULT, D3D11_BIND_RENDER_TARGET, 0, 0};
	ID3D11Texture2D *targets[2] = {NULL, NULL};
	ID3D11RenderTargetView *views[2] = {NULL, NULL};
	for (int index = 0; index < 2; ++index) {
		CHECK("target", ID3D11Device_CreateTexture2D(device, &target_desc, NULL, &targets[index]));
		CHECK("target view", ID3D11Device_CreateRenderTargetView(device, (ID3D11Resource *)targets[index], NULL, &views[index]));
	}

	/* 64 by 64 texels, white on the left half and black on the right: the 1 by 1 level is the average. */
	static unsigned int texels[64 * 64];
	for (int row = 0; row < 64; ++row)
		for (int column = 0; column < 64; ++column)
			texels[row * 64 + column] = column < 32 ? 0xffffffffu : 0xff000000u;
	D3D11_TEXTURE2D_DESC texture_desc = {64, 64, 0, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0}, D3D11_USAGE_DEFAULT,
		D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET, 0, D3D11_RESOURCE_MISC_GENERATE_MIPS};
	ID3D11Texture2D *texture = NULL;
	CHECK("mip texture", ID3D11Device_CreateTexture2D(device, &texture_desc, NULL, &texture));
	ID3D11DeviceContext_UpdateSubresource(context, (ID3D11Resource *)texture, 0, NULL, texels, 64 * 4, 0);
	ID3D11ShaderResourceView *texture_view = NULL;
	CHECK("mip view", ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)texture, NULL, &texture_view));
	ID3D11DeviceContext_GenerateMips(context, texture_view);
	D3D11_SAMPLER_DESC sampler_desc = {D3D11_FILTER_MIN_MAG_MIP_LINEAR, D3D11_TEXTURE_ADDRESS_CLAMP, D3D11_TEXTURE_ADDRESS_CLAMP,
		D3D11_TEXTURE_ADDRESS_CLAMP, 0.0f, 1, D3D11_COMPARISON_NEVER, {0, 0, 0, 0}, 0.0f, D3D11_FLOAT32_MAX};
	ID3D11SamplerState *sampler = NULL;
	CHECK("sampler", ID3D11Device_CreateSamplerState(device, &sampler_desc, &sampler));

	D3D11_BUFFER_DESC constants_desc = {32, D3D11_USAGE_DYNAMIC, D3D11_BIND_CONSTANT_BUFFER, D3D11_CPU_ACCESS_WRITE, 0, 0};
	ID3D11Buffer *constants = NULL;
	CHECK("constant buffer", ID3D11Device_CreateBuffer(device, &constants_desc, NULL, &constants));
	D3D11_MAPPED_SUBRESOURCE mapped;
	CHECK("map constants", ID3D11DeviceContext_Map(context, (ID3D11Resource *)constants, 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped));
	{
		float *values = mapped.pData;
		values[0] = 1.0f; values[1] = 0.0f; values[2] = 0.0f; values[3] = 1.0f;
		values[4] = 0.0f; values[5] = 1.0f; values[6] = 0.0f; values[7] = 1.0f;
	}
	ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)constants, 0);

	/* The draw arguments: four vertices, two instances. */
	static const unsigned int arguments[4] = {4, 2, 0, 0};
	D3D11_BUFFER_DESC arguments_desc = {sizeof arguments, D3D11_USAGE_DEFAULT, 0, 0, D3D11_RESOURCE_MISC_DRAWINDIRECT_ARGS, 0};
	D3D11_SUBRESOURCE_DATA arguments_data = {arguments, 0, 0};
	ID3D11Buffer *indirect = NULL;
	CHECK("argument buffer", ID3D11Device_CreateBuffer(device, &arguments_desc, &arguments_data, &indirect));

	ID3D11VertexShader *vertex_shader = NULL;
	ID3D11PixelShader *pixel_shader = NULL;
	CHECK("vertex shader", ID3D11Device_CreateVertexShader(device, features_vs, sizeof(features_vs), NULL, &vertex_shader));
	CHECK("pixel shader", ID3D11Device_CreatePixelShader(device, features_ps, sizeof(features_ps), NULL, &pixel_shader));

	D3D11_BLEND_DESC blend_desc = {0};
	blend_desc.IndependentBlendEnable = TRUE;
	blend_desc.RenderTarget[0].BlendEnable = TRUE;
	blend_desc.RenderTarget[0].SrcBlend = D3D11_BLEND_SRC_ALPHA;
	blend_desc.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
	blend_desc.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
	blend_desc.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
	blend_desc.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_ZERO;
	blend_desc.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
	blend_desc.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
	blend_desc.RenderTarget[1].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
	ID3D11BlendState *blend = NULL;
	CHECK("blend state", ID3D11Device_CreateBlendState(device, &blend_desc, &blend));
	D3D11_RASTERIZER_DESC raster_desc = {D3D11_FILL_SOLID, D3D11_CULL_NONE, FALSE, 0, 0.0f, 0.0f, TRUE, FALSE, FALSE, FALSE};
	ID3D11RasterizerState *raster = NULL;
	CHECK("rasterizer state", ID3D11Device_CreateRasterizerState(device, &raster_desc, &raster));

	D3D11_QUERY_DESC query_desc = {D3D11_QUERY_OCCLUSION, 0};
	ID3D11Query *query = NULL;
	CHECK("query", ID3D11Device_CreateQuery(device, &query_desc, &query));

	const float black[4] = {0.0f, 0.0f, 0.0f, 1.0f}, blue[4] = {0.0f, 0.0f, 1.0f, 1.0f};
	ID3D11DeviceContext_ClearRenderTargetView(context, views[0], black);
	ID3D11DeviceContext_ClearRenderTargetView(context, views[1], blue);
	ID3D11DeviceContext_OMSetRenderTargets(context, 2, views, NULL);
	ID3D11DeviceContext_OMSetBlendState(context, blend, NULL, 0xffffffffu);
	ID3D11DeviceContext_RSSetState(context, raster);
	D3D11_VIEWPORT viewport = {0.0f, 0.0f, SIZE, SIZE, 0.0f, 1.0f};
	ID3D11DeviceContext_RSSetViewports(context, 1, &viewport);
	ID3D11DeviceContext_IASetInputLayout(context, NULL);
	ID3D11DeviceContext_IASetPrimitiveTopology(context, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
	ID3D11DeviceContext_VSSetShader(context, vertex_shader, NULL, 0);
	ID3D11DeviceContext_PSSetShader(context, pixel_shader, NULL, 0);
	ID3D11DeviceContext_PSSetConstantBuffers(context, 0, 1, &constants);
	ID3D11DeviceContext_PSSetShaderResources(context, 0, 1, &texture_view);
	ID3D11DeviceContext_PSSetSamplers(context, 0, 1, &sampler);
	ID3D11DeviceContext_Begin(context, (ID3D11Asynchronous *)query);
	ID3D11DeviceContext_DrawInstancedIndirect(context, indirect, 0);
	ID3D11DeviceContext_End(context, (ID3D11Asynchronous *)query);
	ID3D11DeviceContext_Flush(context);

	/* The result comes from work another thread of DXVK does, and this loop never calls anything that would let that thread run:
	 * the runtime has to take the processor away from a thread that spins. */
	UINT64 samples = 0;
	HRESULT status = S_FALSE;
	const DWORD started = GetTickCount();
	while (status == S_FALSE && GetTickCount() - started < 60000)
		status = ID3D11DeviceContext_GetData(context, (ID3D11Asynchronous *)query, &samples, sizeof samples, 0);
	if (status != S_OK)
		fail("query data", status);
	write_file(L"C:\\features_samples.raw", &samples, sizeof samples);
	save_target(device, context, targets[0], L"C:\\features0.raw");
	save_target(device, context, targets[1], L"C:\\features1.raw");
	report("OK");
	ExitProcess(0);
}
