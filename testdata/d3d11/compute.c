/* Direct3D 11 compute workload: 256 threads write i * i + 7 plus the red channel of one texel (read with Load from a texture) into a typed
 * unordered access buffer; the buffer is copied to a staging buffer and written to C:\compute.raw as 256 32-bit values. C:\compute.txt holds OK
 * or the first failing step. The shader is compute.hlsl compiled for cs_5_0. */
#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include "compute_shader.h"

static void report(const char *text)
{
	HANDLE f = CreateFileW(L"C:\\compute.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
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

void __stdcall entry(void)
{
	ID3D11Device *device = NULL;
	ID3D11DeviceContext *context = NULL;
	D3D_FEATURE_LEVEL level = 0;
	CHECK("device", D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, NULL, 0, D3D11_SDK_VERSION, &device, &level, &context));

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
	ID3D11ShaderResourceView *srv = NULL;
	CHECK("texture view", ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)texture, NULL, &srv));

	D3D11_BUFFER_DESC output_desc = {256 * 4, D3D11_USAGE_DEFAULT, D3D11_BIND_UNORDERED_ACCESS, 0, 0, 0};
	ID3D11Buffer *output = NULL;
	CHECK("output buffer", ID3D11Device_CreateBuffer(device, &output_desc, NULL, &output));
	D3D11_UNORDERED_ACCESS_VIEW_DESC uav_desc = {DXGI_FORMAT_R32_UINT, D3D11_UAV_DIMENSION_BUFFER};
	uav_desc.Buffer.FirstElement = 0;
	uav_desc.Buffer.NumElements = 256;
	ID3D11UnorderedAccessView *uav = NULL;
	CHECK("unordered access view", ID3D11Device_CreateUnorderedAccessView(device, (ID3D11Resource *)output, &uav_desc, &uav));
	D3D11_BUFFER_DESC staging_desc = {256 * 4, D3D11_USAGE_STAGING, 0, D3D11_CPU_ACCESS_READ, 0, 0};
	ID3D11Buffer *staging = NULL;
	CHECK("staging buffer", ID3D11Device_CreateBuffer(device, &staging_desc, NULL, &staging));

	ID3D11ComputeShader *shader = NULL;
	CHECK("compute shader", ID3D11Device_CreateComputeShader(device, compute_cs, sizeof(compute_cs), NULL, &shader));
	ID3D11DeviceContext_CSSetShader(context, shader, NULL, 0);
	ID3D11DeviceContext_CSSetShaderResources(context, 0, 1, &srv);
	ID3D11DeviceContext_CSSetUnorderedAccessViews(context, 0, 1, &uav, NULL);
	ID3D11DeviceContext_Dispatch(context, 4, 1, 1);
	ID3D11DeviceContext_CopyResource(context, (ID3D11Resource *)staging, (ID3D11Resource *)output);

	D3D11_MAPPED_SUBRESOURCE mapped;
	CHECK("map", ID3D11DeviceContext_Map(context, (ID3D11Resource *)staging, 0, D3D11_MAP_READ, 0, &mapped));
	HANDLE f = CreateFileW(L"C:\\compute.raw", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD n;
	WriteFile(f, mapped.pData, 256 * 4, &n, NULL);
	CloseHandle(f);
	ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)staging, 0);
	report("OK");
	ExitProcess(0);
}
