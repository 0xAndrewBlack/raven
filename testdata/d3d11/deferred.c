/* Direct3D 11 workload that records its clear and draw on a deferred context, finishes them into a command list and executes that on the
 * immediate context before the read-back; the output files are those of triangle.c. */
/* Independent Direct3D 11 workload: draws one vertex-coloured triangle into an offscreen target and writes the pixels it reads back.
 * The shaders are tri.hlsl compiled for vs_4_0 and ps_4_0 and embedded as tri_shaders.h. */
#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include "tri_shaders.h"

#define SIZE 256

struct vertex { float x, y; float r, g, b, a; };

static void report(const char *text)
{
	HANDLE f = CreateFileW(L"C:\\triangle.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD n;
	WriteFile(f, text, lstrlenA(text), &n, NULL);
	CloseHandle(f);
}

static int fail(const char *step, HRESULT hr)
{
	char text[128];
	wsprintfA(text, "FAIL %s hr=%08x", step, (unsigned)hr);
	report(text);
	return 1;
}

void __stdcall entry(void)
{
	ID3D11Device *device = NULL;
	ID3D11DeviceContext *context = NULL;
	D3D_FEATURE_LEVEL level = 0;
	HRESULT hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, NULL, 0, D3D11_SDK_VERSION, &device, &level, &context);
	if (FAILED(hr))
		ExitProcess(fail("device", hr));

	D3D11_TEXTURE2D_DESC td = {SIZE, SIZE, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0}, D3D11_USAGE_DEFAULT, D3D11_BIND_RENDER_TARGET, 0, 0};
	ID3D11Texture2D *target = NULL, *staging = NULL;
	if (FAILED(hr = ID3D11Device_CreateTexture2D(device, &td, NULL, &target)))
		ExitProcess(fail("target", hr));
	td.Usage = D3D11_USAGE_STAGING;
	td.BindFlags = 0;
	td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
	if (FAILED(hr = ID3D11Device_CreateTexture2D(device, &td, NULL, &staging)))
		ExitProcess(fail("staging", hr));
	ID3D11RenderTargetView *view = NULL;
	if (FAILED(hr = ID3D11Device_CreateRenderTargetView(device, (ID3D11Resource *)target, NULL, &view)))
		ExitProcess(fail("view", hr));

	ID3D11VertexShader *vs = NULL;
	ID3D11PixelShader *ps = NULL;
	if (FAILED(hr = ID3D11Device_CreateVertexShader(device, tri_vs, sizeof(tri_vs), NULL, &vs)))
		ExitProcess(fail("vertex shader", hr));
	if (FAILED(hr = ID3D11Device_CreatePixelShader(device, tri_ps, sizeof(tri_ps), NULL, &ps)))
		ExitProcess(fail("pixel shader", hr));
	D3D11_INPUT_ELEMENT_DESC elements[] = {
		{"POSITION", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
		{"COLOR", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 8, D3D11_INPUT_PER_VERTEX_DATA, 0},
	};
	ID3D11InputLayout *layout = NULL;
	if (FAILED(hr = ID3D11Device_CreateInputLayout(device, elements, 2, tri_vs, sizeof(tri_vs), &layout)))
		ExitProcess(fail("layout", hr));

	/* Clockwise in clip space: the default rasterizer state culls counter-clockwise (back) faces. */
	struct vertex vertices[3] = {{-0.8f, -0.8f, 1, 0, 0, 1}, {0.0f, 0.8f, 0, 0, 1, 1}, {0.8f, -0.8f, 0, 1, 0, 1}};
	D3D11_BUFFER_DESC bd = {sizeof vertices, D3D11_USAGE_IMMUTABLE, D3D11_BIND_VERTEX_BUFFER, 0, 0, 0};
	D3D11_SUBRESOURCE_DATA sd = {vertices, 0, 0};
	ID3D11Buffer *buffer = NULL;
	if (FAILED(hr = ID3D11Device_CreateBuffer(device, &bd, &sd, &buffer)))
		ExitProcess(fail("buffer", hr));

	const float clear[4] = {0.1f, 0.1f, 0.3f, 1.0f};
	D3D11_VIEWPORT viewport = {0, 0, SIZE, SIZE, 0, 1};
	UINT stride = sizeof(struct vertex), offset = 0;
	/* The state, the clear and the draw are recorded on a deferred context and replayed on the immediate one. */
	ID3D11DeviceContext *deferred = NULL;
	if (FAILED(hr = ID3D11Device_CreateDeferredContext(device, 0, &deferred)))
		ExitProcess(fail("deferred context", hr));
	ID3D11DeviceContext_OMSetRenderTargets(deferred, 1, &view, NULL);
	ID3D11DeviceContext_ClearRenderTargetView(deferred, view, clear);
	ID3D11DeviceContext_RSSetViewports(deferred, 1, &viewport);
	ID3D11DeviceContext_IASetInputLayout(deferred, layout);
	ID3D11DeviceContext_IASetVertexBuffers(deferred, 0, 1, &buffer, &stride, &offset);
	ID3D11DeviceContext_IASetPrimitiveTopology(deferred, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
	ID3D11DeviceContext_VSSetShader(deferred, vs, NULL, 0);
	ID3D11DeviceContext_PSSetShader(deferred, ps, NULL, 0);
	ID3D11DeviceContext_Draw(deferred, 3, 0);
	ID3D11CommandList *commands = NULL;
	if (FAILED(hr = ID3D11DeviceContext_FinishCommandList(deferred, FALSE, &commands)))
		ExitProcess(fail("finish command list", hr));
	ID3D11DeviceContext_ExecuteCommandList(context, commands, FALSE);
	ID3D11DeviceContext_CopyResource(context, (ID3D11Resource *)staging, (ID3D11Resource *)target);

	D3D11_MAPPED_SUBRESOURCE mapped;
	if (FAILED(hr = ID3D11DeviceContext_Map(context, (ID3D11Resource *)staging, 0, D3D11_MAP_READ, 0, &mapped)))
		ExitProcess(fail("map", hr));
	HANDLE f = CreateFileW(L"C:\\triangle.raw", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD n;
	for (int row = 0; row < SIZE; ++row)
		WriteFile(f, (const BYTE *)mapped.pData + (size_t)row * mapped.RowPitch, SIZE * 4, &n, NULL);
	CloseHandle(f);
	ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)staging, 0);
	report("OK");
	ExitProcess(0);
}
