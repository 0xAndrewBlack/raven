/* Independent Direct3D 11 workload with a window that goes into full screen mode and out again: it renders a few frames, calls
 * SetFullscreenState(TRUE), resizes the swap chain buffers to what the swap chain now is, renders and presents again, then leaves full screen
 * and does the same. The last frame of each state is copied with the GPU to C:\fullscreen_full.raw and C:\fullscreen_back.raw, the sizes are
 * written to C:\fullscreen_full.txt and C:\fullscreen_back.txt, and C:\fullscreen.txt holds OK or the first failing step. */
#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include "tri_shaders.h"

#define SIZE 256
#define WIDE 320
#define HIGH 200
#define FRAMES 5

struct vertex { float x, y; float r, g, b, a; };

static void write_text(const wchar_t *path, const char *text)
{
	HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
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
	while (*step && length < 60)
		text[length++] = *step++;
	text[length++] = ' ';
	for (int shift = 28; shift >= 0; shift -= 4)
		text[length++] = "0123456789abcdef"[((unsigned)hr >> shift) & 15];
	text[length] = 0;
	write_text(L"C:\\fullscreen.txt", text);
	ExitProcess(1);
}

static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
	if (message == WM_DESTROY) {
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProcW(window, message, wparam, lparam);
}

static void pump(void)
{
	MSG message;
	while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE)) {
		TranslateMessage(&message);
		DispatchMessageW(&message);
	}
}

static void save(ID3D11DeviceContext *context, ID3D11Texture2D *staging, ID3D11Texture2D *back, const wchar_t *path, int width, int height)
{
	D3D11_MAPPED_SUBRESOURCE mapped;
	HRESULT hr;
	ID3D11DeviceContext_CopyResource(context, (ID3D11Resource *)staging, (ID3D11Resource *)back);
	if (FAILED(hr = ID3D11DeviceContext_Map(context, (ID3D11Resource *)staging, 0, D3D11_MAP_READ, 0, &mapped)))
		fail("map", hr);
	HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD n;
	for (int row = 0; row < height; ++row)
		WriteFile(f, (const BYTE *)mapped.pData + (size_t)row * mapped.RowPitch, (DWORD)width * 4, &n, NULL);
	CloseHandle(f);
	ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)staging, 0);
}

void __stdcall entry(void)
{
	HINSTANCE instance = GetModuleHandleW(NULL);
	WNDCLASSEXW class_info = {sizeof class_info, 0, procedure, 0, 0, instance, NULL, LoadCursorW(NULL, (LPCWSTR)IDC_ARROW), (HBRUSH)(COLOR_WINDOW + 1), NULL, L"RavenD3D", NULL};
	RegisterClassExW(&class_info);
	RECT frame = {0, 0, SIZE, SIZE};
	AdjustWindowRect(&frame, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE);
	HWND window = CreateWindowExW(0, L"RavenD3D", L"Direct3D 11 frame", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, 100, 100,
		frame.right - frame.left, frame.bottom - frame.top, NULL, NULL, instance, NULL);
	if (!window)
		fail("window", 0);
	ShowWindow(window, SW_SHOW);
	UpdateWindow(window);
	pump();

	DXGI_SWAP_CHAIN_DESC description = {{SIZE, SIZE, {60, 1}, DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED, DXGI_MODE_SCALING_UNSPECIFIED},
		{1, 0}, DXGI_USAGE_RENDER_TARGET_OUTPUT, 2, window, TRUE, DXGI_SWAP_EFFECT_DISCARD, 0};
	IDXGISwapChain *swap = NULL;
	ID3D11Device *device = NULL;
	ID3D11DeviceContext *context = NULL;
	D3D_FEATURE_LEVEL level = 0;
	HRESULT hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, NULL, 0, D3D11_SDK_VERSION, &description, &swap, &device, &level, &context);
	if (FAILED(hr))
		fail("device and swap chain", hr);
	ID3D11Texture2D *back = NULL, *staging = NULL;
	if (FAILED(hr = IDXGISwapChain_GetBuffer(swap, 0, &IID_ID3D11Texture2D, (void **)&back)))
		fail("buffer", hr);
	D3D11_TEXTURE2D_DESC td = {SIZE, SIZE, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0}, D3D11_USAGE_STAGING, 0, D3D11_CPU_ACCESS_READ, 0};
	if (FAILED(hr = ID3D11Device_CreateTexture2D(device, &td, NULL, &staging)))
		fail("staging", hr);
	ID3D11RenderTargetView *view = NULL;
	if (FAILED(hr = ID3D11Device_CreateRenderTargetView(device, (ID3D11Resource *)back, NULL, &view)))
		fail("view", hr);
	ID3D11VertexShader *vs = NULL;
	ID3D11PixelShader *ps = NULL;
	if (FAILED(hr = ID3D11Device_CreateVertexShader(device, tri_vs, sizeof(tri_vs), NULL, &vs)))
		fail("vertex shader", hr);
	if (FAILED(hr = ID3D11Device_CreatePixelShader(device, tri_ps, sizeof(tri_ps), NULL, &ps)))
		fail("pixel shader", hr);
	D3D11_INPUT_ELEMENT_DESC elements[] = {
		{"POSITION", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
		{"COLOR", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 8, D3D11_INPUT_PER_VERTEX_DATA, 0},
	};
	ID3D11InputLayout *layout = NULL;
	if (FAILED(hr = ID3D11Device_CreateInputLayout(device, elements, 2, tri_vs, sizeof(tri_vs), &layout)))
		fail("layout", hr);
	/* Clockwise in clip space: the default rasterizer state culls counter-clockwise (back) faces. */
	struct vertex vertices[3] = {{-0.8f, -0.8f, 1, 0, 0, 1}, {0.0f, 0.8f, 0, 0, 1, 1}, {0.8f, -0.8f, 0, 1, 0, 1}};
	D3D11_BUFFER_DESC bd = {sizeof vertices, D3D11_USAGE_IMMUTABLE, D3D11_BIND_VERTEX_BUFFER, 0, 0, 0};
	D3D11_SUBRESOURCE_DATA sd = {vertices, 0, 0};
	ID3D11Buffer *buffer = NULL;
	if (FAILED(hr = ID3D11Device_CreateBuffer(device, &bd, &sd, &buffer)))
		fail("buffer", hr);
	D3D11_VIEWPORT viewport = {0, 0, SIZE, SIZE, 0, 1};
	UINT stride = sizeof(struct vertex), offset = 0;
	ID3D11DeviceContext_OMSetRenderTargets(context, 1, &view, NULL);
	ID3D11DeviceContext_RSSetViewports(context, 1, &viewport);
	ID3D11DeviceContext_IASetInputLayout(context, layout);
	ID3D11DeviceContext_IASetVertexBuffers(context, 0, 1, &buffer, &stride, &offset);
	ID3D11DeviceContext_IASetPrimitiveTopology(context, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
	ID3D11DeviceContext_VSSetShader(context, vs, NULL, 0);
	ID3D11DeviceContext_PSSetShader(context, ps, NULL, 0);

	for (int frame_number = 0; frame_number < FRAMES; ++frame_number) {
		/* The last frame clears to the colour the offscreen workload uses; earlier frames ramp towards it. */
		const float ramp = (float)(FRAMES - 1 - frame_number) / (FRAMES - 1);
		const float clear[4] = {0.1f + 0.5f * ramp, 0.1f, 0.3f, 1.0f};
		ID3D11DeviceContext_ClearRenderTargetView(context, view, clear);
		ID3D11DeviceContext_Draw(context, 3, 0);
		if (frame_number == 0)
			save(context, staging, back, L"C:\\fullscreen_first.raw", SIZE, SIZE);
		if (frame_number == FRAMES - 1)
			save(context, staging, back, L"C:\\fullscreen_last.raw", SIZE, SIZE);
		if (FAILED(hr = IDXGISwapChain_Present(swap, 0, 0)))
			fail("present", hr);
		pump();
	}
	/* Into full screen mode and out again: the swap chain follows the window each time, and presents keep working. */
	static const wchar_t *names[2] = {L"C:\\fullscreen_full.raw", L"C:\\fullscreen_back.raw"};
	for (int round = 0; round < 2; ++round) {
		if (FAILED(hr = IDXGISwapChain_SetFullscreenState(swap, round == 0, NULL)))
			fail(round == 0 ? "enter full screen" : "leave full screen", hr);
		pump();
		ID3D11DeviceContext_OMSetRenderTargets(context, 0, NULL, NULL);
		ID3D11RenderTargetView_Release(view);
		ID3D11Texture2D_Release(back);
		ID3D11Texture2D_Release(staging);
		if (FAILED(hr = IDXGISwapChain_ResizeBuffers(swap, 0, 0, 0, DXGI_FORMAT_UNKNOWN, 0)))
			fail("resize buffers", hr);
		DXGI_SWAP_CHAIN_DESC now;
		IDXGISwapChain_GetDesc(swap, &now);
		if (FAILED(hr = IDXGISwapChain_GetBuffer(swap, 0, &IID_ID3D11Texture2D, (void **)&back)))
			fail("buffer", hr);
		td.Width = now.BufferDesc.Width;
		td.Height = now.BufferDesc.Height;
		if (FAILED(hr = ID3D11Device_CreateTexture2D(device, &td, NULL, &staging)))
			fail("staging", hr);
		if (FAILED(hr = ID3D11Device_CreateRenderTargetView(device, (ID3D11Resource *)back, NULL, &view)))
			fail("view", hr);
		viewport.Width = (float)now.BufferDesc.Width;
		viewport.Height = (float)now.BufferDesc.Height;
		ID3D11DeviceContext_OMSetRenderTargets(context, 1, &view, NULL);
		ID3D11DeviceContext_RSSetViewports(context, 1, &viewport);
		for (int frame_number = 0; frame_number < 5; ++frame_number) {
			const float clear[4] = {0.1f, round == 0 ? 0.4f : 0.2f, 0.3f, 1.0f};
			ID3D11DeviceContext_ClearRenderTargetView(context, view, clear);
			ID3D11DeviceContext_Draw(context, 3, 0);
			if (frame_number == 4)
				save(context, staging, back, names[round], (int)now.BufferDesc.Width, (int)now.BufferDesc.Height);
			if (FAILED(hr = IDXGISwapChain_Present(swap, 0, 0)))
				fail("present", hr);
			pump();
		}
		char text[64];
		wsprintfA(text, "%dx%d", (int)now.BufferDesc.Width, (int)now.BufferDesc.Height);
		write_text(round == 0 ? L"C:\\fullscreen_full.txt" : L"C:\\fullscreen_back.txt", text);
	}
	write_text(L"C:\\fullscreen.txt", "OK");
	ExitProcess(0);
}
