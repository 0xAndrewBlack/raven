/* Independent Direct3D 11 workload with a window: renders animated frames into a DXGI swap chain and presents every one of them.
 * Frame number n clears to a colour that depends on n and draws the vertex-coloured triangle of tri.hlsl; the first and the last
 * back buffer are copied to C:\window_first.raw and C:\window_last.raw. The program keeps the last frame on screen for a few seconds
 * so that a compositor capture can be compared with the read-back pixels, then resizes the window and the swap chain to 320 by 200,
 * renders and presents again, writes the new back buffer to C:\window_resized.raw and C:\window_resized.txt, and keeps that frame
 * on screen for another capture. */
#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include "tri_shaders.h"

#define SIZE 256
#define WIDE 320
#define HIGH 200
#define FRAMES 60

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
	write_text(L"C:\\window.txt", text);
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
			save(context, staging, back, L"C:\\window_first.raw", SIZE, SIZE);
		if (frame_number == FRAMES - 1)
			save(context, staging, back, L"C:\\window_last.raw", SIZE, SIZE);
		if (FAILED(hr = IDXGISwapChain_Present(swap, 0, 0)))
			fail("present", hr);
		pump();
	}
	write_text(L"C:\\window.txt", "OK");
	/* Keep the last frame up for a capture; the back buffer is redrawn so that each present shows the same picture. */
	for (int hold = 0; hold < 40; ++hold) {
		const float clear[4] = {0.1f, 0.1f, 0.3f, 1.0f};
		ID3D11DeviceContext_ClearRenderTargetView(context, view, clear);
		ID3D11DeviceContext_Draw(context, 3, 0);
		IDXGISwapChain_Present(swap, 0, 0);
		pump();
		Sleep(100);
	}

	/* Resize: the client area and the swap chain buffers become WIDE by HIGH. */
	RECT bigger = {0, 0, WIDE, HIGH};
	AdjustWindowRect(&bigger, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE);
	SetWindowPos(window, NULL, 0, 0, bigger.right - bigger.left, bigger.bottom - bigger.top, SWP_NOMOVE | SWP_NOZORDER);
	pump();
	{
		/* The client area the window reports after the resize is what the swap chain has to follow. */
		RECT client;
		char text[32];
		GetClientRect(window, &client);
		wsprintfA(text, "%dx%d", (int)(client.right - client.left), (int)(client.bottom - client.top));
		write_text(L"C:\\window_client.txt", text);
	}
	ID3D11DeviceContext_OMSetRenderTargets(context, 0, NULL, NULL);
	ID3D11RenderTargetView_Release(view);
	ID3D11Texture2D_Release(back);
	ID3D11Texture2D_Release(staging);
	if (FAILED(hr = IDXGISwapChain_ResizeBuffers(swap, 0, WIDE, HIGH, DXGI_FORMAT_UNKNOWN, 0)))
		fail("resize", hr);
	if (FAILED(hr = IDXGISwapChain_GetBuffer(swap, 0, &IID_ID3D11Texture2D, (void **)&back)))
		fail("buffer after resize", hr);
	td.Width = WIDE;
	td.Height = HIGH;
	if (FAILED(hr = ID3D11Device_CreateTexture2D(device, &td, NULL, &staging)))
		fail("staging after resize", hr);
	if (FAILED(hr = ID3D11Device_CreateRenderTargetView(device, (ID3D11Resource *)back, NULL, &view)))
		fail("view after resize", hr);
	viewport.Width = WIDE;
	viewport.Height = HIGH;
	ID3D11DeviceContext_OMSetRenderTargets(context, 1, &view, NULL);
	ID3D11DeviceContext_RSSetViewports(context, 1, &viewport);
	for (int frame_number = 0; frame_number < 10; ++frame_number) {
		const float clear[4] = {0.1f, 0.3f, 0.1f, 1.0f};
		ID3D11DeviceContext_ClearRenderTargetView(context, view, clear);
		ID3D11DeviceContext_Draw(context, 3, 0);
		if (frame_number == 9)
			save(context, staging, back, L"C:\\window_resized.raw", WIDE, HIGH);
		if (FAILED(hr = IDXGISwapChain_Present(swap, 0, 0)))
			fail("present after resize", hr);
		pump();
	}
	write_text(L"C:\\window_resized.txt", "OK");
	for (int hold = 0; hold < 200; ++hold) {
		const float clear[4] = {0.1f, 0.3f, 0.1f, 1.0f};
		ID3D11DeviceContext_ClearRenderTargetView(context, view, clear);
		ID3D11DeviceContext_Draw(context, 3, 0);
		IDXGISwapChain_Present(swap, 0, 0);
		pump();
		Sleep(100);
	}
	ExitProcess(0);
}
