/* Direct3D 11 presentation rate: the swap chain and the triangle of window.c, presented as fast as the runtime allows. After a warm-up
 * the program times FRAMES presents with the performance counter and writes "frames microseconds" to C:\present_rate.txt, so the rate
 * is measured inside the program and does not depend on the resolution of file times. */
#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include "tri_shaders.h"

#define SIZE 256
#define WARM 60
#define FRAMES 2000

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
	wsprintfA(text, "FAIL %s %08lx", step, (unsigned long)hr);
	write_text(L"C:\\present_rate.txt", text);
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

void __stdcall entry(void)
{
	HINSTANCE instance = GetModuleHandleW(NULL);
	WNDCLASSEXW class_info = {sizeof class_info, 0, procedure, 0, 0, instance, NULL, LoadCursorW(NULL, (LPCWSTR)IDC_ARROW), (HBRUSH)(COLOR_WINDOW + 1), NULL, L"RavenRate", NULL};
	RegisterClassExW(&class_info);
	RECT frame = {0, 0, SIZE, SIZE};
	AdjustWindowRect(&frame, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE);
	HWND window = CreateWindowExW(0, L"RavenRate", L"Direct3D 11 present rate", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, 100, 100,
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
	ID3D11Texture2D *back = NULL;
	if (FAILED(hr = IDXGISwapChain_GetBuffer(swap, 0, &IID_ID3D11Texture2D, (void **)&back)))
		fail("buffer", hr);
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

	LARGE_INTEGER frequency, start, end;
	QueryPerformanceFrequency(&frequency);
	for (int frame_number = 0; frame_number < WARM + FRAMES; ++frame_number) {
		if (frame_number == WARM)
			QueryPerformanceCounter(&start);
		const float clear[4] = {0.1f + 0.5f * (float)(frame_number % 64) / 63, 0.1f, 0.3f, 1.0f};
		ID3D11DeviceContext_ClearRenderTargetView(context, view, clear);
		ID3D11DeviceContext_Draw(context, 3, 0);
		if (FAILED(hr = IDXGISwapChain_Present(swap, 0, 0)))
			fail("present", hr);
		pump();
	}
	QueryPerformanceCounter(&end);
	char text[64];
	wsprintfA(text, "%d %lu", FRAMES, (unsigned long)((end.QuadPart - start.QuadPart) * 1000000 / frequency.QuadPart));
	write_text(L"C:\\present_rate.txt", text);
	ExitProcess(0);
}
