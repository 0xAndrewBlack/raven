/* Independent Direct3D 9 workload for a 32-bit program: renders sixty frames into a window with the fixed-function pipeline and presents each.
 * Frame number n clears to a colour that depends on n and draws one red triangle with pre-transformed vertices. The first and the last back
 * buffer are copied with the GPU into system memory and written as RGBA to C:\window_first.raw and C:\window_last.raw; C:\window.txt says OK
 * once every frame was presented. The program then keeps the last frame on screen for a few seconds so that a compositor capture can be
 * compared with the read-back pixels. */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <d3d9.h>

#define SIZE 256
#define FRAMES 60

struct vertex { float x, y, z, w; DWORD color; };
#define FVF (D3DFVF_XYZRHW | D3DFVF_DIFFUSE)

static void write_file(const char *path, const void *data, DWORD size)
{
	HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD written;
	WriteFile(file, data, size, &written, NULL);
	CloseHandle(file);
}

static void say(const char *text)
{
	DWORD length = 0;
	while (text[length])
		++length;
	write_file("C:\\window.txt", text, length);
}

static void fail(const char *step, HRESULT result)
{
	char text[64];
	int length = 0;
	const char *prefix = "FAIL ";
	while (*prefix)
		text[length++] = *prefix++;
	while (*step && length < 40)
		text[length++] = *step++;
	text[length++] = ' ';
	for (int shift = 28; shift >= 0; shift -= 4)
		text[length++] = "0123456789abcdef"[((unsigned)result >> shift) & 15];
	text[length] = 0;
	say(text);
	ExitProcess(1);
}

static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
	if (message == WM_DESTROY) {
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProcA(window, message, wparam, lparam);
}

static void pump(void)
{
	MSG message;
	while (PeekMessageA(&message, NULL, 0, 0, PM_REMOVE)) {
		TranslateMessage(&message);
		DispatchMessageA(&message);
	}
}

typedef IDirect3D9 *(WINAPI *create_function)(UINT);

static void read_back(IDirect3DDevice9 *device, IDirect3DSurface9 *staging, const char *path)
{
	IDirect3DSurface9 *back = NULL;
	HRESULT result = IDirect3DDevice9_GetBackBuffer(device, 0, 0, D3DBACKBUFFER_TYPE_MONO, &back);
	if (result != D3D_OK)
		fail("GetBackBuffer", result);
	result = IDirect3DDevice9_GetRenderTargetData(device, back, staging);
	if (result != D3D_OK)
		fail("GetRenderTargetData", result);
	D3DLOCKED_RECT locked;
	result = IDirect3DSurface9_LockRect(staging, &locked, NULL, D3DLOCK_READONLY);
	if (result != D3D_OK)
		fail("LockRect", result);
	static unsigned char pixels[SIZE * SIZE * 4];
	for (int y = 0; y < SIZE; ++y) {
		const unsigned char *row = (const unsigned char *)locked.pBits + y * locked.Pitch;
		for (int x = 0; x < SIZE; ++x) {
			pixels[(y * SIZE + x) * 4 + 0] = row[x * 4 + 2];
			pixels[(y * SIZE + x) * 4 + 1] = row[x * 4 + 1];
			pixels[(y * SIZE + x) * 4 + 2] = row[x * 4 + 0];
			pixels[(y * SIZE + x) * 4 + 3] = 255;
		}
	}
	IDirect3DSurface9_UnlockRect(staging);
	IDirect3DSurface9_Release(back);
	write_file(path, pixels, sizeof pixels);
}

int raven_entry(void)
{
	WNDCLASSA window_class = {0};
	window_class.lpfnWndProc = procedure;
	window_class.hInstance = GetModuleHandleA(NULL);
	window_class.lpszClassName = "raven_d3d9_window";
	RegisterClassA(&window_class);
	HWND window = CreateWindowExA(0, "raven_d3d9_window", "d3d9", WS_POPUP | WS_VISIBLE, 0, 0, SIZE, SIZE, NULL, NULL, window_class.hInstance, NULL);
	if (!window)
		fail("window", 0);
	HMODULE library = LoadLibraryA("d3d9.dll");
	if (!library)
		fail("d3d9.dll", GetLastError());
	create_function create = (create_function)GetProcAddress(library, "Direct3DCreate9");
	if (!create)
		fail("Direct3DCreate9", 0);
	IDirect3D9 *direct3d = create(D3D_SDK_VERSION);
	if (!direct3d)
		fail("create", 0);
	D3DPRESENT_PARAMETERS parameters = {0};
	parameters.Windowed = TRUE;
	parameters.SwapEffect = D3DSWAPEFFECT_DISCARD;
	parameters.BackBufferFormat = D3DFMT_X8R8G8B8;
	parameters.BackBufferWidth = SIZE;
	parameters.BackBufferHeight = SIZE;
	parameters.BackBufferCount = 1;
	parameters.hDeviceWindow = window;
	parameters.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;
	IDirect3DDevice9 *device = NULL;
	HRESULT result = IDirect3D9_CreateDevice(direct3d, D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, window, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &parameters, &device);
	if (result != D3D_OK)
		fail("CreateDevice", result);
	IDirect3DSurface9 *staging = NULL;
	result = IDirect3DDevice9_CreateOffscreenPlainSurface(device, SIZE, SIZE, D3DFMT_X8R8G8B8, D3DPOOL_SYSTEMMEM, &staging, NULL);
	if (result != D3D_OK)
		fail("CreateOffscreenPlainSurface", result);
	struct vertex triangle[3] = {
		{128.0f, 24.0f, 0.5f, 1.0f, 0xffff0000u},
		{232.0f, 232.0f, 0.5f, 1.0f, 0xffff0000u},
		{24.0f, 232.0f, 0.5f, 1.0f, 0xffff0000u},
	};
	for (int frame = 0; frame < FRAMES; ++frame) {
		const DWORD clear = 0xff000000u | (DWORD)(frame * 4) << 8 | 0x40u;
		result = IDirect3DDevice9_Clear(device, 0, NULL, D3DCLEAR_TARGET, clear, 1.0f, 0);
		if (result != D3D_OK)
			fail("Clear", result);
		result = IDirect3DDevice9_BeginScene(device);
		if (result != D3D_OK)
			fail("BeginScene", result);
		IDirect3DDevice9_SetFVF(device, FVF);
		result = IDirect3DDevice9_DrawPrimitiveUP(device, D3DPT_TRIANGLELIST, 1, triangle, sizeof(struct vertex));
		if (result != D3D_OK)
			fail("DrawPrimitiveUP", result);
		IDirect3DDevice9_EndScene(device);
		if (frame == 0)
			read_back(device, staging, "C:\\window_first.raw");
		if (frame == FRAMES - 1)
			read_back(device, staging, "C:\\window_last.raw");
		result = IDirect3DDevice9_Present(device, NULL, NULL, NULL, NULL);
		if (result != D3D_OK)
			fail("Present", result);
		pump();
	}
	say("OK");
	for (int tick = 0; tick < 100; ++tick) {
		pump();
		Sleep(100);
	}
	return 0;
}
