/* Creates a Direct3D 12 device and writes the result and the highest feature level it supports to C:\d3d12.txt. */
#define COBJMACROS
#include <windows.h>
#include <d3d12.h>

static void write_text(const char *text)
{
	HANDLE f = CreateFileW(L"C:\\d3d12.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD n;
	WriteFile(f, text, lstrlenA(text), &n, NULL);
	CloseHandle(f);
}

static void hex(char *out, unsigned value)
{
	for (int shift = 28; shift >= 0; shift -= 4)
		*out++ = "0123456789abcdef"[(value >> shift) & 15];
	*out = 0;
}

void __stdcall entry(void)
{
	ID3D12Device *device = NULL;
	HRESULT hr = D3D12CreateDevice(NULL, D3D_FEATURE_LEVEL_11_0, &IID_ID3D12Device, (void **)&device);
	char text[64] = "hr=";
	hex(text + 3, (unsigned)hr);
	if (SUCCEEDED(hr)) {
		D3D12_FEATURE_DATA_FEATURE_LEVELS levels = {0};
		static const D3D_FEATURE_LEVEL wanted[] = {D3D_FEATURE_LEVEL_12_2, D3D_FEATURE_LEVEL_12_1, D3D_FEATURE_LEVEL_12_0, D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
		levels.NumFeatureLevels = 5;
		levels.pFeatureLevelsRequested = wanted;
		HRESULT query = ID3D12Device_CheckFeatureSupport(device, D3D12_FEATURE_FEATURE_LEVELS, &levels, sizeof levels);
		lstrcatA(text, " level=");
		hex(text + lstrlenA(text), (unsigned)levels.MaxSupportedFeatureLevel);
		lstrcatA(text, SUCCEEDED(query) ? " query=ok" : " query=failed");
	}
	write_text(text);
	ExitProcess(SUCCEEDED(hr) ? 0 : 1);
}
