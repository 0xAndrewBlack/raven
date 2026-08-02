#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <d3d9.h>

typedef IDirect3D9 *(WINAPI *create_function)(UINT);

int raven_entry(void)
{
	HMODULE library = LoadLibraryA("d3d9.dll");
	if (!library)
		return 1;
	create_function create = (create_function)GetProcAddress(library, "Direct3DCreate9");
	if (!create)
		return 2;
	IDirect3D9 *direct3d = create(D3D_SDK_VERSION);
	if (!direct3d)
		return 3;
	if (IDirect3D9_AddRef(direct3d) != 2 || IDirect3D9_Release(direct3d) != 1)
		return 4;
	IDirect3DDevice9 *device = NULL;
	D3DPRESENT_PARAMETERS parameters = {0};
	if (IDirect3D9_CreateDevice(direct3d, 0, D3DDEVTYPE_HAL, NULL, 0, &parameters, &device) != S_OK || !device)
		return 5;
	if (IDirect3DDevice9_AddRef(device) != 2 || IDirect3DDevice9_Release(device) != 1)
		return 6;
	if (IDirect3DDevice9_Release(device) != 0 || IDirect3D9_Release(direct3d) != 0)
		return 7;
	return 0;
}
