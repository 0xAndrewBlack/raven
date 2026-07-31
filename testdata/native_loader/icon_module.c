#include <windows.h>
#include "icon_data.h"

__declspec(dllexport) BYTE *icon_data(void)
{
	return color_icon;
}

__declspec(dllexport) DWORD icon_size(void)
{
	return sizeof(color_icon);
}
