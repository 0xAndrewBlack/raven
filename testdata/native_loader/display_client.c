/* Checks the display enumeration answers and returns 0, or the number of the first failing check. */
#include <windows.h>

unsigned int raven_entry(void)
{
	DEVMODEW mode;
	for (unsigned index = 0; index < sizeof mode; ++index)
		((char *)&mode)[index] = 0;
	mode.dmSize = sizeof mode;
	if (!EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &mode))
		return 1;
	if (mode.dmBitsPerPel != 32 || mode.dmPelsWidth == 0 || mode.dmPelsHeight == 0 || mode.dmDisplayFrequency == 0)
		return 2;
	if ((mode.dmFields & (DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL | DM_DISPLAYFREQUENCY)) != (DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL | DM_DISPLAYFREQUENCY))
		return 3;
	if (mode.dmPelsWidth != (DWORD)GetSystemMetrics(SM_CXSCREEN) || mode.dmPelsHeight != (DWORD)GetSystemMetrics(SM_CYSCREEN))
		return 4;
	DEVMODEW listed = mode;
	if (!EnumDisplaySettingsW(L"\\\\.\\DISPLAY1", 0, &listed) || listed.dmPelsWidth != mode.dmPelsWidth)
		return 5;
	if (EnumDisplaySettingsW(NULL, 1, &listed))
		return 6;
	if (EnumDisplaySettingsW(L"\\\\.\\DISPLAY9", 0, &listed))
		return 7;
	UINT32 paths = 7, modes = 7;
	if (GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &paths, &modes) != ERROR_NOT_SUPPORTED || paths || modes)
		return 8;
	return 0;
}
