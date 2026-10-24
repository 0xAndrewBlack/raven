#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int raven_entry(void)
{
	UINT count = 99;
	if (GetRawInputDeviceList(NULL, &count, sizeof(RAWINPUTDEVICELIST)) || count != 1)
		return 1;
	RAWINPUTDEVICELIST devices[2] = {{(HANDLE)0x55, 0x55}, {(HANDLE)0x66, 0x66}};
	count = 0;
	SetLastError(0);
	if (GetRawInputDeviceList(devices, &count, sizeof(devices[0])) != (UINT)-1 || GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
		count != 1 || devices[0].hDevice != (HANDLE)0x55 || devices[0].dwType != 0x55)
		return 2;
	count = 2;
	if (GetRawInputDeviceList(devices, &count, sizeof(devices[0])) != 1 || count != 2 || !devices[0].hDevice ||
		devices[0].dwType != RIM_TYPEMOUSE || devices[1].hDevice != (HANDLE)0x66 || devices[1].dwType != 0x66)
		return 3;
	UINT size = 0;
	if (GetRawInputDeviceInfoW(devices[0].hDevice, RIDI_DEVICEINFO, NULL, &size) || size != sizeof(RID_DEVICE_INFO))
		return 4;
	RID_DEVICE_INFO info = {0};
	info.cbSize = sizeof(info);
	info.dwType = 0x55;
	size = sizeof(info) - 1;
	if (GetRawInputDeviceInfoW(devices[0].hDevice, RIDI_DEVICEINFO, &info, &size) != (UINT)-1 ||
		GetLastError() != ERROR_INSUFFICIENT_BUFFER || size != sizeof(info) || info.dwType != 0x55)
		return 5;
	if (GetRawInputDeviceInfoW(devices[0].hDevice, RIDI_DEVICEINFO, &info, &size) != sizeof(info) ||
		info.dwType != devices[0].dwType || info.mouse.dwNumberOfButtons != 3 || !info.mouse.fHasHorizontalWheel)
		return 6;
	UINT ansi_size = 0, wide_size = 0;
	if (GetRawInputDeviceInfoA(devices[0].hDevice, RIDI_DEVICENAME, NULL, &ansi_size) ||
		GetRawInputDeviceInfoW(devices[0].hDevice, RIDI_DEVICENAME, NULL, &wide_size) ||
		ansi_size < 2 || ansi_size != wide_size || ansi_size > 128)
		return 7;
	_Alignas(4) char ansi[128];
	_Alignas(4) WCHAR wide[128];
	for (UINT index = 0; index < 128; ++index) { ansi[index] = 0x5a; wide[index] = 0x5555; }
	size = ansi_size - 1;
	if (GetRawInputDeviceInfoA(devices[0].hDevice, RIDI_DEVICENAME, ansi, &size) != (UINT)-1 ||
		GetLastError() != ERROR_INSUFFICIENT_BUFFER || size != ansi_size || ansi[0] != 0x5a)
		return 8;
	if (GetRawInputDeviceInfoA(devices[0].hDevice, RIDI_DEVICENAME, ansi, &ansi_size) == (UINT)-1 ||
		GetRawInputDeviceInfoW(devices[0].hDevice, RIDI_DEVICENAME, wide, &wide_size) == (UINT)-1 ||
		ansi[ansi_size - 1] || wide[wide_size - 1] || ansi[ansi_size] != 0x5a || wide[wide_size] != 0x5555)
		return 9;
	for (UINT index = 0; index < ansi_size; ++index)
		if ((BYTE)ansi[index] != wide[index]) return 10;
	size = sizeof(info);
	info.cbSize = 0;
	if (GetRawInputDeviceInfoW(devices[0].hDevice, RIDI_DEVICEINFO, &info, &size) != (UINT)-1 || GetLastError() != ERROR_INVALID_PARAMETER)
		return 11;
	if (GetRawInputDeviceInfoW((HANDLE)0x123456, RIDI_DEVICEINFO, NULL, &size) != (UINT)-1 || GetLastError() != ERROR_INVALID_HANDLE)
		return 12;
	if (GetRawInputDeviceInfoW(devices[0].hDevice, 0, NULL, &size) != (UINT)-1 || GetLastError() != ERROR_INVALID_PARAMETER)
		return 13;
	if (GetRawInputDeviceList(NULL, NULL, sizeof(devices[0])) != (UINT)-1 || GetLastError() != ERROR_INVALID_PARAMETER ||
		GetRawInputDeviceList(NULL, &count, sizeof(devices[0]) - 1) != (UINT)-1 || GetLastError() != ERROR_INVALID_PARAMETER)
		return 14;
	return 0;
}
