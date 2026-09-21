/* What a game finds after the OpenAL installer has run: the router library loads from the system directory and answers. It reports
 * device enumeration, which the router itself provides, and names its devices or none; opening a device is left out, as a machine without
 * sound has none to open. Built for both widths; the entry returns the number of the first check that failed. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef char (__cdecl *ExtensionPresent)(void *, const char *);
typedef const char *(__cdecl *DeviceString)(void *, int);

#define DEVICE_SPECIFIER 0x1005

int raven_entry(void)
{
	HMODULE openal = LoadLibraryA("OpenAL32.dll");
	if (!openal)
		return 1;
	const ExtensionPresent present = (ExtensionPresent)GetProcAddress(openal, "alcIsExtensionPresent");
	const DeviceString string = (DeviceString)GetProcAddress(openal, "alcGetString");
	if (!present || !string || !GetProcAddress(openal, "alcOpenDevice") || !GetProcAddress(openal, "alGenSources"))
		return 2;
	if (!present(NULL, "ALC_ENUMERATION_EXT"))
		return 3;
	/* The device list: names each ended by a zero, the list by one more; empty without sound hardware. */
	if (!string(NULL, DEVICE_SPECIFIER))
		return 4;
	return 0;
}
