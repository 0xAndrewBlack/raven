#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <mmsystem.h>
#include <dsound.h>

typedef HRESULT (WINAPI *create_function)(const GUID *, IDirectSound8 **, void *);

int raven_entry(void)
{
	HMODULE library = LoadLibraryA("dsound.dll");
	if (!library)
		return 1;
	create_function create = (create_function)GetProcAddress(library, "DirectSoundCreate8");
	if (!create)
		return 2;
	IDirectSound8 *sound = NULL;
	if (create(NULL, &sound, NULL) != DS_OK || !sound)
		return 3;
	if (IDirectSound8_SetCooperativeLevel(sound, GetDesktopWindow(), DSSCL_PRIORITY) != DS_OK)
		return 4;
	WAVEFORMATEX format = {0};
	format.wFormatTag = WAVE_FORMAT_PCM;
	format.nChannels = 2;
	format.nSamplesPerSec = 44100;
	format.wBitsPerSample = 16;
	format.nBlockAlign = 4;
	format.nAvgBytesPerSec = 176400;
	DSBUFFERDESC description = {0};
	description.dwSize = sizeof description;
	description.dwFlags = DSBCAPS_GETCURRENTPOSITION2 | DSBCAPS_CTRLVOLUME;
	description.dwBufferBytes = 17640;
	description.lpwfxFormat = &format;
	IDirectSoundBuffer *buffer = NULL;
	if (IDirectSound8_CreateSoundBuffer(sound, &description, &buffer, NULL) != DS_OK || !buffer)
		return 5;
	void *first = NULL, *second = NULL;
	DWORD first_bytes = 0, second_bytes = 0;
	if (IDirectSoundBuffer_Lock(buffer, 100, 17640, &first, &first_bytes, &second, &second_bytes, 0) != DS_OK)
		return 6;
	if (!first || first_bytes != 17540 || !second || second_bytes != 100)
		return 7;
	for (DWORD index = 0; index < first_bytes; ++index)
		((unsigned char *)first)[index] = (unsigned char)index;
	if (IDirectSoundBuffer_Unlock(buffer, first, first_bytes, second, second_bytes) != DS_OK)
		return 8;
	DWORD status = 99;
	if (IDirectSoundBuffer_GetStatus(buffer, &status) != DS_OK || status != 0)
		return 9;
	if (IDirectSoundBuffer_Play(buffer, 0, 0, 0) != DS_OK)
		return 10;
	if (IDirectSoundBuffer_GetStatus(buffer, &status) != DS_OK || !(status & DSBSTATUS_PLAYING))
		return 11;
	DWORD play = 0, write = 0;
	Sleep(30);
	if (IDirectSoundBuffer_GetCurrentPosition(buffer, &play, &write) != DS_OK || play == 0)
		return 12;
	/* One tenth of a second of audio at 176400 bytes per second: playback ends by itself. */
	Sleep(200);
	if (IDirectSoundBuffer_GetStatus(buffer, &status) != DS_OK || (status & DSBSTATUS_PLAYING))
		return 13;
	IDirectSoundBuffer *same = NULL;
	if (IDirectSoundBuffer_QueryInterface(buffer, &IID_IDirectSoundBuffer, (void **)&same) != DS_OK || same != buffer)
		return 14;
	if (IDirectSoundBuffer_Release(same) != 1 || IDirectSoundBuffer_Release(buffer) != 0 || IDirectSound8_Release(sound) != 0)
		return 15;
	return 0;
}
