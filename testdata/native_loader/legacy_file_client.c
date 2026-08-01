/* Round trips a file through the 16-bit era file functions and returns 0, or the number of the first failing check. */
#include <windows.h>

unsigned int raven_entry(void)
{
	static const char data[] = "legacy file api";
	char back[32];
	for (int index = 0; index < 32; ++index)
		back[index] = 0;
	HFILE file = _lcreat("C:\\legacy.bin", 0);
	if (file == HFILE_ERROR)
		return 1;
	if (_lwrite(file, data, sizeof data) != sizeof data)
		return 2;
	if (_llseek(file, 7, 0) != 7)
		return 3;
	if (_lclose(file) != 0)
		return 4;
	file = _lopen("C:\\legacy.bin", OF_READ);
	if (file == HFILE_ERROR)
		return 5;
	if (_lread(file, back, sizeof data) != sizeof data)
		return 6;
	for (unsigned index = 0; index < sizeof data; ++index)
		if (back[index] != data[index])
			return 7;
	if (_llseek(file, 0, 2) != sizeof data)
		return 8;
	if (_lclose(file) != 0 || _lclose(file) != HFILE_ERROR)
		return 9;
	if (_lopen("C:\\does-not-exist.bin", OF_READ) != HFILE_ERROR)
		return 10;
	return 0;
}
