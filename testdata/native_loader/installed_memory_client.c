#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>

int raven_entry(void)
{
	struct { ULONGLONG before, value, after; } memory = {0x1122334455667788ULL, 0xfedcba9876543210ULL, 0x8877665544332211ULL};
	SetLastError(71);
	if (GetPhysicallyInstalledSystemMemory(NULL) || GetLastError() != ERROR_INVALID_PARAMETER) return 1;
	SetLastError(71);
	BOOL result = GetPhysicallyInstalledSystemMemory(&memory.value);
	DWORD error = GetLastError();
	if (result) {
		if (!memory.value || memory.value == 0xfedcba9876543210ULL || GetLastError() != 71) return 2;
	} else {
		if (memory.value != 0xfedcba9876543210ULL ||
			(GetLastError() != ERROR_NOT_SUPPORTED && GetLastError() != ERROR_INVALID_DATA)) return 3;
	}
	if (memory.before != 0x1122334455667788ULL || memory.after != 0x8877665544332211ULL) return 4;
	char expected[32];
	if (GetEnvironmentVariableA("RAVEN_TEST_MEMORY_KIB", expected, sizeof(expected))) {
		ULONGLONG value = 0;
		for (unsigned index = 0; expected[index]; ++index) {
			if (expected[index] < '0' || expected[index] > '9') return 5;
			value = value * 10 + expected[index] - '0';
		}
		if (value ? !result || memory.value != value : result || error != ERROR_INVALID_DATA) return 6;
	}
	return 0;
}
