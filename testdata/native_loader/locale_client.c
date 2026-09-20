#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* Locale information, whether the runtime or the program answers it: lengths, texts, numbers and the failures. */

static int same(const WCHAR *left, const WCHAR *right)
{
	while (*left && *left == *right)
		++left, ++right;
	return *left == *right;
}

int raven_entry(void)
{
	WCHAR text[64];
	for (int round = 0; round < 3; ++round) {
		if (GetLocaleInfoEx(NULL, LOCALE_SDECIMAL, NULL, 0) != 2 || GetLocaleInfoEx(L"en-US", LOCALE_SDECIMAL, text, 64) != 2 || !same(text, L"."))
			return 1;
		if (GetLocaleInfoEx(NULL, LOCALE_SMONTHNAME1, text, 64) != 8 || !same(text, L"January"))
			return 2;
		if (GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SSHORTDATE, text, 64) != 9 || !same(text, L"M/d/yyyy"))
			return 3;
		if (GetLocaleInfoEx(NULL, LOCALE_STIMEFORMAT, text, 64) != 11 || !same(text, L"h:mm:ss tt"))
			return 4;
		DWORD number = 0;
		if (GetLocaleInfoEx(NULL, LOCALE_IFIRSTDAYOFWEEK | LOCALE_RETURN_NUMBER, (LPWSTR)&number, 2) != 2 || number != 6)
			return 5;
		if (GetLocaleInfoEx(NULL, LOCALE_SGROUPING | LOCALE_NOUSEROVERRIDE, text, 64) != 4 || !same(text, L"3;0"))
			return 6;
		SetLastError(0);
		if (GetLocaleInfoEx(NULL, LOCALE_SMONTHNAME1, text, 3) || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			return 7;
		SetLastError(0);
		if (GetLocaleInfoEx(NULL, 0x7f, text, 64) || GetLastError() != ERROR_INVALID_PARAMETER)
			return 8;
		/* The text ends at its terminator and leaves the rest of the buffer alone. */
		text[5] = 0x1234;
		if (GetLocaleInfoEx(NULL, LOCALE_SCURRENCY, text, 64) != 2 || !same(text, L"$") || text[5] != 0x1234)
			return 9;
	}
	return 0;
}
