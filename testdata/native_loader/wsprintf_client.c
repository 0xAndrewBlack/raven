/* Checks wsprintfA and wsprintfW in the guest and returns 0, or the number of the first failing check. */
typedef unsigned short wchar;

extern int __stdcall wsprintfA(char *buffer, const char *format, ...);
extern int __stdcall wsprintfW(wchar *buffer, const wchar *format, ...);

static int same_narrow(const char *left, const char *right)
{
	while (*left && *left == *right) {
		++left;
		++right;
	}
	return *left == *right;
}

static int same_wide(const wchar *left, const char *right)
{
	while (*left && *left == (unsigned char)*right) {
		++left;
		++right;
	}
	return *left == (unsigned char)*right;
}

static int narrow_length(const char *text)
{
	volatile int count = 0;
	while (text[count])
		++count;
	return count;
}

unsigned int raven_entry(void)
{
	char narrow[128];
	wchar wide[128];
	static const wchar wide_text[] = {'h', 'i', 0};
	static const wchar wide_format[] = {'%', 's', '|', '%', 'S', '|', '%', 'd', 0};
	static const wchar wide_word[] = {'w', 'i', 'd', 'e', 0};

	int length = wsprintfA(narrow, "%d|%5d|%-5d|%05d|%x|%X|%s|%c|%u", -42, 42, 42, 42, 255, 255, "abc", 'z', 7);
	if (!same_narrow(narrow, "-42|   42|42   |00042|ff|FF|abc|z|7") || length != narrow_length(narrow))
		return 1;
	length = wsprintfA(narrow, "%S", wide_text);
	if (!same_narrow(narrow, "hi") || length != 2)
		return 2;
	length = wsprintfA(narrow, "%s", "\xe9");
	if ((unsigned char)narrow[0] != 0xe9 || narrow[1] || length != 1)
		return 3;
	length = wsprintfW(wide, wide_format, wide_word, "narrow", 5);
	if (!same_wide(wide, "wide|narrow|5") || length != 13)
		return 4;
	length = wsprintfA(narrow, "100%%");
	if (!same_narrow(narrow, "100%") || length != 4)
		return 5;
	return 0;
}
