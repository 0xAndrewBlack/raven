/* The older msvcrt.dll entry points that programs import next to the Universal CRT ones: bounded formatting with the
 * historic truncation rules, wide scanning, wide character classes and the C++ allocation operators. Included by ucrtbase.c. */

#define SCAN_END (-1)

CRT int iswalnum(wint_t c) { return iswdigit(c) || iswalpha(c); }
CRT int iswcntrl(wint_t c) { return c < 32 || (c >= 0x7f && c < 0xa0); }
CRT int iswupper(wint_t c) { return towlower(c) != c; }
CRT int iswlower(wint_t c) { return towupper(c) != c; }
CRT int iswxdigit(wint_t c) { return iswdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
CRT int iswpunct(wint_t c) { return c > 32 && c < 127 && !iswalnum(c); }

CRT int _wcsnicmp(const wchar_t *a, const wchar_t *b, size_t count)
{
	while (count--) {
		wint_t x = towlower(*a), y = towlower(*b);
		if (x != y)
			return x < y ? -1 : 1;
		if (!x)
			return 0;
		++a;
		++b;
	}
	return 0;
}

CRT wchar_t *_wcslwr(wchar_t *text)
{
	for (wchar_t *at = text; *at; ++at)
		*at = towlower(*at);
	return text;
}

CRT wchar_t *_wcsupr(wchar_t *text)
{
	for (wchar_t *at = text; *at; ++at)
		*at = towupper(*at);
	return text;
}

CRT wchar_t *_wcsdup(const wchar_t *text)
{
	if (!text)
		return NULL;
	size_t size = (wcslen(text) + 1) * sizeof(wchar_t);
	wchar_t *copy = malloc(size);
	if (copy)
		memcpy(copy, text, size);
	return copy;
}

CRT void *bsearch(const void *key, const void *base, size_t count, size_t size, int (__cdecl *compare)(const void *, const void *))
{
	const char *low = base;
	while (count) {
		const char *middle = low + (count / 2) * size;
		const int order = compare(key, middle);
		if (!order)
			return (void *)middle;
		if (order > 0) {
			low = middle + size;
			count -= count / 2 + 1;
		} else
			count /= 2;
	}
	return NULL;
}

/* The count of characters a formatted string takes, with the historic rule: when the text does not fit, no terminator is
 * written and the result is -1. */
CRT int _vsnprintf(char *buffer, size_t count, const char *text, va_list arguments)
{
	va_list again;
	int length;
	char *whole;
	va_copy(again, arguments);
	length = __stdio_common_vsprintf(0, buffer, count, text, NULL, arguments);
	if (length >= 0 && (size_t)length < count) {
		va_end(again);
		return length;
	}
	/* Truncated: the buffer holds count - 1 characters and a terminator, but the last place must hold a character. */
	if (length >= 0 && count) {
		whole = malloc((size_t)length + 1);
		if (whole) {
			__stdio_common_vsprintf(0, whole, (size_t)length + 1, text, NULL, again);
			memcpy(buffer, whole, count);
			free(whole);
		}
	}
	va_end(again);
	return -1;
}

CRT int _snprintf(char *buffer, size_t count, const char *text, ...)
{
	va_list arguments;
	int result;
	va_start(arguments, text);
	result = _vsnprintf(buffer, count, text, arguments);
	va_end(arguments);
	return result;
}

/* The unbounded form: the caller sized the buffer. */
CRT int sprintf(char *buffer, const char *text, ...)
{
	va_list arguments;
	int result;
	va_start(arguments, text);
	result = __stdio_common_vsprintf(0, buffer, (size_t)-1, text, NULL, arguments);
	va_end(arguments);
	return result;
}

CRT int _vsnwprintf(wchar_t *buffer, size_t count, const wchar_t *text, va_list arguments)
{
	va_list again;
	int length;
	wchar_t *whole;
	va_copy(again, arguments);
	length = __stdio_common_vswprintf(0, buffer, count, text, NULL, arguments);
	if (length >= 0 && (size_t)length < count) {
		va_end(again);
		return length;
	}
	if (length >= 0 && count) {
		whole = malloc(((size_t)length + 1) * sizeof(wchar_t));
		if (whole) {
			__stdio_common_vswprintf(0, whole, (size_t)length + 1, text, NULL, again);
			memcpy(buffer, whole, count * sizeof(wchar_t));
			free(whole);
		}
	}
	va_end(again);
	return -1;
}

CRT int _snwprintf(wchar_t *buffer, size_t count, const wchar_t *text, ...)
{
	va_list arguments;
	int result;
	va_start(arguments, text);
	result = _vsnwprintf(buffer, count, text, arguments);
	va_end(arguments);
	return result;
}

/* ---- wide scanning ---- */

static int scan_digit(wchar_t c, int base)
{
	int value = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 99;
	return value < base ? value : -1;
}

static int scan_wide(const wchar_t *input, const wchar_t *format, va_list arguments)
{
	const wchar_t *start = input;
	int assigned = 0, converted_any = 0;
	while (*format) {
		wchar_t c = *format++;
		int suppress = 0, width = 0, size = 0;
		if (iswspace(c)) {
			while (iswspace(*input))
				++input;
			continue;
		}
		if (c != '%') {
			if (*input != c)
				return assigned || converted_any ? assigned : (*input ? assigned : SCAN_END);
			++input;
			continue;
		}
		c = *format++;
		if (c == '%') {
			while (iswspace(*input))
				++input;
			if (*input != '%')
				return assigned;
			++input;
			continue;
		}
		if (c == '*') {
			suppress = 1;
			c = *format++;
		}
		while (c >= '0' && c <= '9') {
			width = width * 10 + (c - '0');
			c = *format++;
		}
		if (c == 'h') {
			size = -1;
			c = *format++;
		} else if (c == 'l') {
			size = 1;
			c = *format++;
			if (c == 'l') {
				size = 2;
				c = *format++;
			}
		} else if (c == 'I' && format[0] == '6' && format[1] == '4') {
			size = 2;
			format += 2;
			c = *format++;
		}
		if (c == 'n') {
			if (!suppress)
				*va_arg(arguments, int *) = (int)(input - start);
			continue;
		}
		if (c != 'c' && c != '[')
			while (iswspace(*input))
				++input;
		if (!*input)
			return assigned || converted_any ? assigned : SCAN_END;
		if (c == 'd' || c == 'i' || c == 'u' || c == 'x' || c == 'X' || c == 'o') {
			int base = c == 'x' || c == 'X' ? 16 : c == 'o' ? 8 : c == 'i' ? 0 : 10, negative = 0, digits = 0, remaining = width ? width : 1 << 30;
			unsigned long long value = 0;
			if (*input == '-' || *input == '+') {
				negative = *input == '-';
				++input;
				--remaining;
			}
			if ((base == 0 || base == 16) && remaining > 1 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X') && scan_digit(input[2], 16) >= 0) {
				input += 2;
				remaining -= 2;
				base = 16;
			} else if (base == 0) {
				base = input[0] == '0' ? 8 : 10;
			}
			while (remaining > 0 && scan_digit(*input, base) >= 0) {
				value = value * (unsigned)base + (unsigned)scan_digit(*input, base);
				++input;
				--remaining;
				++digits;
			}
			if (!digits)
				return assigned;
			if (negative)
				value = (unsigned long long)(-(long long)value);
			if (!suppress) {
				if (size == 2)
					*va_arg(arguments, long long *) = (long long)value;
				else if (size == -1)
					*va_arg(arguments, short *) = (short)value;
				else
					*va_arg(arguments, int *) = (int)value;
				++assigned;
			}
			converted_any = 1;
		} else if (c == 's') {
			int remaining = width ? width : 1 << 30;
			wchar_t *wide = !suppress && size >= 0 ? va_arg(arguments, wchar_t *) : NULL;
			char *narrow = !suppress && size < 0 ? va_arg(arguments, char *) : NULL;
			size_t written = 0;
			while (remaining-- > 0 && *input && !iswspace(*input)) {
				if (wide)
					wide[written++] = *input;
				else if (narrow)
					narrow[written++] = *input < 256 ? (char)*input : '?';
				++input;
			}
			if (wide)
				wide[written] = 0;
			else if (narrow)
				narrow[written] = 0;
			if (!suppress)
				++assigned;
			converted_any = 1;
		} else if (c == 'c') {
			int remaining = width ? width : 1;
			wchar_t *wide = !suppress && size >= 0 ? va_arg(arguments, wchar_t *) : NULL;
			char *narrow = !suppress && size < 0 ? va_arg(arguments, char *) : NULL;
			size_t written = 0;
			while (remaining-- > 0 && *input) {
				if (wide)
					wide[written++] = *input;
				else if (narrow)
					narrow[written++] = *input < 256 ? (char)*input : '?';
				++input;
			}
			if (!written)
				return assigned;
			if (!suppress)
				++assigned;
			converted_any = 1;
		} else if (c == '[') {
			int invert = 0, remaining = width ? width : 1 << 30;
			const wchar_t *set, *end;
			wchar_t *wide = !suppress && size >= 0 ? va_arg(arguments, wchar_t *) : NULL;
			char *narrow = !suppress && size < 0 ? va_arg(arguments, char *) : NULL;
			size_t written = 0;
			if (*format == '^') {
				invert = 1;
				++format;
			}
			set = format;
			if (*format == ']')
				++format;
			while (*format && *format != ']')
				++format;
			end = format;
			if (*format == ']')
				++format;
			while (remaining-- > 0 && *input) {
				int member = 0;
				const wchar_t *scan;
				for (scan = set; scan < end; ++scan) {
					if (scan + 2 < end && scan[1] == '-') {
						if (*input >= scan[0] && *input <= scan[2])
							member = 1;
						scan += 2;
					} else if (*scan == *input) {
						member = 1;
					}
				}
				if (member == invert)
					break;
				if (wide)
					wide[written++] = *input;
				else if (narrow)
					narrow[written++] = *input < 256 ? (char)*input : '?';
				++input;
			}
			if (!written)
				return assigned;
			if (wide)
				wide[written] = 0;
			else if (narrow)
				narrow[written] = 0;
			if (!suppress)
				++assigned;
			converted_any = 1;
		} else {
			return assigned;
		}
	}
	return assigned;
}

CRT int vswscanf(const wchar_t *input, const wchar_t *format, va_list arguments) { return scan_wide(input, format, arguments); }

CRT int swscanf(const wchar_t *input, const wchar_t *format, ...)
{
	va_list arguments;
	int result;
	va_start(arguments, format);
	result = scan_wide(input, format, arguments);
	va_end(arguments);
	return result;
}

/* ---- time and startup ---- */

CRT long time(long *result)
{
	FILETIME now;
	unsigned long long ticks;
	long seconds;
	GetSystemTimeAsFileTime(&now);
	ticks = ((unsigned long long)now.dwHighDateTime << 32) | now.dwLowDateTime;
	seconds = (long)((ticks - 116444736000000000ULL) / 10000000ULL);
	if (result)
		*result = seconds;
	return seconds;
}

static wchar_t *no_wide_environment[1];

CRT int __wgetmainargs(int *count, wchar_t ***vector, wchar_t ***environment_out, int wildcard, void *startup)
{
	if (!wide_argument_vector)
		_configure_wide_argv(1);
	*count = argument_count;
	*vector = wide_argument_vector;
	*environment_out = no_wide_environment;
	return 0;
}

/* ---- C++ allocation: the operators of the 32-bit Microsoft ABI, which ucrtbase32.def exports under their decorated names ---- */

CRT void *raven_operator_new(size_t size) { return malloc(size); }
CRT void raven_operator_delete(void *block) { free(block); }
