#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stddef.h>

typedef size_t (__cdecl *strlen_function)(const char *);
typedef void *(__cdecl *malloc_function)(size_t);
typedef void *(__cdecl *realloc_function)(void *, size_t);
typedef void (__cdecl *free_function)(void *);
typedef void *(__cdecl *memcpy_function)(void *, const void *, size_t);
typedef int (__cdecl *strcmp_function)(const char *, const char *);
typedef double (__cdecl *pow_function)(double, double);
typedef double (__cdecl *cos_function)(double);
typedef int (__cdecl *vsprintf_function)(unsigned long long, char *, size_t, const char *, void *, va_list);

static vsprintf_function format;

static int formatted(char *buffer, size_t size, const char *text, ...)
{
	va_list arguments;
	va_start(arguments, text);
	int length = format(0, buffer, size, text, NULL, arguments);
	va_end(arguments);
	return length;
}

int raven_entry(void)
{
	HMODULE crt = LoadLibraryA("api-ms-win-crt-string-l1-1-0.dll");
	HMODULE heap = LoadLibraryA("ucrtbase.dll");
	if (!crt || !heap)
		return 1;
	strlen_function length = (strlen_function)GetProcAddress(heap, "strlen");
	malloc_function allocate = (malloc_function)GetProcAddress(heap, "malloc");
	realloc_function reallocate = (realloc_function)GetProcAddress(heap, "realloc");
	free_function release = (free_function)GetProcAddress(heap, "free");
	memcpy_function copy = (memcpy_function)GetProcAddress(heap, "memcpy");
	strcmp_function compare = (strcmp_function)GetProcAddress(heap, "strcmp");
	pow_function power = (pow_function)GetProcAddress(heap, "pow");
	cos_function cosine = (cos_function)GetProcAddress(heap, "cos");
	format = (vsprintf_function)GetProcAddress(heap, "__stdio_common_vsprintf");
	if (!length || !allocate || !reallocate || !release || !copy || !compare || !power || !cosine || !format)
		return 2;
	if (length("hello") != 5 || compare("abc", "abd") >= 0)
		return 3;
	char *block = allocate(16);
	if (!block)
		return 4;
	copy(block, "0123456789abcde", 16);
	block = reallocate(block, 4096);
	if (!block || compare(block, "0123456789abcde") != 0)
		return 5;
	release(block);
	char text[64];
	if (formatted(text, sizeof text, "x=%d y=%s z=%5.2f", 42, "hi", 3.14159) <= 0 || compare(text, "x=42 y=hi z= 3.14") != 0)
		return 6;
	if (power(2.0, 10.0) != 1024.0 || cosine(0.0) != 1.0)
		return 7;
	return 0;
}
