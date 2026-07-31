#include <windef.h>
#include <wine/debug.h>

/* The component never traces: every channel reports no enabled classes and the formatters return empty text. */
unsigned char __cdecl __wine_dbg_get_channel_flags(struct __wine_debug_channel *channel)
{
	return 0;
}

const char *__cdecl wine_dbg_sprintf(const char *format, ...)
{
	return "";
}

const char *wine_dbgstr_an(const char *string, int count)
{
	return "";
}

const char *wine_dbgstr_wn(const WCHAR *string, int count)
{
	return "";
}

int __cdecl ros_dbg_log(enum __wine_debug_class class, struct __wine_debug_channel *channel, const char *file,
	const char *function, const int line, const char *format, ...)
{
	return 0;
}
