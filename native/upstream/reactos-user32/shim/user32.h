/* Replacement for the upstream private header: it keeps the public and shared-structure includes and drops the kernel-mode ones. */
#pragma once
#include <stdio.h>
#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#define OEMRESOURCE
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
#include <winreg.h>
#include <windowsx.h>
#include <undocuser.h>
#include <wine/unicode.h>
#include <wine/debug.h>
#include <imm.h>
#include <immdev.h>
#include <imm32_undoc.h>
#ifndef _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
#endif
typedef const char *PCSZ;
typedef USHORT RTL_ATOM, *PRTL_ATOM;
typedef LONG NTSTATUS;
typedef struct _OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
/* Only the client information array is read; its upstream offset in the thread block is kept. */
typedef struct _TEB { char reserved[0x800]; void *Win32ClientInfo[62]; } TEB, *PTEB;
typedef struct _STRING { USHORT Length; USHORT MaximumLength; PCHAR Buffer; } STRING, *PSTRING;
#define FASTCALL
#include <ntusrtyp.h>
#include <ntuser.h>
#include <controls.h>
#include <regcontrol.h>
#include <ddeml.h>
#include <dde.h>
#define ASSERT(condition) ((void)0)
BOOLEAN NTAPI RtlIsThreadWithinLoaderCallout(VOID);
#include <user32p.h>
#include <user_x.h>
