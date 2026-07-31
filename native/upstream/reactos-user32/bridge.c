#include <user32.h>

/* Process-wide state and kernel services the upstream control and dialog sources expect, rebuilt on public calls. */

HINSTANCE User32Instance;
static SERVERINFO server_info;
PSERVERINFO gpsi = &server_info;
USERAPIHOOK guah;
BOOLEAN gfServerProcess;
Imm32ApiTable gImmApiEntries;

static const WCHAR function_property[] = {'R','a','v','e','n','F','n','i','d',0};

/* Control and dialog code reads these fields through a window pointer; the values are sampled per call. */
PWND FASTCALL ValidateHwnd(HWND window)
{
	static WND ring[8];
	static unsigned next;
	WND *record;
	RECT rectangle;
	POINT origin = {0, 0};
	if (!IsWindow(window))
		return NULL;
	record = &ring[next++ & 7];
	ZeroMemory(record, sizeof *record);
	record->fnid = (WORD)(ULONG_PTR)GetPropW(window, function_property);
	record->style = (DWORD)GetWindowLongW(window, GWL_STYLE);
	record->ExStyle = (DWORD)GetWindowLongW(window, GWL_EXSTYLE);
	record->cbwndExtra = (int)GetClassLongW(window, GCL_CBWNDEXTRA);
	/* Every window follows the Windows 4.0 behavior; dialog windows are recognized by their class procedure. */
	record->state2 = WNDS2_WIN40COMPAT;
	GetWindowRect(window, &record->rcWindow);
	GetClientRect(window, &rectangle);
	ClientToScreen(window, &origin);
	OffsetRect(&rectangle, origin.x, origin.y);
	record->rcClient = rectangle;
	return record;
}

BOOL NTAPI NtUserSetWindowFNID(HWND window, WORD function)
{
	return SetPropW(window, function_property, (HANDLE)(ULONG_PTR)function);
}

DWORD NTAPI NtUserAlterWindowStyle(HWND window, DWORD index, LONG value)
{
	return (DWORD)SetWindowLongW(window, (int)index, value);
}

BOOL NTAPI NtUserInvalidateRect(HWND window, CONST RECT *rectangle, BOOL erase)
{
	return InvalidateRect(window, rectangle, erase);
}

BOOL NTAPI NtUserInvalidateRgn(HWND window, HRGN region, BOOL erase)
{
	return InvalidateRgn(window, region, erase);
}

BOOL NTAPI NtUserRedrawWindow(HWND window, CONST RECT *rectangle, HRGN region, UINT flags)
{
	return RedrawWindow(window, rectangle, region, flags);
}

HDC NTAPI NtUserGetDC(HWND window)
{
	return GetDC(window);
}

HDC NTAPI NtUserGetDCEx(HWND window, HANDLE region, ULONG flags)
{
	return GetDCEx(window, region, flags);
}

HDC NTAPI NtUserBeginPaint(HWND window, PAINTSTRUCT *paint)
{
	return BeginPaint(window, paint);
}

BOOL NTAPI NtUserEndPaint(HWND window, CONST PAINTSTRUCT *paint)
{
	return EndPaint(window, paint);
}

HWND NTAPI NtUserSetFocus(HWND window)
{
	return SetFocus(window);
}

HWND NTAPI NtUserSetCapture(HWND window)
{
	return SetCapture(window);
}

HWND NTAPI NtUserSetActiveWindow(HWND window)
{
	return SetActiveWindow(window);
}

HWND NTAPI NtUserGetForegroundWindow(VOID)
{
	return GetForegroundWindow();
}

/* The upstream header turns ShowScrollBar into a kernel call, so the real function is reached under its import name. */
extern BOOL WINAPI raven_show_scroll_bar(HWND window, int bar, BOOL show) __asm__("ShowScrollBar");

DWORD NTAPI NtUserShowScrollBar(HWND window, int bar, DWORD show)
{
	return raven_show_scroll_bar(window, bar, show);
}

BOOL NTAPI NtUserSetWindowPos(HWND window, HWND after, int x, int y, int width, int height, UINT flags)
{
	return SetWindowPos(window, after, x, y, width, height, flags);
}

BOOL NTAPI NtUserMoveWindow(HWND window, int x, int y, int width, int height, BOOL repaint)
{
	return MoveWindow(window, x, y, width, height, repaint);
}

BOOL NTAPI NtUserShowWindow(HWND window, LONG command)
{
	return ShowWindow(window, command);
}

HWND NTAPI NtUserSetParent(HWND child, HWND parent)
{
	return SetParent(child, parent);
}

BOOLEAN NTAPI NtUserDestroyWindow(HWND window)
{
	return DestroyWindow(window);
}

BOOL NTAPI NtUserDestroyMenu(HMENU menu)
{
	return DestroyMenu(menu);
}

BOOL NTAPI NtUserFlashWindowEx(PFLASHWINFO info)
{
	return TRUE;
}

UINT_PTR NTAPI NtUserSetTimer(HWND window, UINT_PTR identifier, UINT elapse, TIMERPROC procedure)
{
	return SetTimer(window, identifier, elapse, procedure);
}

UINT_PTR NTAPI NtUserSetSystemTimer(HWND window, UINT_PTR identifier, UINT elapse, TIMERPROC procedure)
{
	return SetSystemTimer(window, identifier, elapse, procedure);
}

BOOL NTAPI NtUserKillTimer(HWND window, UINT_PTR identifier)
{
	return KillTimer(window, identifier);
}

BOOL NTAPI NtUserCreateCaret(HWND window, HBITMAP bitmap, int width, int height)
{
	return CreateCaret(window, bitmap, width, height);
}

BOOL NTAPI NtUserShowCaret(HWND window)
{
	return ShowCaret(window);
}

BOOL NTAPI NtUserHideCaret(HWND window)
{
	return HideCaret(window);
}

BOOL NTAPI NtUserSystemParametersInfo(UINT action, UINT parameter, PVOID value, UINT flags)
{
	return SystemParametersInfoW(action, parameter, value, flags);
}

BOOL NTAPI NtUserGetComboBoxInfo(HWND window, PCOMBOBOXINFO info)
{
	return (BOOL)SendMessageW(window, CB_GETCOMBOBOXINFO, 0, (LPARAM)info);
}

BOOL NTAPI NtUserIsClipboardFormatAvailable(UINT format)
{
	return IsClipboardFormatAvailable(format);
}

BOOL NTAPI NtUserEmptyClipboard(VOID)
{
	return EmptyClipboard();
}

BOOL NTAPI NtUserCloseClipboard(VOID)
{
	return CloseClipboard();
}

/* The thread-state queries only feed dialog activation heuristics; this process has one input queue. */
DWORD_PTR NTAPI NtUserGetThreadState(DWORD routine)
{
	return routine == THREADSTATE_FOREGROUNDTHREAD;
}

DWORD NTAPI NtUserSetThreadState(DWORD flags, DWORD mask)
{
	return 0;
}

DWORD_PTR NTAPI NtUserCallNoParam(DWORD routine)
{
	return 0;
}

DWORD_PTR NTAPI NtUserCallOneParam(DWORD_PTR parameter, DWORD routine)
{
	return 0;
}

DWORD NTAPI NtUserCallHwndParam(HWND window, DWORD_PTR parameter, DWORD routine)
{
	return 0;
}

DWORD_PTR NTAPI NtUserQueryWindow(HWND window, DWORD index)
{
	DWORD process = 0;
	if (index == QUERY_WINDOW_FOREGROUND)
		return GetForegroundWindow() == GetAncestor(window, GA_ROOT);
	if (index == QUERY_WINDOW_UNIQUE_PROCESS_ID) {
		GetWindowThreadProcessId(window, &process);
		return process;
	}
	return 0;
}

/* The class window procedures ask the parent for a brush and fall back to the system colors. */
HBRUSH DefWndControlColor(HDC device, UINT type)
{
	if (type == CTLCOLOR_SCROLLBAR) {
		COLORREF background = GetSysColor(COLOR_3DHILIGHT);
		SetTextColor(device, GetSysColor(COLOR_3DFACE));
		SetBkColor(device, background);
		if (background == GetSysColor(COLOR_WINDOW))
			return gpsi->hbrGray;
		return GetSysColorBrush(COLOR_SCROLLBAR);
	}
	SetTextColor(device, GetSysColor(COLOR_WINDOWTEXT));
	if (type == CTLCOLOR_EDIT || type == CTLCOLOR_LISTBOX) {
		SetBkColor(device, GetSysColor(COLOR_WINDOW));
		return GetSysColorBrush(COLOR_WINDOW);
	}
	SetBkColor(device, GetSysColor(COLOR_3DFACE));
	return GetSysColorBrush(COLOR_3DFACE);
}

HBRUSH NTAPI NtUserGetControlColor(HWND parent, HWND window, HDC device, UINT message)
{
	HBRUSH brush;
	if (!parent)
		parent = GetParent(window);
	brush = parent ? (HBRUSH)SendMessageW(parent, message, (WPARAM)device, (LPARAM)window) : NULL;
	if (!brush || GetObjectType(brush) != OBJ_BRUSH)
		brush = DefWndControlColor(device, message - WM_CTLCOLORMSGBOX);
	return brush;
}

HBRUSH NTAPI NtUserGetControlBrush(HWND window, HDC device, UINT message)
{
	return NtUserGetControlColor(NULL, window, device, message);
}

/* Controls that share their parent's device context clip to their own rectangle. */
HRGN set_control_clipping(HDC device, const RECT *rectangle)
{
	RECT clip = *rectangle;
	HRGN region = CreateRectRgn(0, 0, 0, 0);
	if (GetClipRgn(device, region) != 1) {
		DeleteObject(region);
		region = 0;
	}
	DPtoLP(device, (POINT *)&clip, 2);
	if (GetLayout(device) & LAYOUT_RTL) {
		clip.left++;
		clip.right++;
	}
	IntersectClipRect(device, clip.left, clip.top, clip.right, clip.bottom);
	return region;
}

BOOL get_icon_size(HICON icon, SIZE *size)
{
	ICONINFO information;
	BITMAP bitmap;
	HBITMAP source;
	if (!GetIconInfo(icon, &information))
		return FALSE;
	source = information.hbmColor ? information.hbmColor : information.hbmMask;
	if (!GetObjectW(source, sizeof bitmap, &bitmap)) {
		if (information.hbmColor)
			DeleteObject(information.hbmColor);
		DeleteObject(information.hbmMask);
		return FALSE;
	}
	size->cx = bitmap.bmWidth;
	/* A monochrome icon stacks its AND and XOR masks in one bitmap. */
	size->cy = information.hbmColor ? bitmap.bmHeight : bitmap.bmHeight / 2;
	if (information.hbmColor)
		DeleteObject(information.hbmColor);
	DeleteObject(information.hbmMask);
	return TRUE;
}

HWND *WIN_ListChildren(HWND parent)
{
	HWND *list;
	UINT count = 0, index = 0;
	HWND child;
	for (child = GetWindow(parent, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT))
		++count;
	list = HeapAlloc(GetProcessHeap(), 0, (count + 1) * sizeof(HWND));
	if (!list)
		return NULL;
	for (child = GetWindow(parent, GW_CHILD); child && index < count; child = GetWindow(child, GW_HWNDNEXT))
		list[index++] = child;
	list[index] = NULL;
	return list;
}

BOOL FASTCALL TestWindowProcess(PWND window)
{
	return TRUE;
}

VOID FASTCALL IntNotifyWinEvent(DWORD event, HWND window, LONG object, LONG child, DWORD flags)
{
}

PTHREADINFO GetW32ThreadInfo(VOID)
{
	return NULL;
}

/* No API hooking: user hooks are never installed, so every control and dialog call runs directly. */
BOOL FASTCALL BeginIfHookedUserApiHook(VOID)
{
	return FALSE;
}

BOOL FASTCALL EndUserApiHook(VOID)
{
	return FALSE;
}

BOOL FASTCALL IsInsideUserApiHook(VOID)
{
	return FALSE;
}

const char *SPY_GetMsgName(UINT message, HWND window)
{
	return "";
}

BOOL WINAPI RavenInitControls(VOID);

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH) {
		static const WORD gray_bits[8] = {0x5555, 0xaaaa, 0x5555, 0xaaaa, 0x5555, 0xaaaa, 0x5555, 0xaaaa};
		HBITMAP pattern = CreateBitmap(8, 8, 1, 1, gray_bits);
		User32Instance = instance;
		DisableThreadLibraryCalls(instance);
		if (pattern) {
			gpsi->hbrGray = CreatePatternBrush(pattern);
			DeleteObject(pattern);
		}
		gpsi->PUSIFlags = PUSIF_KEYBOARDCUES;
		/* Registering here, ahead of every other library, lets later libraries subclass the built-in classes. */
		if (!RavenInitControls())
			return FALSE;
	}
	return TRUE;
}

/* The hook loader asks whether the thread runs inside a loader callout; this component never loads hooks. */
BOOLEAN NTAPI RtlIsThreadWithinLoaderCallout(VOID)
{
	return FALSE;
}
