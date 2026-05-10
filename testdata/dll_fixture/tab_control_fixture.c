#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>

static HWND tab_hwnd;
static WNDPROC tab_default_proc;
static int notify_step;
static int cancel_selection;

static LRESULT CALLBACK ParentProc(HWND hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    if (msg == WM_NOTIFY) {
        NMHDR *header = (NMHDR *)l_param;
        if (header->hwndFrom != tab_hwnd || header->idFrom != 77) {
            return 0;
        }
        if (header->code == TCN_SELCHANGING) {
            if (notify_step != 0) {
                ExitProcess(20);
            }
            notify_step = 1;
            return cancel_selection ? TRUE : FALSE;
        }
        if (header->code == TCN_SELCHANGE) {
            if (notify_step != 1) {
                ExitProcess(21);
            }
            notify_step = 2;
        }
    }
    return DefWindowProcW(hwnd, msg, w_param, l_param);
}

static LRESULT CALLBACK TabProc(HWND hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    return CallWindowProcW(tab_default_proc, hwnd, msg, w_param, l_param);
}

void raven_entry(void) {
    WNDCLASSW window_class;
    TCITEMW item;
    RECT rect;
    HWND parent;
    HINSTANCE instance = GetModuleHandleW(0);

    window_class.style = 0;
    window_class.lpfnWndProc = ParentProc;
    window_class.cbClsExtra = 0;
    window_class.cbWndExtra = 0;
    window_class.hInstance = instance;
    window_class.hIcon = 0;
    window_class.hCursor = 0;
    window_class.hbrBackground = 0;
    window_class.lpszMenuName = 0;
    window_class.lpszClassName = L"RavenTabFixture";
    if (!RegisterClassW(&window_class)) {
        ExitProcess(1);
    }

    parent = CreateWindowExW(0, L"RavenTabFixture", L"tab fixture",
                             WS_OVERLAPPEDWINDOW, 0, 0, 320, 200,
                             0, 0, instance, 0);
    if (!parent) {
        ExitProcess(2);
    }
    tab_hwnd = CreateWindowExW(0, WC_TABCONTROLW, L"",
                               WS_CHILD | WS_VISIBLE, 0, 0, 300, 160,
                               parent, (HMENU)77, instance, 0);
    if (!tab_hwnd) {
        ExitProcess(3);
    }

    item.mask = TCIF_TEXT;
    item.pszText = L"one";
    if (TabCtrl_InsertItem(tab_hwnd, 0, &item) != 0) {
        ExitProcess(4);
    }
    item.pszText = L"two";
    if (TabCtrl_InsertItem(tab_hwnd, 1, &item) != 1) {
        ExitProcess(5);
    }

    tab_default_proc = (WNDPROC)SetWindowLongPtrW(tab_hwnd, GWLP_WNDPROC, (LONG_PTR)TabProc);
    if (!tab_default_proc) {
        ExitProcess(6);
    }

    notify_step = 0;
    TabProc(tab_hwnd, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(60, 10));
    if (notify_step != 2 || TabCtrl_GetCurSel(tab_hwnd) != 1) {
        ExitProcess(7);
    }

    notify_step = 0;
    cancel_selection = 1;
    TabProc(tab_hwnd, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(20, 10));
    if (notify_step != 1 || TabCtrl_GetCurSel(tab_hwnd) != 1) {
        ExitProcess(8);
    }

    rect.left = 0;
    rect.top = 0;
    rect.right = 300;
    rect.bottom = 160;
    CallWindowProcW(tab_default_proc, tab_hwnd, TCM_ADJUSTRECT, FALSE, (LPARAM)&rect);
    if (rect.left <= 0 || rect.top <= 0 || rect.right >= 300 || rect.bottom >= 160) {
        ExitProcess(9);
    }

    ExitProcess(0);
}
