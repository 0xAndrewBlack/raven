#include <windows.h>

static void fail(UINT code) {
    ExitProcess(code);
}

static LRESULT CALLBACK fixture_wnd_proc(HWND hwnd, UINT message, WPARAM w_param, LPARAM l_param) {
    return DefWindowProcW(hwnd, message, w_param, l_param);
}

void raven_entry(void) {
    WNDCLASSW window_class = {0};
    HWND root;
    HWND parent;
    HWND visible;
    HWND nested;
    HWND hidden;
    HWND disabled;
    HWND transparent;
    HWND behind_group;
    HWND group_box;
    HWND isolated_group;
    HWND overlap;
    POINT point;

    window_class.lpfnWndProc = fixture_wnd_proc;
    window_class.hInstance = GetModuleHandleW(NULL);
    window_class.lpszClassName = L"RavenPointFixture";
    if (!RegisterClassW(&window_class)) {
        fail(10);
    }

    root = CreateWindowExW(
        0, window_class.lpszClassName, L"point fixture",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        0, 0, 320, 240, NULL, NULL, window_class.hInstance, NULL);
    parent = CreateWindowExW(
        0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
        20, 30, 240, 150, root, (HMENU)100, window_class.hInstance, NULL);
    visible = CreateWindowExW(
        0, L"BUTTON", L"visible", WS_CHILD | WS_VISIBLE,
        10, 10, 80, 40, parent, (HMENU)101, window_class.hInstance, NULL);
    nested = CreateWindowExW(
        0, L"STATIC", L"nested", WS_CHILD | WS_VISIBLE,
        5, 5, 20, 20, visible, (HMENU)102, window_class.hInstance, NULL);
    hidden = CreateWindowExW(
        0, L"BUTTON", L"hidden", WS_CHILD,
        100, 10, 80, 40, parent, (HMENU)103, window_class.hInstance, NULL);
    disabled = CreateWindowExW(
        0, L"BUTTON", L"disabled", WS_CHILD | WS_VISIBLE | WS_DISABLED,
        10, 60, 80, 40, parent, (HMENU)104, window_class.hInstance, NULL);
    transparent = CreateWindowExW(
        WS_EX_TRANSPARENT, L"STATIC", L"transparent", WS_CHILD | WS_VISIBLE,
        100, 60, 80, 40, parent, (HMENU)105, window_class.hInstance, NULL);
    behind_group = CreateWindowExW(
        0, L"BUTTON", L"behind", WS_CHILD | WS_VISIBLE,
        10, 105, 80, 35, parent, (HMENU)106, window_class.hInstance, NULL);
    group_box = CreateWindowExW(
        0, L"BUTTON", L"group", WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        10, 105, 80, 35, parent, (HMENU)107, window_class.hInstance, NULL);
    isolated_group = CreateWindowExW(
        0, L"BUTTON", L"isolated", WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        120, 105, 80, 35, parent, (HMENU)108, window_class.hInstance, NULL);
    if (!root || !parent || !visible || !nested || !hidden || !disabled || !transparent ||
        !behind_group || !group_box || !isolated_group) {
        fail(11);
    }

    point.x = 15;
    point.y = 15;
    if (ChildWindowFromPoint(parent, point) != visible) {
        fail(20);
    }
    if (ChildWindowFromPointEx(parent, point, CWP_SKIPINVISIBLE) != visible) {
        fail(21);
    }

    point.x = 110;
    point.y = 20;
    if (ChildWindowFromPoint(parent, point) != hidden) {
        fail(22);
    }
    if (ChildWindowFromPointEx(parent, point, CWP_SKIPINVISIBLE) != parent) {
        fail(23);
    }
    if (RealChildWindowFromPoint(parent, point) != parent) {
        fail(33);
    }

    point.x = 20;
    point.y = 70;
    if (ChildWindowFromPointEx(parent, point, CWP_SKIPDISABLED) != parent) {
        fail(24);
    }

    point.x = 110;
    point.y = 70;
    if (ChildWindowFromPointEx(parent, point, CWP_SKIPTRANSPARENT) != parent) {
        fail(25);
    }
    if (RealChildWindowFromPoint(parent, point) != transparent) {
        fail(26);
    }

    point.x = 20;
    point.y = 115;
    if (ChildWindowFromPoint(parent, point) != group_box) {
        fail(27);
    }
    if (RealChildWindowFromPoint(parent, point) != behind_group) {
        fail(28);
    }

    point.x = 130;
    point.y = 115;
    if (RealChildWindowFromPoint(parent, point) != isolated_group) {
        fail(34);
    }

    point.x = 220;
    point.y = 140;
    if (ChildWindowFromPoint(parent, point) != parent) {
        fail(29);
    }

    point.x = -1;
    point.y = 10;
    if (ChildWindowFromPoint(parent, point) != NULL) {
        fail(30);
    }

    point.x = 7;
    point.y = 7;
    if (!ClientToScreen(visible, &point)) {
        fail(31);
    }
    if (WindowFromPoint(point) != visible) {
        fail(32);
    }

    overlap = CreateWindowExW(
        0, window_class.lpszClassName, L"overlap",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        0, 0, 320, 240, NULL, NULL, window_class.hInstance, NULL);
    if (!overlap) {
        fail(35);
    }
    if (WindowFromPoint(point) != overlap) {
        fail(36);
    }
    if (!SetWindowPos(root, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)) {
        fail(37);
    }
    if (WindowFromPoint(point) != visible) {
        fail(38);
    }
    EnableWindow(root, FALSE);
    if (WindowFromPoint(point) != overlap) {
        fail(40);
    }

    ExitProcess(0);
}
