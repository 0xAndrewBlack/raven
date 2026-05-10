#include <windows.h>

#define DIALOG_RESULT 0x3456

typedef union {
    DWORD alignment;
    WORD words[64];
} DIALOG_TEMPLATE_BUFFER;

static volatile LONG callback_entered;
static volatile LONG end_dialog_returned;
static volatile LONG dialog_box_returned;
static volatile LONG callback_error;
static HWND owner;

static INT_PTR CALLBACK DialogProc(
    HWND dialog,
    UINT message,
    WPARAM w_param,
    LPARAM l_param
) {
    (void)l_param;

    if (message == WM_INITDIALOG) {
        if (IsWindowEnabled(owner)) {
            callback_error = 10;
            EndDialog(dialog, DIALOG_RESULT);
            return TRUE;
        }
        if ((GetWindowLongPtrA(owner, GWL_STYLE) & WS_DISABLED) == 0) {
            callback_error = 14;
            EndDialog(dialog, DIALOG_RESULT);
            return TRUE;
        }
        if (!PostMessageA(dialog, WM_COMMAND, IDOK, 0)) {
            callback_error = 11;
            EndDialog(dialog, DIALOG_RESULT);
        }
        return TRUE;
    }
    if (message == WM_COMMAND && LOWORD(w_param) == IDOK) {
        callback_entered = 1;
        if (!EndDialog(dialog, DIALOG_RESULT)) {
            callback_error = 12;
        }
        if (dialog_box_returned) {
            callback_error = 13;
        }
        end_dialog_returned = 1;
        return TRUE;
    }
    return FALSE;
}

static DLGTEMPLATE *CreateDialogTemplate(DIALOG_TEMPLATE_BUFFER *buffer) {
    static const WCHAR title[] = L"ANSI indirect contract";
    DLGTEMPLATE *dialog = (DLGTEMPLATE *)buffer->words;
    WORD *field;
    UINT index;

    dialog->style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME;
    dialog->dwExtendedStyle = 0;
    dialog->cdit = 0;
    dialog->x = 10;
    dialog->y = 10;
    dialog->cx = 120;
    dialog->cy = 40;

    field = (WORD *)(dialog + 1);
    *field++ = 0;
    *field++ = 0;
    for (index = 0; index < sizeof(title) / sizeof(title[0]); index++) {
        *field++ = title[index];
    }
    return dialog;
}

void raven_entry(void) {
    DIALOG_TEMPLATE_BUFFER buffer = {0};
    INT_PTR result;
    HWND disabled_window;

    owner = GetDesktopWindow();
    disabled_window = CreateWindowExA(
        0,
        "STATIC",
        "",
        WS_CHILD | WS_DISABLED,
        0,
        0,
        10,
        10,
        owner,
        NULL,
        GetModuleHandleA(NULL),
        NULL
    );
    if (!disabled_window) {
        ExitProcess(50);
    }
    if (IsWindowEnabled(disabled_window)) {
        ExitProcess(51);
    }
    if (!EnableWindow(disabled_window, TRUE)) {
        ExitProcess(52);
    }
    if (!IsWindowEnabled(disabled_window)) {
        ExitProcess(53);
    }
    if ((GetWindowLongPtrA(disabled_window, GWL_STYLE) & WS_DISABLED) != 0) {
        ExitProcess(54);
    }
    DestroyWindow(disabled_window);

    result = DialogBoxIndirectParamA(
        GetModuleHandleA(NULL),
        CreateDialogTemplate(&buffer),
        owner,
        DialogProc,
        0
    );
    dialog_box_returned = 1;

    if (callback_error) {
        ExitProcess(20 + callback_error);
    }
    if (!callback_entered) {
        ExitProcess(40);
    }
    if (!end_dialog_returned) {
        ExitProcess(41);
    }
    if (!IsWindowEnabled(owner)) {
        ExitProcess(42);
    }
    if ((GetWindowLongPtrA(owner, GWL_STYLE) & WS_DISABLED) != 0) {
        ExitProcess(44);
    }
    if (result != DIALOG_RESULT) {
        ExitProcess(43);
    }
    ExitProcess(0);
}
