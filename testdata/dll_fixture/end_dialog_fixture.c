#include <windows.h>

#define DIALOG_RESULT 0x2345

typedef union {
    DWORD alignment;
    WORD words[64];
} DIALOG_TEMPLATE_BUFFER;

static volatile LONG callback_entered;
static volatile LONG end_dialog_returned;
static volatile LONG dialog_box_returned;
static volatile LONG callback_error;

static INT_PTR CALLBACK DialogProc(
    HWND dialog,
    UINT message,
    WPARAM w_param,
    LPARAM l_param
) {
    (void)l_param;

    if (message == WM_INITDIALOG) {
        if (!PostMessageW(dialog, WM_COMMAND, IDOK, 0)) {
            callback_error = 10;
            EndDialog(dialog, DIALOG_RESULT);
        }
        return TRUE;
    }
    if (message == WM_COMMAND && LOWORD(w_param) == IDOK) {
        callback_entered = 1;
        if (!EndDialog(dialog, DIALOG_RESULT)) {
            callback_error = 11;
        }
        if (dialog_box_returned) {
            callback_error = 12;
        }
        end_dialog_returned = 1;
        return TRUE;
    }
    return FALSE;
}

static DLGTEMPLATE *CreateDialogTemplate(DIALOG_TEMPLATE_BUFFER *buffer) {
    static const WCHAR title[] = L"EndDialog contract";
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

    result = DialogBoxIndirectParamW(
        GetModuleHandleW(NULL),
        CreateDialogTemplate(&buffer),
        NULL,
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
    if (result == -1) {
        ExitProcess(42);
    }
    if (result != DIALOG_RESULT) {
        ExitProcess(43);
    }
    ExitProcess(0);
}
