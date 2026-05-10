#include <windows.h>
#include <commdlg.h>

void raven_entry(void) {
    PRINTDLGW dialog = {0};
    DEVNAMES *names;

    dialog.lStructSize = sizeof(dialog);
    dialog.Flags = PD_RETURNDEFAULT | PD_RETURNDC;
    if (!PrintDlgW(&dialog)) {
        ExitProcess(10);
    }
    if (!dialog.hDevMode || !dialog.hDevNames || !dialog.hDC || dialog.nCopies != 1) {
        ExitProcess(11);
    }
    names = (DEVNAMES *)GlobalLock(dialog.hDevNames);
    if (!names || !names->wDeviceOffset || !names->wOutputOffset || !names->wDefault) {
        ExitProcess(12);
    }
    GlobalUnlock(dialog.hDevNames);
    DeleteDC(dialog.hDC);
    GlobalFree(dialog.hDevMode);
    names = (DEVNAMES *)GlobalLock(dialog.hDevNames);
    if (!names || !names->wDeviceOffset) {
        ExitProcess(13);
    }
    GlobalUnlock(dialog.hDevNames);
    GlobalFree(dialog.hDevNames);
    ExitProcess(0);
}
