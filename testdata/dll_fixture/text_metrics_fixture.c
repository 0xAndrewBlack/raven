#include <windows.h>

void raven_entry(void) {
    HDC dc = CreateCompatibleDC(NULL);
    HFONT font = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        FIXED_PITCH | FF_MODERN, L"Courier New");
    TEXTMETRICW metricsW;
    TEXTMETRICA metricsA;
    OUTLINETEXTMETRICW outline;
    DWORD outlineSize;

    if (!dc || !font || !SelectObject(dc, font)) {
        ExitProcess(10);
    }
    if (!GetTextMetricsW(dc, &metricsW) || !GetTextMetricsA(dc, &metricsA)) {
        ExitProcess(11);
    }
    if ((metricsW.tmPitchAndFamily & TMPF_FIXED_PITCH) != 0 ||
        (metricsA.tmPitchAndFamily & TMPF_FIXED_PITCH) != 0) {
        ExitProcess(12);
    }
    if ((metricsW.tmPitchAndFamily & (TMPF_VECTOR | TMPF_TRUETYPE)) !=
        (TMPF_VECTOR | TMPF_TRUETYPE)) {
        ExitProcess(13);
    }
    outlineSize = GetOutlineTextMetricsW(dc, 0, NULL);
    if (outlineSize != sizeof(outline)) {
        ExitProcess(14);
    }
    if (GetOutlineTextMetricsW(dc, sizeof(outline), &outline) != outlineSize) {
        ExitProcess(15);
    }
    if (outline.otmTextMetrics.tmPitchAndFamily != metricsW.tmPitchAndFamily) {
        ExitProcess(16);
    }
    SelectObject(dc, GetStockObject(SYSTEM_FONT));
    DeleteObject(font);
    DeleteDC(dc);
    ExitProcess(0);
}
