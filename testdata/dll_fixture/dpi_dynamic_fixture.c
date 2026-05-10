#ifdef _WIN64
#define WINAPI
#else
#define WINAPI __attribute__((stdcall))
#endif

#define DLLIMPORT __declspec(dllimport)
#define NULL ((void *)0)

typedef unsigned int UINT;
typedef unsigned char BYTE;
typedef unsigned short WCHAR;
typedef int BOOL;
typedef void *HANDLE;
typedef HANDLE HMODULE;
typedef HANDLE HWND;
typedef void *FARPROC;

typedef struct {
    long height;
    long width;
    long escapement;
    long orientation;
    long weight;
    BYTE italic;
    BYTE underline;
    BYTE strike_out;
    BYTE char_set;
    BYTE out_precision;
    BYTE clip_precision;
    BYTE quality;
    BYTE pitch_and_family;
    WCHAR face_name[32];
} LOGFONTW;

typedef struct {
    int attribute;
    void *data;
    unsigned long size;
} WINDOWCOMPOSITIONATTRIBDATA;

typedef int (WINAPI *get_system_metrics_for_dpi_fn)(int, UINT);
typedef BOOL (WINAPI *system_parameters_info_for_dpi_fn)(
    UINT, UINT, void *, UINT, UINT
);
typedef BOOL (WINAPI *set_window_composition_attribute_fn)(
    HWND, WINDOWCOMPOSITIONATTRIBDATA *
);

DLLIMPORT HMODULE WINAPI GetModuleHandleA(const char *);
DLLIMPORT FARPROC WINAPI GetProcAddress(HMODULE, const char *);
DLLIMPORT HWND WINAPI GetDesktopWindow(void);
DLLIMPORT void WINAPI ExitProcess(UINT);

#define SM_CXSCREEN 0
#define SM_CXICON 11
#define SPI_GETICONTITLELOGFONT 0x001F
#define SPI_GETWORKAREA 0x0030
#define WCA_USEDARKMODECOLORS 26

static const BYTE read_only_output[108] = {1};

void raven_entry(void) {
    HMODULE user32 = GetModuleHandleA("user32.dll");
    get_system_metrics_for_dpi_fn get_metrics;
    system_parameters_info_for_dpi_fn get_parameters;
    set_window_composition_attribute_fn set_composition;
    WINDOWCOMPOSITIONATTRIBDATA composition;
    LOGFONTW font;
    HWND desktop;
    BOOL enabled = 1;

    if (!user32) {
        ExitProcess(10);
    }
    get_metrics = (get_system_metrics_for_dpi_fn)GetProcAddress(
        user32, "GetSystemMetricsForDpi");
    get_parameters = (system_parameters_info_for_dpi_fn)GetProcAddress(
        user32, "SystemParametersInfoForDpi");
    set_composition = (set_window_composition_attribute_fn)GetProcAddress(
        user32, "SetWindowCompositionAttribute");
    if (!get_metrics || !get_parameters || !set_composition) {
        ExitProcess(11);
    }
    if (get_metrics(SM_CXSCREEN, 96) <= 0 ||
        get_metrics(SM_CXICON, 144) != 48) {
        ExitProcess(12);
    }
    if (!get_parameters(
            SPI_GETICONTITLELOGFONT, 0, &font, 0, 144) ||
        font.height != -18) {
        ExitProcess(13);
    }
    if (get_parameters(SPI_GETWORKAREA, 0, &font, 0, 144)) {
        ExitProcess(14);
    }
    if (get_parameters(
            SPI_GETICONTITLELOGFONT, 0,
            (void *)read_only_output, 0, 144)) {
        ExitProcess(15);
    }
    desktop = GetDesktopWindow();
    if (!desktop) {
        ExitProcess(16);
    }
    composition.attribute = WCA_USEDARKMODECOLORS;
    composition.data = &enabled;
    composition.size = sizeof(enabled);
    if (!set_composition(desktop, &composition)) {
        ExitProcess(17);
    }
    composition.size = 0;
    if (set_composition(desktop, &composition)) {
        ExitProcess(18);
    }
    composition.size = sizeof(enabled);
    if (set_composition(NULL, &composition)) {
        ExitProcess(19);
    }
    ExitProcess(0);
}
