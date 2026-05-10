#ifdef _WIN64
#define WINAPI
#else
#define WINAPI __attribute__((stdcall))
#endif

#define DLLIMPORT __declspec(dllimport)
#define NULL ((void *)0)

typedef unsigned short WCHAR;
typedef unsigned short ATOM;
typedef unsigned int UINT;
typedef unsigned long DWORD;
#ifdef _WIN64
typedef unsigned long long UINT_PTR;
typedef long long LONG_PTR;
#else
typedef unsigned long UINT_PTR;
typedef long LONG_PTR;
#endif
typedef LONG_PTR LRESULT;
typedef void *HANDLE;
typedef HANDLE HWND;
typedef HANDLE HINSTANCE;
typedef HANDLE HICON;
typedef HANDLE HCURSOR;
typedef HANDLE HBRUSH;
typedef HANDLE HMENU;
typedef const WCHAR *LPCWSTR;
typedef LRESULT (WINAPI *WNDPROC)(HWND, UINT, UINT_PTR, LONG_PTR);

typedef struct {
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    LPCWSTR lpszMenuName;
    LPCWSTR lpszClassName;
} WNDCLASSW;

DLLIMPORT LRESULT WINAPI DefWindowProcW(HWND, UINT, UINT_PTR, LONG_PTR);
DLLIMPORT ATOM WINAPI RegisterClassW(const WNDCLASSW *);
DLLIMPORT HWND WINAPI CreateWindowExW(
    DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int,
    HWND, HMENU, HINSTANCE, void *
);
DLLIMPORT int WINAPI MessageBoxA(HWND, const char *, const char *, UINT);
DLLIMPORT int WINAPI MessageBoxW(HWND, LPCWSTR, LPCWSTR, UINT);
DLLIMPORT void WINAPI ExitProcess(UINT);

#define WS_VISIBLE 0x10000000UL
#define WS_OVERLAPPEDWINDOW 0x00CF0000UL
#define MB_OKCANCEL 0x00000001UL
#define MB_YESNOCANCEL 0x00000003UL
#define MB_ICONQUESTION 0x00000020UL
#define MB_DEFBUTTON2 0x00000100UL
#define IDCANCEL 2
#define IDNO 7

static const WCHAR owner_class[] = {
    'R', 'a', 'v', 'e', 'n', 'M', 'e', 's', 's', 'a', 'g', 'e',
    'B', 'o', 'x', 'O', 'w', 'n', 'e', 'r', 0
};
static const WCHAR owner_title[] = {
    'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', ' ', 'o',
    'w', 'n', 'e', 'r', 0
};
static const WCHAR message_text[] = {
    'S', 'e', 'l', 'e', 'c', 't', ' ', 't', 'h', 'e', ' ', 'd',
    'e', 'f', 'a', 'u', 'l', 't', ' ', 'b', 'u', 't', 't', 'o',
    'n', ' ', 't', 'o', ' ', 'c', 'o', 'n', 't', 'i', 'n', 'u',
    'e', '.', 0
};
static const WCHAR message_title[] = {
    'R', 'a', 'v', 'e', 'n', ' ', 'M', 'e', 's', 's', 'a', 'g',
    'e', 'B', 'o', 'x', 0
};
static const WCHAR close_title[] = {
    'R', 'a', 'v', 'e', 'n', ' ', 'M', 'e', 's', 's', 'a', 'g',
    'e', 'B', 'o', 'x', ' ', 'C', 'l', 'o', 's', 'e', 0
};

void raven_entry(void) {
    WNDCLASSW window_class;
    HWND owner;
    ATOM atom;
    int result;

    window_class.style = 0;
    window_class.lpfnWndProc = DefWindowProcW;
    window_class.cbClsExtra = 0;
    window_class.cbWndExtra = 0;
    window_class.hInstance = NULL;
    window_class.hIcon = NULL;
    window_class.hCursor = NULL;
    window_class.hbrBackground = NULL;
    window_class.lpszMenuName = NULL;
    window_class.lpszClassName = owner_class;
    atom = RegisterClassW(&window_class);
    if (!atom) {
        ExitProcess(10);
    }
    owner = CreateWindowExW(
        0,
        owner_class,
        owner_title,
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        0,
        0,
        480,
        260,
        NULL,
        NULL,
        NULL,
        NULL
    );
    if (!owner) {
        ExitProcess(11);
    }
    result = MessageBoxW(
        owner,
        message_text,
        message_title,
        MB_YESNOCANCEL | MB_DEFBUTTON2 | MB_ICONQUESTION
    );
    if (result != IDNO) {
        ExitProcess(20 + result);
    }
    result = MessageBoxW(
        owner,
        message_text,
        close_title,
        MB_YESNOCANCEL | MB_ICONQUESTION
    );
    if (result != IDCANCEL) {
        ExitProcess(40 + result);
    }
    result = MessageBoxA(
        owner,
        "Select Cancel to continue.",
        "Raven MessageBox ANSI",
        MB_OKCANCEL
    );
    ExitProcess(result == IDCANCEL ? 0 : 60 + result);
}
