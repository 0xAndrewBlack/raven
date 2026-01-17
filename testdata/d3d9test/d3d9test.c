/*
 * Minimal D3D9 test: clears screen to a color and draws a colored triangle
 * using DrawPrimitiveUP (no vertex buffer object needed).
 * Fixed-function pipeline only - no shaders.
 *
 * Compile:
 *   i686-w64-mingw32-gcc -o d3d9test.exe d3d9test.c -ld3d9 -lgdi32 -luser32
 */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <d3d9.h>
#include <stdio.h>

static LPDIRECT3D9       g_d3d    = NULL;
static LPDIRECT3DDEVICE9 g_dev    = NULL;
static HWND              g_hwnd   = NULL;

/* FVF: transformed + colored (XYZ+RHW+DIFFUSE) */
#define MY_FVF (D3DFVF_XYZRHW | D3DFVF_DIFFUSE)
typedef struct { float x, y, z, rhw; DWORD color; } Vertex;

static BOOL init_d3d(void) {
    D3DPRESENT_PARAMETERS pp = {0};
    pp.Windowed             = TRUE;
    pp.SwapEffect           = D3DSWAPEFFECT_DISCARD;
    pp.BackBufferFormat     = D3DFMT_UNKNOWN;
    pp.BackBufferWidth      = 640;
    pp.BackBufferHeight     = 480;
    pp.PresentationInterval = D3DPRESENT_INTERVAL_DEFAULT;

    g_d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!g_d3d) { fprintf(stderr, "Direct3DCreate9 failed\n"); return FALSE; }

    HRESULT hr = IDirect3D9_CreateDevice(g_d3d, D3DADAPTER_DEFAULT,
        D3DDEVTYPE_HAL, g_hwnd,
        D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &g_dev);
    if (FAILED(hr)) { fprintf(stderr, "CreateDevice failed: %08lx\n", hr); return FALSE; }
    return TRUE;
}

static void render_frame(int frame) {
    /* Cycle clear color through red/green/blue */
    DWORD color;
    switch (frame % 3) {
        case 0: color = D3DCOLOR_XRGB(30, 0, 0); break;
        case 1: color = D3DCOLOR_XRGB(0, 30, 0); break;
        default: color = D3DCOLOR_XRGB(0, 0, 30); break;
    }

    IDirect3DDevice9_Clear(g_dev, 0, NULL, D3DCLEAR_TARGET, color, 1.0f, 0);
    IDirect3DDevice9_BeginScene(g_dev);
    IDirect3DDevice9_SetFVF(g_dev, MY_FVF);

    /* Centered triangle */
    Vertex tri[3] = {
        { 320.0f,  80.0f, 0.5f, 1.0f, D3DCOLOR_XRGB(255,   0,   0) },
        { 520.0f, 400.0f, 0.5f, 1.0f, D3DCOLOR_XRGB(  0, 255,   0) },
        { 120.0f, 400.0f, 0.5f, 1.0f, D3DCOLOR_XRGB(  0,   0, 255) },
    };
    IDirect3DDevice9_DrawPrimitiveUP(g_dev, D3DPT_TRIANGLELIST, 1, tri, sizeof(Vertex));

    IDirect3DDevice9_EndScene(g_dev);
    IDirect3DDevice9_Present(g_dev, NULL, NULL, NULL, NULL);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    WNDCLASSEXA wc = { sizeof(wc) };
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "D3D9TestWnd";
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExA(&wc);

    g_hwnd = CreateWindowExA(0, "D3D9TestWnd", "D3D9 Triangle Test",
        WS_OVERLAPPEDWINDOW, 100, 100, 640, 480,
        NULL, NULL, hInst, NULL);
    ShowWindow(g_hwnd, SW_SHOW);

    if (!init_d3d()) return 1;

    int frame = 0;
    MSG msg = {0};
    while (frame < 300) {   /* ~5 seconds at 60fps */
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) goto done;
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        render_frame(frame++);
        Sleep(16);
    }
done:
    if (g_dev) IDirect3DDevice9_Release(g_dev);
    if (g_d3d) IDirect3D9_Release(g_d3d);
    return 0;
}
