// Minimal real PE DLL fixture for the DLL export check.
// Built with: clang -target x86_64-pc-windows-gnu -shared -nostdlib
//                   -Wl,-e,_DllMainCRTStartup -o raven_min.dll raven_min.c
// Exports return known values so the loader+emulator can be verified
// end-to-end: load a real (non-synthetic) DLL, run DllMain, call exports.

__declspec(dllexport) int raven_add(int a, int b)          { return a + b; }
__declspec(dllexport) int raven_magic(void)                { return 0x2A2A; } // 10794
__declspec(dllexport) int raven_sum3(int a, int b, int c)  { return a + b + c; }

// Exercises a .data global + relocation: reads 100, writes, returns 101.
static int g_counter = 100;
__declspec(dllexport) int raven_inc(void) { return ++g_counter; }

// Exercises an intra-module call (relative CALL to a non-exported helper).
static int helper(int x) { return x * 2; }
__declspec(dllexport) int raven_double(int x) { return helper(x); }

int __stdcall _DllMainCRTStartup(void *h, unsigned long reason, void *x) {
    (void)h; (void)reason; (void)x;
    return 1; // TRUE
}
