// Win32k syscall fixture: a real PE DLL whose exports issue NUMBER-INDEXED win32k
// syscalls exactly like real gdi32/user32/win32u stubs do
// (mov r10,rcx; mov eax,<index>; syscall; ret). Proves the guest-syscall ->
// win32k-engine bridge end-to-end through the emulator.
__declspec(dllexport) __attribute__((naked)) unsigned long long nt_create(
    unsigned long long style, unsigned long long x, unsigned long long y, unsigned long long wh) {
    __asm__ volatile("movq %rcx,%r10\n\t movl $0x1000,%eax\n\t syscall\n\t retq\n\t");
}
__declspec(dllexport) __attribute__((naked)) unsigned long long nt_show(
    unsigned long long hwnd, unsigned long long show) {
    __asm__ volatile("movq %rcx,%r10\n\t movl $0x1001,%eax\n\t syscall\n\t retq\n\t");
}
__declspec(dllexport) __attribute__((naked)) unsigned long long nt_destroy(unsigned long long hwnd) {
    __asm__ volatile("movq %rcx,%r10\n\t movl $0x1002,%eax\n\t syscall\n\t retq\n\t");
}
__declspec(dllexport) __attribute__((naked)) unsigned long long nt_winfrompt(
    unsigned long long x, unsigned long long y) {
    __asm__ volatile("movq %rcx,%r10\n\t movl $0x1004,%eax\n\t syscall\n\t retq\n\t");
}
int __stdcall _DllMainCRTStartup(void *h, unsigned long r, void *x) { (void)h;(void)r;(void)x; return 1; }
