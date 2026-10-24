#include <windows.h>

static int *(__cdecl *error_value)(void);
static unsigned long *(__cdecl *dos_value)(void);
static int (__cdecl *get_dos)(unsigned long *);
static int (__cdecl *set_dos)(unsigned long);
static int (__cdecl *open_file)(const char *, int, ...);
static int (__cdecl *close_file)(int);
static HANDLE start, release, ready[2];
static int *main_error;
static unsigned long *main_dos;

static DWORD WINAPI thread_errors(void *argument)
{
	unsigned index = (unsigned)(ULONG_PTR)argument;
	if (WaitForSingleObject(start, 5000) != WAIT_OBJECT_0) return 10;
	int *error = error_value();
	unsigned long *dos = dos_value();
	if (*error || *dos || error == main_error || dos == main_dos) return 11;
	*error = 40 + index;
	*dos = 0x80000000UL + index;
	SetEvent(ready[index]);
	if (WaitForSingleObject(release, 5000) != WAIT_OBJECT_0) return 12;
	unsigned long value;
	if (error_value() != error || dos_value() != dos || *error != 40 + index ||
		get_dos(&value) || value != 0x80000000UL + index) return 13;
	return 0;
}

int raven_entry(void)
{
	HANDLE threads[2];
	start = CreateEventW(NULL, TRUE, FALSE, NULL);
	release = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (!start || !release) return 1;
	for (unsigned index = 0; index < 2; ++index) {
		ready[index] = CreateEventW(NULL, TRUE, FALSE, NULL);
		threads[index] = CreateThread(NULL, 0, thread_errors, (void *)(ULONG_PTR)index, 0, NULL);
		if (!ready[index] || !threads[index]) return 1;
	}
	/* Loading after thread creation also exercises the DLL's TLS allocation for existing threads. */
	HMODULE crt = LoadLibraryA("msvcrt.dll");
	if (!crt) return 2;
	error_value = (void *)GetProcAddress(crt, "_errno");
	dos_value = (void *)GetProcAddress(crt, "__doserrno");
	get_dos = (void *)GetProcAddress(crt, "_get_doserrno");
	set_dos = (void *)GetProcAddress(crt, "_set_doserrno");
	open_file = (void *)GetProcAddress(crt, "_open");
	close_file = (void *)GetProcAddress(crt, "_close");
	if (!error_value || !dos_value || !get_dos || !set_dos || !open_file || !close_file) return 3;
	main_error = error_value();
	main_dos = dos_value();
	if (*main_error || *main_dos) return 4;
	*main_error = 123;
	if (set_dos(0xffffffffUL) || *main_dos != 0xffffffffUL) return 5;
	SetEvent(start);
	for (unsigned index = 0; index < 2; ++index)
		if (WaitForSingleObject(ready[index], 5000) != WAIT_OBJECT_0) return 6;
	unsigned long value;
	if (*main_error != 123 || get_dos(&value) || value != 0xffffffffUL) return 7;
	if (get_dos(NULL) != 22 || *main_error != 22 || *main_dos != 0xffffffffUL) return 8;
	char path[MAX_PATH];
	GetTempPathA(MAX_PATH, path);
	char file[MAX_PATH];
	if (!GetTempFileNameA(path, "crt", 0, file) || !DeleteFileA(file)) return 14;
	if (open_file(file, 0x8000) != -1 || *main_error != 2 || *main_dos != ERROR_FILE_NOT_FOUND) return 15;
	int fd = open_file(file, 0x8101, 0600);
	if (fd < 0 || *main_error != 2 || *main_dos != ERROR_FILE_NOT_FOUND) return 16;
	if (close_file(fd) || !DeleteFileA(file)) return 17;
	SetEvent(release);
	for (unsigned index = 0; index < 2; ++index) {
		DWORD code;
		if (WaitForSingleObject(threads[index], 5000) != WAIT_OBJECT_0 ||
			!GetExitCodeThread(threads[index], &code) || code) return 18;
		CloseHandle(threads[index]);
	}
	HANDLE fresh = CreateThread(NULL, 0, thread_errors, NULL, 0, NULL);
	DWORD code;
	if (!fresh || WaitForSingleObject(fresh, 5000) != WAIT_OBJECT_0 ||
		!GetExitCodeThread(fresh, &code) || code || *main_error != 2 || *main_dos != ERROR_FILE_NOT_FOUND) return 19;
	CloseHandle(fresh);
	for (unsigned index = 0; index < 2; ++index)
		CloseHandle(ready[index]);
	CloseHandle(start);
	CloseHandle(release);
	return 0;
}
