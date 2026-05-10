#include <windows.h>

static int write_file(const wchar_t *path, const char *data, DWORD size) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    if (!WriteFile(file, data, size, &written, NULL) || written != size) {
        CloseHandle(file);
        return 0;
    }
    return CloseHandle(file);
}

static int verify_file(const wchar_t *path, const char *expected, DWORD size) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    char buffer[32] = {0};
    DWORD read = 0;
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    if (!ReadFile(file, buffer, sizeof(buffer), &read, NULL)) {
        CloseHandle(file);
        return 0;
    }
    CloseHandle(file);
    if (read != size) {
        return 0;
    }
    for (DWORD i = 0; i < size; i++) {
        if (buffer[i] != expected[i]) {
            return 0;
        }
    }
    return 1;
}

void raven_entry(void) {
	if (!write_file(L"replace-target.txt", "old", 3)) {
		ExitProcess(10);
    }
    if (!write_file(L"replace-source.tmp", "new-content", 11)) {
		ExitProcess(11);
    }
    if (!ReplaceFileW(L"replace-target.txt", L"replace-source.tmp", L"replace-backup.bak", 0, NULL, NULL)) {
		ExitProcess(12);
    }
    if (!verify_file(L"replace-target.txt", "new-content", 11)) {
		ExitProcess(13);
    }
    if (!verify_file(L"replace-backup.bak", "old", 3)) {
		ExitProcess(14);
    }
    if (GetFileAttributesW(L"replace-source.tmp") != INVALID_FILE_ATTRIBUTES) {
		ExitProcess(15);
	}
	ExitProcess(0);
}
