/* Raven shell component: the common file dialogs, shell items and the class registry behind CoCreateInstance.
 *
 * The dialogs are Raven code: one dialog template built in memory serves GetOpenFileName, GetSaveFileName and the
 * IFileOpenDialog / IFileSaveDialog objects, listing directories through the file system API of the guest. */
#define CINTERFACE
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0601
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <commdlg.h>
#include <shobjidl.h>
#include <string.h>
#include <stddef.h>

#define ID_PATH 0x101
#define ID_LIST 0x102
#define ID_NAME 0x104
#define ID_TYPE 0x106
#define ID_UP 0x107
#define ID_PATH_LABEL 0x108
#define ID_NAME_LABEL 0x109
#define ID_TYPE_LABEL 0x10a

#define MAX_FILTERS 32
#define MAX_RESULTS 64
#define MAX_CHECKS 4
#define ID_CHECK 0x120

typedef struct {
	WCHAR name[64];
	WCHAR spec[256];
} Filter;

typedef struct {
	BOOL save;
	DWORD options; /* FOS_* values; the classic flags are translated by the callers */
	WCHAR title[128];
	WCHAR ok_label[32];
	WCHAR name_label[32];
	Filter filters[MAX_FILTERS];
	UINT filter_count;
	UINT filter_index; /* one based */
	WCHAR dir[MAX_PATH];
	WCHAR name[MAX_PATH];
	WCHAR defext[16];
	WCHAR result[MAX_PATH];
	BOOL has_result;
	struct { DWORD id; BOOL checked; WCHAR label[64]; } checks[MAX_CHECKS];
	UINT check_count;
} DialogState;

static void copy_text(WCHAR *to, size_t capacity, const WCHAR *from)
{
	size_t length = from ? lstrlenW(from) : 0;
	if (length >= capacity)
		length = capacity - 1;
	if (length)
		memcpy(to, from, length * sizeof(WCHAR));
	to[length] = 0;
}

/* RAVEN_TRACE_SHELL names a file that receives one line per interface request and dialog call. */
static void trace(const char *text, const GUID *iid)
{
	WCHAR path[MAX_PATH];
	char line[160];
	DWORD written, count = 0;
	HANDLE file;
	if (!GetEnvironmentVariableW(L"RAVEN_TRACE_SHELL", path, MAX_PATH))
		return;
	while (text[count] && count < 100)
		line[count] = text[count], ++count;
	if (iid) {
		static const char digits[] = "0123456789abcdef";
		const unsigned char *bytes = (const unsigned char *)iid;
		unsigned index;
		line[count++] = ' ';
		for (index = 0; index < 16; ++index)
			line[count++] = digits[bytes[index] >> 4], line[count++] = digits[bytes[index] & 15];
	}
	line[count++] = '\n';
	file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return;
	WriteFile(file, line, count, &written, NULL);
	CloseHandle(file);
}

static BOOL is_separator(WCHAR c)
{
	return c == L'\\' || c == L'/';
}

/* Joins a directory and a name with a single separator. */
static void join_path(WCHAR *out, size_t capacity, const WCHAR *dir, const WCHAR *name)
{
	size_t length;
	copy_text(out, capacity, dir);
	length = lstrlenW(out);
	if (length && !is_separator(out[length - 1]) && length + 1 < capacity)
		out[length++] = L'\\', out[length] = 0;
	if (length + lstrlenW(name) < capacity)
		lstrcatW(out, name);
}

static BOOL is_absolute(const WCHAR *path)
{
	return is_separator(path[0]) || (path[0] && path[1] == L':');
}

static const WCHAR *file_part(const WCHAR *path)
{
	const WCHAR *last = path;
	for (; *path; ++path)
		if (is_separator(*path) || *path == L':')
			last = path + 1;
	return last;
}

static void parent_directory(WCHAR *dir)
{
	size_t length = lstrlenW(dir);
	while (length > 3 && is_separator(dir[length - 1]))
		dir[--length] = 0;
	while (length > 3 && !is_separator(dir[length - 1]))
		dir[--length] = 0;
	while (length > 3 && is_separator(dir[length - 1]))
		dir[--length] = 0;
	if (length == 2 && dir[1] == L':')
		dir[length++] = L'\\', dir[length] = 0;
}

static WCHAR fold(WCHAR c)
{
	return c >= L'A' && c <= L'Z' ? (WCHAR)(c + 32) : c;
}

/* Case-insensitive wildcard match of one pattern ('*' and '?') against a file name. */
static BOOL match_pattern(const WCHAR *pattern, const WCHAR *name)
{
	while (*pattern) {
		if (*pattern == L'*') {
			while (*pattern == L'*')
				++pattern;
			if (!*pattern)
				return TRUE;
			for (; *name; ++name)
				if (match_pattern(pattern, name))
					return TRUE;
			return FALSE;
		}
		if (!*name || (*pattern != L'?' && fold(*pattern) != fold(*name)))
			return FALSE;
		++pattern;
		++name;
	}
	return !*name;
}

/* A filter specification is a semicolon separated list of patterns. */
static BOOL match_spec(const WCHAR *spec, const WCHAR *name)
{
	WCHAR one[128];
	while (*spec) {
		size_t length = 0;
		while (*spec == L';' || *spec == L' ')
			++spec;
		while (spec[length] && spec[length] != L';' && length < 127)
			++length;
		memcpy(one, spec, length * sizeof(WCHAR));
		one[length] = 0;
		if (length && match_pattern(one, name))
			return TRUE;
		spec += length;
	}
	return FALSE;
}

typedef struct {
	WCHAR name[MAX_PATH];
	BOOL directory;
} Entry;

static int compare_entries(const void *left, const void *right)
{
	const Entry *a = left, *b = right;
	if (a->directory != b->directory)
		return a->directory ? -1 : 1;
	return lstrcmpiW(a->name, b->name);
}

static const WCHAR *active_spec(const DialogState *state, const WCHAR *override)
{
	if (override && override[0])
		return override;
	if (state->filter_count && state->filter_index >= 1 && state->filter_index <= state->filter_count)
		return state->filters[state->filter_index - 1].spec;
	return L"*";
}

static WCHAR typed_spec[128];

static void refresh_list(HWND dialog, DialogState *state)
{
	WCHAR pattern[MAX_PATH + 4];
	WIN32_FIND_DATAW found;
	HANDLE search;
	Entry *entries = NULL;
	size_t count = 0, capacity = 0, index;
	HWND list = GetDlgItem(dialog, ID_LIST);
	const WCHAR *spec = active_spec(state, typed_spec);
	BOOL folders_only = (state->options & FOS_PICKFOLDERS) != 0;
	SendMessageW(list, LB_RESETCONTENT, 0, 0);
	SetDlgItemTextW(dialog, ID_PATH, state->dir);
	join_path(pattern, MAX_PATH + 4, state->dir, L"*");
	search = FindFirstFileW(pattern, &found);
	if (search != INVALID_HANDLE_VALUE) {
		do {
			BOOL directory = (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
			if (!lstrcmpW(found.cFileName, L".") || !lstrcmpW(found.cFileName, L".."))
				continue;
			if ((found.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) && !directory)
				continue;
			if (!directory && (folders_only || !match_spec(spec, found.cFileName)))
				continue;
			if (count == capacity) {
				Entry *grown;
				capacity = capacity ? capacity * 2 : 64;
				grown = HeapAlloc(GetProcessHeap(), 0, capacity * sizeof(Entry));
				if (!grown)
					break;
				if (entries) {
					memcpy(grown, entries, count * sizeof(Entry));
					HeapFree(GetProcessHeap(), 0, entries);
				}
				entries = grown;
			}
			copy_text(entries[count].name, MAX_PATH, found.cFileName);
			entries[count++].directory = directory;
		} while (FindNextFileW(search, &found));
		FindClose(search);
	}
	if (count > 1)
		qsort(entries, count, sizeof(Entry), compare_entries);
	for (index = 0; index < count; ++index) {
		WCHAR label[MAX_PATH + 2];
		if (entries[index].directory) {
			label[0] = L'[';
			copy_text(label + 1, MAX_PATH, entries[index].name);
			lstrcatW(label, L"]");
		} else {
			copy_text(label, MAX_PATH, entries[index].name);
		}
		SendMessageW(list, LB_ADDSTRING, 0, (LPARAM)label);
	}
	if (entries)
		HeapFree(GetProcessHeap(), 0, entries);
}

static void navigate(HWND dialog, DialogState *state, const WCHAR *dir)
{
	copy_text(state->dir, MAX_PATH, dir);
	typed_spec[0] = 0;
	refresh_list(dialog, state);
}

static void say(HWND owner, const DialogState *state, const WCHAR *text, UINT flags)
{
	MessageBoxW(owner, text, state->title[0] ? state->title : L"File", flags);
}

static BOOL accept(HWND dialog, DialogState *state)
{
	WCHAR text[MAX_PATH], full[MAX_PATH + 16];
	DWORD attributes;
	BOOL folders = (state->options & FOS_PICKFOLDERS) != 0;
	GetDlgItemTextW(dialog, ID_NAME, text, MAX_PATH);
	if (!text[0]) {
		if (!folders)
			return FALSE;
		copy_text(state->result, MAX_PATH, state->dir);
		return TRUE;
	}
	if (lstrlenW(text) >= 2 && text[0] == L'"') {
		size_t length = lstrlenW(text);
		if (text[length - 1] == L'"')
			text[length - 1] = 0;
		memmove(text, text + 1, (lstrlenW(text) + 1) * sizeof(WCHAR));
	}
	if (is_absolute(text))
		copy_text(full, MAX_PATH, text);
	else
		join_path(full, MAX_PATH, state->dir, text);
	if (wcschr(text, L'*') || wcschr(text, L'?')) {
		copy_text(typed_spec, 128, file_part(text));
		refresh_list(dialog, state);
		return FALSE;
	}
	attributes = GetFileAttributesW(full);
	if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
		if (folders) {
			copy_text(state->result, MAX_PATH, full);
			return TRUE;
		}
		SetDlgItemTextW(dialog, ID_NAME, L"");
		navigate(dialog, state, full);
		return FALSE;
	}
	if (!folders && state->save && !wcschr(file_part(full), L'.')) {
		/* The default extension, else the extension of the selected file type (a pattern like "*.txt"). */
		WCHAR extension[16];
		const WCHAR *spec = active_spec(state, NULL);
		copy_text(extension, 16, state->defext);
		if (!extension[0] && spec[0] == L'*' && spec[1] == L'.' && spec[2] && spec[2] != L'*' && spec[2] != L'?') {
			size_t length = 0;
			while (spec[2 + length] && spec[2 + length] != L';' && spec[2 + length] != L'*' && spec[2 + length] != L'?' && length < 15)
				extension[length] = spec[2 + length], ++length;
			extension[length] = 0;
		}
		if (extension[0] && lstrlenW(full) + lstrlenW(extension) + 2 < MAX_PATH) {
			size_t length = lstrlenW(full);
			full[length] = L'.';
			copy_text(full + length + 1, 16, extension);
			attributes = GetFileAttributesW(full);
		}
	}
	if (state->save) {
		if (attributes != INVALID_FILE_ATTRIBUTES && (state->options & FOS_OVERWRITEPROMPT)) {
			WCHAR message[MAX_PATH + 80];
			copy_text(message, MAX_PATH + 80, file_part(full));
			lstrcatW(message, L" already exists.\nDo you want to replace it?");
			if (MessageBoxW(dialog, message, state->title[0] ? state->title : L"Save", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
				return FALSE;
		}
	} else if (attributes == INVALID_FILE_ATTRIBUTES && (state->options & FOS_FILEMUSTEXIST)) {
		WCHAR message[MAX_PATH + 80];
		copy_text(message, MAX_PATH + 80, file_part(full));
		lstrcatW(message, L"\nFile not found.\nCheck the file name and try again.");
		say(dialog, state, message, MB_OK | MB_ICONWARNING);
		return FALSE;
	}
	copy_text(state->result, MAX_PATH, full);
	return TRUE;
}

static INT_PTR CALLBACK dialog_proc(HWND dialog, UINT message, WPARAM wparam, LPARAM lparam)
{
	DialogState *state = (DialogState *)GetWindowLongPtrW(dialog, DWLP_USER);
	switch (message) {
	case WM_INITDIALOG: {
		UINT index;
		state = (DialogState *)lparam;
		SetWindowLongPtrW(dialog, DWLP_USER, (LONG_PTR)state);
		if (state->ok_label[0])
			SetDlgItemTextW(dialog, IDOK, state->ok_label);
		if (state->name_label[0])
			SetDlgItemTextW(dialog, ID_NAME_LABEL, state->name_label);
		for (index = 0; index < state->filter_count; ++index)
			SendDlgItemMessageW(dialog, ID_TYPE, CB_ADDSTRING, 0, (LPARAM)state->filters[index].name);
		if (state->filter_count) {
			if (state->filter_index < 1 || state->filter_index > state->filter_count)
				state->filter_index = 1;
			SendDlgItemMessageW(dialog, ID_TYPE, CB_SETCURSEL, state->filter_index - 1, 0);
		} else {
			EnableWindow(GetDlgItem(dialog, ID_TYPE), FALSE);
		}
		for (index = 0; index < state->check_count; ++index)
			CheckDlgButton(dialog, ID_CHECK + index, state->checks[index].checked ? BST_CHECKED : BST_UNCHECKED);
		SetDlgItemTextW(dialog, ID_NAME, state->name);
		typed_spec[0] = 0;
		refresh_list(dialog, state);
		return TRUE; /* the dialog manager focuses the first tab stop, the file name field, with its text selected */
	}
	case WM_COMMAND:
		if (!state)
			return FALSE;
		switch (LOWORD(wparam)) {
		case IDOK:
			if (accept(dialog, state)) {
				UINT check;
				for (check = 0; check < state->check_count; ++check)
					state->checks[check].checked = IsDlgButtonChecked(dialog, ID_CHECK + check) == BST_CHECKED;
				state->has_result = TRUE;
				EndDialog(dialog, IDOK);
			}
			return TRUE;
		case IDCANCEL:
			EndDialog(dialog, IDCANCEL);
			return TRUE;
		case ID_UP: {
			WCHAR dir[MAX_PATH];
			copy_text(dir, MAX_PATH, state->dir);
			parent_directory(dir);
			navigate(dialog, state, dir);
			return TRUE;
		}
		case ID_TYPE:
			if (HIWORD(wparam) == CBN_SELCHANGE) {
				LRESULT selected = SendDlgItemMessageW(dialog, ID_TYPE, CB_GETCURSEL, 0, 0);
				if (selected >= 0)
					state->filter_index = (UINT)selected + 1;
				typed_spec[0] = 0;
				refresh_list(dialog, state);
			}
			return TRUE;
		case ID_LIST:
			if (HIWORD(wparam) == LBN_SELCHANGE || HIWORD(wparam) == LBN_DBLCLK) {
				WCHAR label[MAX_PATH + 2];
				LRESULT selected = SendDlgItemMessageW(dialog, ID_LIST, LB_GETCURSEL, 0, 0);
				if (selected < 0 || SendDlgItemMessageW(dialog, ID_LIST, LB_GETTEXT, (WPARAM)selected, (LPARAM)label) < 0)
					return TRUE;
				if (label[0] == L'[') {
					WCHAR dir[MAX_PATH];
					label[lstrlenW(label) - 1] = 0;
					if (HIWORD(wparam) == LBN_DBLCLK) {
						join_path(dir, MAX_PATH, state->dir, label + 1);
						navigate(dialog, state, dir);
					}
				} else {
					SetDlgItemTextW(dialog, ID_NAME, label);
					if (HIWORD(wparam) == LBN_DBLCLK)
						SendMessageW(dialog, WM_COMMAND, IDOK, 0);
				}
			}
			return TRUE;
		}
		return FALSE;
	}
	return FALSE;
}

/* Template assembly ----------------------------------------------------------------------------------------- */

typedef struct {
	WORD *at;
	WORD *base;
} Template;

static void put_word(Template *t, WORD value) { *t->at++ = value; }
static void put_dword(Template *t, DWORD value) { put_word(t, (WORD)value); put_word(t, (WORD)(value >> 16)); }
static void align(Template *t) { if (((ULONG_PTR)t->at - (ULONG_PTR)t->base) & 2) put_word(t, 0); }
static void put_text(Template *t, const WCHAR *text) { while (*text) put_word(t, *text++); put_word(t, 0); }

static void put_item(Template *t, DWORD style, short x, short y, short cx, short cy, WORD id, WORD klass, const WCHAR *text)
{
	align(t);
	put_dword(t, style | WS_CHILD | WS_VISIBLE);
	put_dword(t, 0);
	put_word(t, (WORD)x); put_word(t, (WORD)y); put_word(t, (WORD)cx); put_word(t, (WORD)cy);
	put_word(t, id);
	put_word(t, 0xffff); put_word(t, klass);
	put_text(t, text ? text : L"");
	put_word(t, 0);
}

static BOOL run_dialog(HWND owner, DialogState *state)
{
	WORD *buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 4096);
	Template t;
	INT_PTR answer;
	if (!buffer)
		return FALSE;
	t.at = t.base = buffer;
	put_dword(&t, DS_MODALFRAME | DS_SETFONT | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE);
	put_dword(&t, 0);
	put_word(&t, (WORD)(10 + state->check_count)); /* control count */
	put_word(&t, 0); put_word(&t, 0); put_word(&t, 300); put_word(&t, (WORD)(184 + 14 * state->check_count));
	put_word(&t, 0); put_word(&t, 0);
	put_text(&t, state->title[0] ? state->title : (state->save ? L"Save As" : L"Open"));
	put_word(&t, 8);
	put_text(&t, L"MS Shell Dlg");
	put_item(&t, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 56, 140, 170, 12, ID_NAME, 0x0081, L"");
	put_item(&t, SS_LEFT, 8, 8, 40, 10, ID_PATH_LABEL, 0x0082, (state->options & FOS_PICKFOLDERS) ? L"Folder:" : L"Look in:");
	put_item(&t, WS_BORDER | SS_NOPREFIX | SS_ENDELLIPSIS, 48, 6, 190, 12, ID_PATH, 0x0082, L"");
	put_item(&t, WS_TABSTOP | BS_PUSHBUTTON, 244, 5, 48, 14, ID_UP, 0x0080, L"Up");
	put_item(&t, WS_BORDER | WS_TABSTOP | WS_VSCROLL | LBS_NOTIFY, 8, 24, 284, 110, ID_LIST, 0x0083, L"");
	put_item(&t, SS_LEFT, 8, 142, 44, 10, ID_NAME_LABEL, 0x0082, L"File name:");
	put_item(&t, WS_TABSTOP | BS_DEFPUSHBUTTON, 234, 139, 58, 14, IDOK, 0x0080, state->save ? L"Save" : L"Open");
	put_item(&t, SS_LEFT, 8, 162, 44, 10, ID_TYPE_LABEL, 0x0082, (state->options & FOS_PICKFOLDERS) ? L"" : L"Files of type:");
	put_item(&t, WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST, 56, 160, 170, 80, ID_TYPE, 0x0085, L"");
	put_item(&t, WS_TABSTOP | BS_PUSHBUTTON, 234, 159, 58, 14, IDCANCEL, 0x0080, L"Cancel");
	{
		UINT check;
		for (check = 0; check < state->check_count; ++check)
			put_item(&t, WS_TABSTOP | BS_AUTOCHECKBOX, 8, (short)(180 + 14 * check), 220, 12, (WORD)(ID_CHECK + check), 0x0080, state->checks[check].label);
	}
	if (!state->dir[0])
		GetCurrentDirectoryW(MAX_PATH, state->dir);
	answer = DialogBoxIndirectParamW(GetModuleHandleW(NULL), (LPCDLGTEMPLATEW)buffer, owner, dialog_proc, (LPARAM)state);
	HeapFree(GetProcessHeap(), 0, buffer);
	return answer == IDOK && state->has_result;
}

/* Shell items ----------------------------------------------------------------------------------------------- */

typedef struct {
	IShellItemVtbl *vtbl;
	LONG refs;
	WCHAR path[MAX_PATH];
} Item;

typedef struct {
	IShellItemArrayVtbl *vtbl;
	LONG refs;
	UINT count;
	IShellItem *items[MAX_RESULTS];
} ItemArray;

static BOOL same_iid(REFIID a, REFIID b)
{
	const DWORD *left = (const DWORD *)a, *right = (const DWORD *)b;
	return left[0] == right[0] && left[1] == right[1] && left[2] == right[2] && left[3] == right[3];
}

static HRESULT STDMETHODCALLTYPE item_query(IShellItem *self, REFIID iid, void **out)
{
	if (same_iid(iid, &IID_IUnknown) || same_iid(iid, &IID_IShellItem)) {
		*out = self;
		InterlockedIncrement(&((Item *)self)->refs);
		return S_OK;
	}
	*out = NULL;
	return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE item_add_ref(IShellItem *self) { return (ULONG)InterlockedIncrement(&((Item *)self)->refs); }

static ULONG STDMETHODCALLTYPE item_release(IShellItem *self)
{
	LONG left = InterlockedDecrement(&((Item *)self)->refs);
	if (!left)
		HeapFree(GetProcessHeap(), 0, self);
	return (ULONG)left;
}

static HRESULT STDMETHODCALLTYPE item_bind(IShellItem *self, IBindCtx *context, REFGUID handler, REFIID iid, void **out)
{
	*out = NULL;
	return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE item_parent(IShellItem *self, IShellItem **parent);

static HRESULT STDMETHODCALLTYPE item_display_name(IShellItem *self, SIGDN kind, LPWSTR *name)
{
	const WCHAR *source = ((Item *)self)->path;
	size_t length;
	WCHAR *copy;
	if ((DWORD)kind != 0x80058000 && (DWORD)kind != 0x80028000 && (DWORD)kind != 0x8004c000 && (DWORD)kind != 0x80068000)
		source = file_part(source);
	length = lstrlenW(source);
	copy = CoTaskMemAlloc((length + 1) * sizeof(WCHAR));
	if (!copy) {
		*name = NULL;
		return E_OUTOFMEMORY;
	}
	memcpy(copy, source, (length + 1) * sizeof(WCHAR));
	*name = copy;
	return S_OK;
}

static HRESULT STDMETHODCALLTYPE item_attributes(IShellItem *self, SFGAOF mask, SFGAOF *out)
{
	DWORD attributes = GetFileAttributesW(((Item *)self)->path);
	SFGAOF value = 0;
	if (attributes != INVALID_FILE_ATTRIBUTES) {
		value |= SFGAO_FILESYSTEM;
		if (attributes & FILE_ATTRIBUTE_DIRECTORY)
			value |= SFGAO_FOLDER;
	}
	*out = value & mask;
	return (value & mask) == mask ? S_OK : S_FALSE;
}

static HRESULT STDMETHODCALLTYPE item_compare(IShellItem *self, IShellItem *other, SICHINTF hint, int *order)
{
	LPWSTR text = NULL;
	HRESULT result = IShellItem_GetDisplayName(other, SIGDN_FILESYSPATH, &text);
	if (FAILED(result))
		return result;
	*order = lstrcmpiW(((Item *)self)->path, text);
	CoTaskMemFree(text);
	return *order ? S_FALSE : S_OK;
}

static IShellItemVtbl item_vtbl = {
	item_query, item_add_ref, item_release, item_bind, item_parent, item_display_name, item_attributes, item_compare
};

static HRESULT make_item(const WCHAR *path, IShellItem **out)
{
	Item *item = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Item));
	if (!item)
		return E_OUTOFMEMORY;
	item->vtbl = &item_vtbl;
	item->refs = 1;
	copy_text(item->path, MAX_PATH, path);
	*out = (IShellItem *)item;
	return S_OK;
}

static HRESULT STDMETHODCALLTYPE item_parent(IShellItem *self, IShellItem **parent)
{
	WCHAR dir[MAX_PATH];
	copy_text(dir, MAX_PATH, ((Item *)self)->path);
	parent_directory(dir);
	return make_item(dir, parent);
}

static HRESULT STDMETHODCALLTYPE array_query(IShellItemArray *self, REFIID iid, void **out)
{
	if (same_iid(iid, &IID_IUnknown) || same_iid(iid, &IID_IShellItemArray)) {
		*out = self;
		InterlockedIncrement(&((ItemArray *)self)->refs);
		return S_OK;
	}
	*out = NULL;
	return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE array_add_ref(IShellItemArray *self) { return (ULONG)InterlockedIncrement(&((ItemArray *)self)->refs); }

static ULONG STDMETHODCALLTYPE array_release(IShellItemArray *self)
{
	ItemArray *array = (ItemArray *)self;
	LONG left = InterlockedDecrement(&array->refs);
	if (!left) {
		UINT index;
		for (index = 0; index < array->count; ++index)
			IShellItem_Release(array->items[index]);
		HeapFree(GetProcessHeap(), 0, array);
	}
	return (ULONG)left;
}

static HRESULT STDMETHODCALLTYPE array_bind(IShellItemArray *s, IBindCtx *c, REFGUID h, REFIID i, void **o) { *o = NULL; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE array_store(IShellItemArray *s, GETPROPERTYSTOREFLAGS f, REFIID i, void **o) { *o = NULL; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE array_descriptions(IShellItemArray *s, REFPROPERTYKEY k, REFIID i, void **o) { *o = NULL; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE array_attributes(IShellItemArray *s, SIATTRIBFLAGS f, SFGAOF m, SFGAOF *o) { *o = 0; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE array_count(IShellItemArray *self, DWORD *count) { *count = ((ItemArray *)self)->count; return S_OK; }

static HRESULT STDMETHODCALLTYPE array_item(IShellItemArray *self, DWORD index, IShellItem **item)
{
	ItemArray *array = (ItemArray *)self;
	if (index >= array->count) {
		*item = NULL;
		return E_INVALIDARG;
	}
	*item = array->items[index];
	IShellItem_AddRef(*item);
	return S_OK;
}

static HRESULT STDMETHODCALLTYPE array_enum(IShellItemArray *s, IEnumShellItems **o) { *o = NULL; return E_NOTIMPL; }

static IShellItemArrayVtbl array_vtbl = {
	array_query, array_add_ref, array_release, array_bind, array_store, array_descriptions, array_attributes, array_count, array_item, array_enum
};

/* IFileDialog ----------------------------------------------------------------------------------------------- */

typedef struct {
	void *vtbl;
	void *custom_vtbl; /* IFileDialogCustomize shares the object */
	LONG refs;
	BOOL save;
	DialogState state;
} FileDialog;

static FileDialog *dialog_of(void *self) { return (FileDialog *)self; }
static FileDialog *dialog_of_custom(void *self) { return (FileDialog *)((char *)self - offsetof(FileDialog, custom_vtbl)); }

static HRESULT STDMETHODCALLTYPE fd_query(void *self, REFIID iid, void **out)
{
	FileDialog *dialog = dialog_of(self);
	trace("dialog QueryInterface", iid);
	if (same_iid(iid, &IID_IUnknown) || same_iid(iid, &IID_IModalWindow) || same_iid(iid, &IID_IFileDialog) ||
		same_iid(iid, dialog->save ? &IID_IFileSaveDialog : &IID_IFileOpenDialog)) {
		*out = self;
		InterlockedIncrement(&dialog->refs);
		return S_OK;
	}
	if (same_iid(iid, &IID_IFileDialogCustomize)) {
		*out = &dialog->custom_vtbl;
		InterlockedIncrement(&dialog->refs);
		return S_OK;
	}
	*out = NULL;
	return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE fd_add_ref(void *self) { return (ULONG)InterlockedIncrement(&dialog_of(self)->refs); }

static ULONG STDMETHODCALLTYPE fd_release(void *self)
{
	LONG left = InterlockedDecrement(&dialog_of(self)->refs);
	if (!left)
		HeapFree(GetProcessHeap(), 0, self);
	return (ULONG)left;
}

static HRESULT STDMETHODCALLTYPE fd_show(void *self, HWND owner)
{
	FileDialog *dialog = dialog_of(self);
	trace("dialog Show", NULL);
	dialog->state.has_result = FALSE;
	if (!run_dialog(owner, &dialog->state))
		return HRESULT_FROM_WIN32(ERROR_CANCELLED);
	return S_OK;
}

static HRESULT STDMETHODCALLTYPE fd_set_types(void *self, UINT count, const COMDLG_FILTERSPEC *specs)
{
	DialogState *state = &dialog_of(self)->state;
	UINT index;
	if (count > MAX_FILTERS)
		count = MAX_FILTERS;
	for (index = 0; index < count; ++index) {
		copy_text(state->filters[index].name, 64, specs[index].pszName);
		copy_text(state->filters[index].spec, 256, specs[index].pszSpec);
	}
	state->filter_count = count;
	if (state->filter_index < 1 || state->filter_index > count)
		state->filter_index = count ? 1 : 0;
	return S_OK;
}

static HRESULT STDMETHODCALLTYPE fd_set_index(void *self, UINT index) { dialog_of(self)->state.filter_index = index; return S_OK; }
static HRESULT STDMETHODCALLTYPE fd_get_index(void *self, UINT *index) { *index = dialog_of(self)->state.filter_index; return S_OK; }
static HRESULT STDMETHODCALLTYPE fd_advise(void *self, IFileDialogEvents *events, DWORD *cookie) { *cookie = 1; return S_OK; }
static HRESULT STDMETHODCALLTYPE fd_unadvise(void *self, DWORD cookie) { return S_OK; }
static HRESULT STDMETHODCALLTYPE fd_set_options(void *self, FILEOPENDIALOGOPTIONS options) { dialog_of(self)->state.options = options; return S_OK; }
static HRESULT STDMETHODCALLTYPE fd_get_options(void *self, FILEOPENDIALOGOPTIONS *options) { *options = dialog_of(self)->state.options; return S_OK; }

static HRESULT item_path(IShellItem *item, WCHAR *out)
{
	LPWSTR text = NULL;
	HRESULT result = IShellItem_GetDisplayName(item, SIGDN_FILESYSPATH, &text);
	if (FAILED(result))
		return result;
	copy_text(out, MAX_PATH, text);
	CoTaskMemFree(text);
	return S_OK;
}

static HRESULT STDMETHODCALLTYPE fd_set_folder(void *self, IShellItem *item)
{
	WCHAR path[MAX_PATH];
	HRESULT result = item ? item_path(item, path) : E_INVALIDARG;
	if (SUCCEEDED(result))
		copy_text(dialog_of(self)->state.dir, MAX_PATH, path);
	return result;
}

static HRESULT STDMETHODCALLTYPE fd_get_folder(void *self, IShellItem **item)
{
	return make_item(dialog_of(self)->state.dir, item);
}

static HRESULT STDMETHODCALLTYPE fd_get_selection(void *self, IShellItem **item)
{
	DialogState *state = &dialog_of(self)->state;
	if (!state->has_result) {
		*item = NULL;
		return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
	}
	return make_item(state->result, item);
}

static HRESULT STDMETHODCALLTYPE fd_set_name(void *self, LPCWSTR name) { copy_text(dialog_of(self)->state.name, MAX_PATH, name); return S_OK; }

static HRESULT STDMETHODCALLTYPE fd_get_name(void *self, LPWSTR *name)
{
	DialogState *state = &dialog_of(self)->state;
	const WCHAR *source = state->has_result ? file_part(state->result) : state->name;
	WCHAR *copy = CoTaskMemAlloc((lstrlenW(source) + 1) * sizeof(WCHAR));
	if (!copy)
		return E_OUTOFMEMORY;
	lstrcpyW(copy, source);
	*name = copy;
	return S_OK;
}

static HRESULT STDMETHODCALLTYPE fd_set_title(void *self, LPCWSTR text) { copy_text(dialog_of(self)->state.title, 128, text); return S_OK; }
static HRESULT STDMETHODCALLTYPE fd_set_ok(void *self, LPCWSTR text) { copy_text(dialog_of(self)->state.ok_label, 32, text); return S_OK; }
static HRESULT STDMETHODCALLTYPE fd_set_name_label(void *self, LPCWSTR text) { copy_text(dialog_of(self)->state.name_label, 32, text); return S_OK; }

static HRESULT STDMETHODCALLTYPE fd_get_result(void *self, IShellItem **item)
{
	return fd_get_selection(self, item);
}

static HRESULT STDMETHODCALLTYPE fd_add_place(void *self, IShellItem *item, FDAP placement) { return S_OK; }

static HRESULT STDMETHODCALLTYPE fd_set_extension(void *self, LPCWSTR text)
{
	if (text && text[0] == L'.')
		++text;
	copy_text(dialog_of(self)->state.defext, 16, text);
	return S_OK;
}

static HRESULT STDMETHODCALLTYPE fd_close(void *self, HRESULT result) { return S_OK; }
static HRESULT STDMETHODCALLTYPE fd_set_guid(void *self, REFGUID guid) { return S_OK; }
static HRESULT STDMETHODCALLTYPE fd_clear_client(void *self) { return S_OK; }
static HRESULT STDMETHODCALLTYPE fd_set_filter(void *self, IShellItemFilter *filter) { return S_OK; }

static HRESULT STDMETHODCALLTYPE fd_get_results(void *self, IShellItemArray **array)
{
	DialogState *state = &dialog_of(self)->state;
	ItemArray *created;
	if (!state->has_result) {
		*array = NULL;
		return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
	}
	created = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ItemArray));
	if (!created)
		return E_OUTOFMEMORY;
	created->vtbl = &array_vtbl;
	created->refs = 1;
	created->count = 1;
	if (FAILED(make_item(state->result, &created->items[0]))) {
		HeapFree(GetProcessHeap(), 0, created);
		return E_OUTOFMEMORY;
	}
	*array = (IShellItemArray *)created;
	return S_OK;
}

static HRESULT STDMETHODCALLTYPE fd_not_implemented() { return E_NOTIMPL; }

#define COMMON_ENTRIES \
	(void *)fd_query, (void *)fd_add_ref, (void *)fd_release, (void *)fd_show, (void *)fd_set_types, (void *)fd_set_index, \
	(void *)fd_get_index, (void *)fd_advise, (void *)fd_unadvise, (void *)fd_set_options, (void *)fd_get_options, \
	(void *)fd_set_folder /* default folder */, (void *)fd_set_folder, (void *)fd_get_folder, (void *)fd_get_selection, \
	(void *)fd_set_name, (void *)fd_get_name, (void *)fd_set_title, (void *)fd_set_ok, (void *)fd_set_name_label, \
	(void *)fd_get_result, (void *)fd_add_place, (void *)fd_set_extension, (void *)fd_close, (void *)fd_set_guid, \
	(void *)fd_clear_client, (void *)fd_set_filter

static void *open_vtbl[] = { COMMON_ENTRIES, (void *)fd_get_results, (void *)fd_get_results };
static void *save_vtbl[] = { COMMON_ENTRIES, (void *)fd_not_implemented, (void *)fd_not_implemented, (void *)fd_not_implemented,
	(void *)fd_not_implemented, (void *)fd_not_implemented };

/* IFileDialogCustomize: the controls are recorded and answer their state queries; check boxes are shown. */
static HRESULT STDMETHODCALLTYPE cu_query(void *self, REFIID iid, void **out) { return fd_query(dialog_of_custom(self), iid, out); }
static ULONG STDMETHODCALLTYPE cu_add_ref(void *self) { return fd_add_ref(dialog_of_custom(self)); }
static ULONG STDMETHODCALLTYPE cu_release(void *self) { return fd_release(dialog_of_custom(self)); }
static HRESULT STDMETHODCALLTYPE cu_ok() { trace("customize call", NULL); return S_OK; }
static HRESULT STDMETHODCALLTYPE cu_add_check(void *self, DWORD id, LPCWSTR label, BOOL checked)
{
	DialogState *state = &dialog_of_custom(self)->state;
	trace("customize AddCheckButton", NULL);
	if (state->check_count < MAX_CHECKS) {
		state->checks[state->check_count].id = id;
		state->checks[state->check_count].checked = checked;
		copy_text(state->checks[state->check_count].label, 64, label);
		++state->check_count;
	}
	return S_OK;
}
static HRESULT STDMETHODCALLTYPE cu_get_check(void *self, DWORD id, BOOL *checked)
{
	DialogState *state = &dialog_of_custom(self)->state;
	UINT index;
	for (index = 0; index < state->check_count; ++index)
		if (state->checks[index].id == id) {
			*checked = state->checks[index].checked;
			return S_OK;
		}
	return E_INVALIDARG;
}
static HRESULT STDMETHODCALLTYPE cu_set_check(void *self, DWORD id, BOOL checked)
{
	DialogState *state = &dialog_of_custom(self)->state;
	UINT index;
	for (index = 0; index < state->check_count; ++index)
		if (state->checks[index].id == id) {
			state->checks[index].checked = checked;
			return S_OK;
		}
	return E_INVALIDARG;
}

static void *custom_vtbl[] = {
	(void *)cu_query, (void *)cu_add_ref, (void *)cu_release, (void *)cu_ok /*EnableOpenDropDown*/, (void *)cu_ok /*AddMenu*/,
	(void *)cu_ok /*AddPushButton*/, (void *)cu_ok /*AddComboBox*/, (void *)cu_ok /*AddRadioButtonList*/, (void *)cu_add_check,
	(void *)cu_ok /*AddEditBox*/, (void *)cu_ok /*AddSeparator*/, (void *)cu_ok /*AddText*/, (void *)cu_ok /*SetControlLabel*/,
	(void *)cu_ok /*GetControlState*/, (void *)cu_ok /*SetControlState*/, (void *)cu_ok /*GetEditBoxText*/, (void *)cu_ok /*SetEditBoxText*/,
	(void *)cu_get_check, (void *)cu_set_check, (void *)cu_ok /*AddControlItem*/, (void *)cu_ok /*RemoveControlItem*/,
	(void *)cu_ok /*RemoveAllControlItems*/, (void *)cu_ok /*GetControlItemState*/, (void *)cu_ok /*SetControlItemState*/,
	(void *)cu_ok /*GetSelectedControlItem*/, (void *)cu_ok /*SetSelectedControlItem*/, (void *)cu_ok /*StartVisualGroup*/,
	(void *)cu_ok /*EndVisualGroup*/, (void *)cu_ok /*MakeProminent*/, (void *)cu_ok /*SetControlItemText*/
};

static HRESULT make_dialog(BOOL save, REFIID iid, void **out)
{
	FileDialog *dialog = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FileDialog));
	HRESULT result;
	if (!dialog)
		return E_OUTOFMEMORY;
	dialog->vtbl = save ? save_vtbl : open_vtbl;
	dialog->custom_vtbl = custom_vtbl;
	dialog->refs = 1;
	dialog->save = save;
	dialog->state.save = save;
	dialog->state.options = FOS_PATHMUSTEXIST | (save ? FOS_OVERWRITEPROMPT : FOS_FILEMUSTEXIST);
	result = fd_query(dialog, iid, out);
	fd_release(dialog);
	return result;
}

/* Class registry -------------------------------------------------------------------------------------------- */

HRESULT WINAPI CoCreateInstance(REFCLSID clsid, LPUNKNOWN outer, DWORD context, REFIID iid, LPVOID *out)
{
	trace("CoCreateInstance", clsid);
	trace("  requested", iid);
	if (out)
		*out = NULL;
	if (!out)
		return E_POINTER;
	if (outer)
		return CLASS_E_NOAGGREGATION;
	if (same_iid(clsid, &CLSID_FileOpenDialog))
		return make_dialog(FALSE, iid, out);
	if (same_iid(clsid, &CLSID_FileSaveDialog))
		return make_dialog(TRUE, iid, out);
	return REGDB_E_CLASSNOTREG;
}

HRESULT WINAPI CoGetClassObject(REFCLSID clsid, DWORD context, LPVOID server, REFIID iid, LPVOID *out)
{
	if (out)
		*out = NULL;
	return REGDB_E_CLASSNOTREG;
}

HRESULT WINAPI SHCreateItemFromParsingName(PCWSTR path, IBindCtx *context, REFIID iid, void **out)
{
	IShellItem *item;
	HRESULT result;
	WCHAR full[MAX_PATH];
	if (out)
		*out = NULL;
	if (!path || !out)
		return E_INVALIDARG;
	if (is_absolute(path)) {
		copy_text(full, MAX_PATH, path);
	} else {
		GetCurrentDirectoryW(MAX_PATH, full);
		join_path(full, MAX_PATH, full, path);
	}
	if (GetFileAttributesW(full) == INVALID_FILE_ATTRIBUTES)
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	result = make_item(full, &item);
	if (SUCCEEDED(result)) {
		result = IShellItem_QueryInterface(item, iid, out);
		IShellItem_Release(item);
	}
	return result;
}

/* Classic dialogs ------------------------------------------------------------------------------------------- */

static void load_classic_filters(DialogState *state, const WCHAR *filter)
{
	state->filter_count = 0;
	while (filter && *filter && state->filter_count < MAX_FILTERS) {
		Filter *entry = &state->filters[state->filter_count];
		copy_text(entry->name, 64, filter);
		filter += lstrlenW(filter) + 1;
		if (!*filter)
			break;
		copy_text(entry->spec, 256, filter);
		filter += lstrlenW(filter) + 1;
		++state->filter_count;
	}
}

static BOOL classic_dialog(OPENFILENAMEW *request, BOOL save)
{
	DialogState *state = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DialogState));
	BOOL accepted;
	if (!state)
		return FALSE;
	state->save = save;
	state->options = 0;
	if (request->Flags & OFN_FILEMUSTEXIST)
		state->options |= FOS_FILEMUSTEXIST;
	if (request->Flags & OFN_PATHMUSTEXIST)
		state->options |= FOS_PATHMUSTEXIST;
	if (request->Flags & OFN_OVERWRITEPROMPT)
		state->options |= FOS_OVERWRITEPROMPT;
	load_classic_filters(state, request->lpstrFilter);
	state->filter_index = request->nFilterIndex ? request->nFilterIndex : 1;
	copy_text(state->title, 128, request->lpstrTitle);
	copy_text(state->dir, MAX_PATH, request->lpstrInitialDir);
	if (request->lpstrFile && request->lpstrFile[0]) {
		const WCHAR *initial = request->lpstrFile;
		if (is_absolute(initial)) {
			copy_text(state->name, MAX_PATH, file_part(initial));
			if (!state->dir[0]) {
				copy_text(state->dir, MAX_PATH, initial);
				parent_directory(state->dir);
			}
		} else {
			copy_text(state->name, MAX_PATH, initial);
		}
	}
	copy_text(state->defext, 16, request->lpstrDefExt);
	accepted = run_dialog(request->hwndOwner, state);
	if (accepted) {
		size_t length = lstrlenW(state->result);
		if (!request->lpstrFile || length + 1 > request->nMaxFile) {
			request->nMaxFile = (DWORD)(length + 1);
			accepted = FALSE;
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
		} else {
			const WCHAR *name = file_part(state->result);
			const WCHAR *dot = NULL;
			const WCHAR *scan;
			lstrcpyW(request->lpstrFile, state->result);
			request->nFileOffset = (WORD)(name - state->result);
			for (scan = name; *scan; ++scan)
				if (*scan == L'.')
					dot = scan;
			request->nFileExtension = dot ? (WORD)(dot + 1 - state->result) : 0;
			request->nFilterIndex = state->filter_index;
			if (request->lpstrFileTitle && request->nMaxFileTitle)
				copy_text(request->lpstrFileTitle, request->nMaxFileTitle, name);
		}
	}
	HeapFree(GetProcessHeap(), 0, state);
	return accepted;
}

BOOL WINAPI GetOpenFileNameW(LPOPENFILENAMEW request) { return classic_dialog(request, FALSE); }
BOOL WINAPI GetSaveFileNameW(LPOPENFILENAMEW request) { return classic_dialog(request, TRUE); }
DWORD WINAPI CommDlgExtendedError(void) { return 0; }

short WINAPI GetFileTitleW(LPCWSTR file, LPWSTR title, WORD size)
{
	const WCHAR *name;
	size_t length;
	if (!file || !*file)
		return -1;
	name = file_part(file);
	length = lstrlenW(name);
	if (!title || length + 1 > size)
		return (short)(length + 1);
	lstrcpyW(title, name);
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	return TRUE;
}
