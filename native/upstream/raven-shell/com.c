/* Raven shell component: classes registered in the registry, as COM finds them on Windows.
 *
 * A class is looked up under HKEY_CLASSES_ROOT\CLSID\{class}\InprocServer32, whose default value names the library that serves it;
 * the library is loaded and its DllGetClassObject asked for the class factory. Program identifiers lead to their class through
 * HKEY_CLASSES_ROOT\<identifier>\CLSID, following CurVer when the identifier is version independent. */
#define CINTERFACE
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>

typedef HRESULT (WINAPI *class_object_function)(REFCLSID, REFIID, void **);

/* The key of a class: "CLSID\{XXXXXXXX-...}" followed by a subkey. */
static void class_key(REFCLSID clsid, const WCHAR *subkey, WCHAR *key)
{
	WCHAR text[40];
	StringFromGUID2(clsid, text, 40);
	lstrcpyW(key, L"CLSID\\");
	lstrcatW(key, text);
	lstrcatW(key, subkey);
}

/* The default value of a key under HKEY_CLASSES_ROOT, with environment variables expanded; FALSE when there is none. */
static BOOL class_value(const WCHAR *key, WCHAR *value, DWORD capacity)
{
	WCHAR raw[MAX_PATH];
	DWORD type = 0, size = sizeof raw;
	HKEY handle;
	if (RegOpenKeyExW(HKEY_CLASSES_ROOT, key, 0, KEY_READ, &handle))
		return FALSE;
	const LONG status = RegQueryValueExW(handle, NULL, NULL, &type, (BYTE *)raw, &size);
	RegCloseKey(handle);
	if (status || (type != REG_SZ && type != REG_EXPAND_SZ) || size < sizeof(WCHAR))
		return FALSE;
	raw[size / sizeof(WCHAR) - 1] = 0;
	if (type == REG_EXPAND_SZ)
		return ExpandEnvironmentStringsW(raw, value, capacity) != 0;
	lstrcpynW(value, raw, (int)capacity);
	return TRUE;
}

HRESULT raven_registered_class_object(REFCLSID clsid, DWORD context, REFIID iid, void **out)
{
	WCHAR key[MAX_PATH], library[MAX_PATH];
	*out = NULL;
	if (!(context & (CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER)))
		return REGDB_E_CLASSNOTREG;
	class_key(clsid, L"\\InprocServer32", key);
	if (!class_value(key, library, MAX_PATH))
		return REGDB_E_CLASSNOTREG;
	/* The library stays loaded for the objects it makes, as COM keeps it until CoFreeUnusedLibraries. */
	HMODULE module = LoadLibraryExW(library, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
	if (!module)
		return CO_E_DLLNOTFOUND;
	class_object_function get = (class_object_function)GetProcAddress(module, "DllGetClassObject");
	if (!get)
		return CO_E_ERRORINDLL;
	return get(clsid, iid, out);
}

HRESULT raven_create_registered(REFCLSID clsid, LPUNKNOWN outer, DWORD context, REFIID iid, void **out)
{
	IClassFactory *factory;
	HRESULT result = raven_registered_class_object(clsid, context, &IID_IClassFactory, (void **)&factory);
	if (FAILED(result))
		return result;
	result = IClassFactory_CreateInstance(factory, outer, iid, out);
	IClassFactory_Release(factory);
	return result;
}

HRESULT WINAPI CLSIDFromProgID(LPCOLESTR identifier, LPCLSID clsid)
{
	WCHAR key[MAX_PATH], text[MAX_PATH];
	if (!identifier || !clsid)
		return E_INVALIDARG;
	if (lstrlenW(identifier) > MAX_PATH - 16) {
		ZeroMemory(clsid, sizeof *clsid);
		return CO_E_CLASSSTRING;
	}
	/* A version independent identifier names its current version, whose class is the one asked for. */
	lstrcpyW(key, identifier);
	lstrcatW(key, L"\\CurVer");
	if (class_value(key, text, MAX_PATH) && lstrlenW(text) < MAX_PATH - 16)
		lstrcpyW(key, text);
	else
		lstrcpyW(key, identifier);
	lstrcatW(key, L"\\CLSID");
	if (!class_value(key, text, MAX_PATH) || FAILED(CLSIDFromString(text, clsid))) {
		ZeroMemory(clsid, sizeof *clsid);
		return CO_E_CLASSSTRING;
	}
	return S_OK;
}
