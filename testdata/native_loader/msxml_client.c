#define COBJMACROS
#define CINTERFACE
#include <windows.h>
#include <objbase.h>
#include <msxml2.h>

/* The XML document object as installers and their bootstrappers use it: found by its program identifier through the registry, made by
   the library registered for its class, parsing a document and answering an XPath query; then loading the same document from a file in a
   folder named like a bootstrapper's, through its URL. */

int raven_entry(void)
{
	CLSID clsid;
	IXMLDOMDocument *document = NULL;
	IXMLDOMNode *node = NULL;
	VARIANT_BOOL loaded = VARIANT_FALSE;
	BSTR text = NULL, query, value = NULL;
	if (FAILED(CoInitialize(NULL)))
		return 1;
	if (CLSIDFromProgID(L"Msxml2.DOMDocument", &clsid) != S_OK)
		return 2;
	if (CoCreateInstance(&clsid, NULL, CLSCTX_INPROC_SERVER, &IID_IXMLDOMDocument, (void **)&document) != S_OK || !document)
		return 3;
	text = SysAllocString(L"<bundle><package id=\"vcRuntime\" size=\"4242\">runtime</package></bundle>");
	if (IXMLDOMDocument_loadXML(document, text, &loaded) != S_OK || loaded != VARIANT_TRUE)
		return 4;
	query = SysAllocString(L"/bundle/package/@size");
	if (IXMLDOMDocument_selectSingleNode(document, query, &node) != S_OK || !node)
		return 5;
	if (IXMLDOMNode_get_text(node, &value) != S_OK || !value || lstrcmpW(value, L"4242"))
		return 6;
	SysFreeString(value);
	IXMLDOMNode_Release(node);
	WCHAR folder[MAX_PATH], path[MAX_PATH];
	GetTempPathW(MAX_PATH, folder);
	lstrcatW(folder, L"{F2DA498E-66A3-4183-B794-FD6A62ED92B0}");
	CreateDirectoryW(folder, NULL);
	lstrcatW(folder, L"\\.ba");
	CreateDirectoryW(folder, NULL);
	lstrcpyW(path, folder);
	lstrcatW(path, L"\\BootstrapperApplicationData.xml");
	static const char data[] = "<bundle><package id=\"vcRuntime\" size=\"4343\">runtime</package></bundle>";
	DWORD written;
	HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE || !WriteFile(file, data, sizeof data - 1, &written, NULL) || !CloseHandle(file))
		return 7;
	VARIANT source;
	VariantInit(&source);
	V_VT(&source) = VT_BSTR;
	V_BSTR(&source) = SysAllocString(path);
	loaded = VARIANT_FALSE;
	if (IXMLDOMDocument_load(document, source, &loaded) != S_OK || loaded != VARIANT_TRUE)
		return 8;
	if (IXMLDOMDocument_selectSingleNode(document, query, &node) != S_OK || !node)
		return 9;
	if (IXMLDOMNode_get_text(node, &value) != S_OK || !value || lstrcmpW(value, L"4343"))
		return 10;
	DeleteFileW(path);
	SysFreeString(value);
	VariantClear(&source);
	SysFreeString(query);
	SysFreeString(text);
	IXMLDOMNode_Release(node);
	IXMLDOMDocument_Release(document);
	CoUninitialize();
	return 0;
}
