#define COBJMACROS
#define CINTERFACE
#include <windows.h>
#include <objbase.h>
#include <msxml2.h>

/* The XML document object as installers and their bootstrappers use it: found by its program identifier through the registry, made by
   the library registered for its class, parsing a document and answering an XPath query. */

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
	SysFreeString(query);
	SysFreeString(text);
	IXMLDOMNode_Release(node);
	IXMLDOMDocument_Release(document);
	CoUninitialize();
	return 0;
}
