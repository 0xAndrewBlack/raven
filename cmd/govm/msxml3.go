//go:build guest_windows

package main

import (
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
)

var (
	IID_IXMLDOMNode          = GUID{0x2933BF80, 0x7B36, 0x11D2, [8]byte{0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E, 0x60}}
	IID_IXMLDOMDocument      = GUID{0x2933BF81, 0x7B36, 0x11D2, [8]byte{0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E, 0x60}}
	IID_IXMLDOMDocument2     = GUID{0x2933BF95, 0x7B36, 0x11D2, [8]byte{0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E, 0x60}}
	IID_IXMLDOMDocument3     = GUID{0x2933BF96, 0x7B36, 0x11D2, [8]byte{0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E, 0x60}}
	IID_IXMLDOMNodeList      = GUID{0x2933BF82, 0x7B36, 0x11D2, [8]byte{0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E, 0x60}}
	IID_IXMLDOMNamedNodeMap  = GUID{0x2933BF83, 0x7B36, 0x11D2, [8]byte{0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E, 0x60}}
	IID_IXMLDOMCharacterData = GUID{0x2933BF84, 0x7B36, 0x11D2, [8]byte{0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E, 0x60}}
	IID_IXMLDOMAttribute     = GUID{0x2933BF85, 0x7B36, 0x11D2, [8]byte{0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E, 0x60}}
	IID_IXMLDOMElement       = GUID{0x2933BF86, 0x7B36, 0x11D2, [8]byte{0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E, 0x60}}
	IID_IXMLDOMText          = GUID{0x2933BF87, 0x7B36, 0x11D2, [8]byte{0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E, 0x60}}
	IID_IXMLDOMParseError    = GUID{0x3EFAA426, 0x272F, 0x11D2, [8]byte{0x83, 0x6F, 0x00, 0x00, 0xF8, 0x7A, 0x77, 0x82}}

	CLSID_DOMDocument             = GUID{0xF6D90F11, 0x9C73, 0x11D3, [8]byte{0xB3, 0x2E, 0x00, 0xC0, 0x4F, 0x99, 0x0B, 0xB4}}
	CLSID_DOMDocument30           = GUID{0xF5078F32, 0xC551, 0x11D3, [8]byte{0x89, 0xB9, 0x00, 0x00, 0xF8, 0x1F, 0xE2, 0x21}}
	CLSID_DOMDocument60           = GUID{0x88D96A05, 0xF192, 0x11D4, [8]byte{0xA6, 0x5F, 0x00, 0x40, 0x96, 0x32, 0x51, 0xE5}}
	CLSID_FreeThreadedDOMDocument = GUID{0xF6D90F12, 0x9C73, 0x11D3, [8]byte{0xB3, 0x2E, 0x00, 0xC0, 0x4F, 0x99, 0x0B, 0xB4}}
)

const (
	xmlNodeMethods         = 43
	xmlDocumentMethods     = 84
	xmlNodeListMethods     = 12
	xmlNamedNodeMapMethods = 16
	xmlParseErrorMethods   = 14
	xmlAttrMethods         = 46
	xmlCharDataMethods     = 51
	xmlElementMethods      = 52
	xmlTextMethods         = 52
)

type xmlNode struct {
	name       string
	nodeType   int
	value      string
	children   []*xmlNode
	attributes []*xmlNode
	parent     *xmlNode
	ownerDoc   *xmlDoc
}

type xmlDoc struct {
	root               *xmlNode
	url                string
	loaded             bool
	async              bool
	validateOnParse    bool
	resolveExternals   bool
	preserveWhiteSpace bool
	selectionLanguage  string
	selectionNS        string
	properties         map[string]string
	parseErr           xmlParseErrorData
	objectAddr         uint64
}

type xmlNodeList struct {
	nodes []*xmlNode
	index int
}

type xmlNamedNodeMap struct {
	node  *xmlNode
	attrs []*xmlNode
	index int
}

type xmlParseErrorData struct {
	errorCode int32
	url       string
	reason    string
	srcText   string
	line      int32
	linePos   int32
	filePos   int32
}

func registerMSXMLClassFactories(cs *comState) {
	for _, clsid := range []GUID{CLSID_DOMDocument, CLSID_DOMDocument30, CLSID_DOMDocument60, CLSID_FreeThreadedDOMDocument} {
		current := clsid
		cs.classFactories[current] = &classFactory{
			clsid: current,
			create: func(iid GUID) (*comObject, error) {
				return cs.createXMLDocumentObject(current, iid)
			},
		}
	}
}

func newXMLDoc() *xmlDoc {
	root := &xmlNode{name: "#document", nodeType: 9}
	doc := &xmlDoc{
		root:              root,
		selectionLanguage: "XPath",
		properties:        map[string]string{"selectionlanguage": "XPath"},
	}
	root.ownerDoc = doc
	return doc
}

func (cs *comState) createXMLDocumentObject(clsid, iid GUID) (*comObject, error) {
	switch {
	case guidEqual(iid, IID_IUnknown), guidEqual(iid, IID_IDispatch), guidEqual(iid, IID_IXMLDOMNode), guidEqual(iid, IID_IXMLDOMDocument), guidEqual(iid, IID_IXMLDOMDocument2), guidEqual(iid, IID_IXMLDOMDocument3):
	default:
		return nil, hresultError(E_NOINTERFACE)
	}
	doc := newXMLDoc()
	obj, err := cs.createGuestObject(cs.mem, IID_IXMLDOMDocument3, xmlDocumentMethods)
	if err != nil {
		return nil, err
	}
	obj.clsid = clsid
	obj.kind = "xml-document"
	obj.data = doc
	obj.supportedIIDs[IID_IDispatch] = true
	obj.supportedIIDs[IID_IXMLDOMNode] = true
	obj.supportedIIDs[IID_IXMLDOMDocument] = true
	obj.supportedIIDs[IID_IXMLDOMDocument2] = true
	obj.supportedIIDs[IID_IXMLDOMDocument3] = true
	doc.objectAddr = obj.objectAddr
	return obj, nil
}

func xmlNodeMethodCount(node *xmlNode) int {
	switch {
	case node == nil:
		return xmlNodeMethods
	case node.nodeType == 2:
		return xmlAttrMethods
	case node.nodeType == 1:
		return xmlElementMethods
	case node.nodeType == 3 || node.nodeType == 4 || node.nodeType == 8:
		return xmlTextMethods
	default:
		return xmlNodeMethods
	}
}

func (cs *comState) createXMLNodeObject(node *xmlNode) (*comObject, error) {
	if node == nil {
		return nil, hresultError(E_POINTER)
	}
	obj, err := cs.createGuestObject(cs.mem, IID_IXMLDOMNode, xmlNodeMethodCount(node))
	if err != nil {
		return nil, err
	}
	obj.kind = "xml-node"
	obj.data = node
	obj.supportedIIDs[IID_IDispatch] = true
	obj.supportedIIDs[IID_IXMLDOMNode] = true
	switch node.nodeType {
	case 1:
		obj.supportedIIDs[IID_IXMLDOMElement] = true
	case 2:
		obj.supportedIIDs[IID_IXMLDOMAttribute] = true
	case 3, 4, 8:
		obj.supportedIIDs[IID_IXMLDOMCharacterData] = true
		obj.supportedIIDs[IID_IXMLDOMText] = true
	}
	return obj, nil
}

func (cs *comState) createXMLNodeListObject(nodes []*xmlNode) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IXMLDOMNodeList, xmlNodeListMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "xml-node-list"
	obj.data = &xmlNodeList{nodes: append([]*xmlNode(nil), nodes...)}
	obj.supportedIIDs[IID_IDispatch] = true
	obj.supportedIIDs[IID_IXMLDOMNodeList] = true
	return obj, nil
}

func (cs *comState) createXMLNamedNodeMapObject(node *xmlNode) (*comObject, error) {
	attrs := []*xmlNode(nil)
	if node != nil {
		attrs = append(attrs, node.attributes...)
	}
	obj, err := cs.createGuestObject(cs.mem, IID_IXMLDOMNamedNodeMap, xmlNamedNodeMapMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "xml-named-node-map"
	obj.data = &xmlNamedNodeMap{node: node, attrs: attrs}
	obj.supportedIIDs[IID_IDispatch] = true
	obj.supportedIIDs[IID_IXMLDOMNamedNodeMap] = true
	return obj, nil
}

func (cs *comState) createXMLParseErrorObject(errData xmlParseErrorData) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IXMLDOMParseError, xmlParseErrorMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "xml-parse-error"
	obj.data = &errData
	obj.supportedIIDs[IID_IDispatch] = true
	obj.supportedIIDs[IID_IXMLDOMParseError] = true
	return obj, nil
}

func (doc *xmlDoc) documentElement() *xmlNode {
	if doc == nil || doc.root == nil {
		return nil
	}
	for _, child := range doc.root.children {
		if child != nil && child.nodeType == 1 {
			return child
		}
	}
	return nil
}

func (node *xmlNode) isElement() bool {
	return node != nil && node.nodeType == 1
}

func (node *xmlNode) firstChild() *xmlNode {
	if node == nil {
		return nil
	}
	for _, child := range node.children {
		if child != nil {
			return child
		}
	}
	return nil
}

func (node *xmlNode) lastChild() *xmlNode {
	if node == nil {
		return nil
	}
	for i := len(node.children) - 1; i >= 0; i-- {
		if node.children[i] != nil {
			return node.children[i]
		}
	}
	return nil
}

func (node *xmlNode) previousSibling() *xmlNode {
	if node == nil || node.parent == nil {
		return nil
	}
	for i, sibling := range node.parent.children {
		if sibling == node {
			for j := i - 1; j >= 0; j-- {
				if node.parent.children[j] != nil {
					return node.parent.children[j]
				}
			}
			break
		}
	}
	return nil
}

func (node *xmlNode) nextSibling() *xmlNode {
	if node == nil || node.parent == nil {
		return nil
	}
	for i, sibling := range node.parent.children {
		if sibling == node {
			for j := i + 1; j < len(node.parent.children); j++ {
				if node.parent.children[j] != nil {
					return node.parent.children[j]
				}
			}
			break
		}
	}
	return nil
}

func (node *xmlNode) baseName() string {
	if node == nil {
		return ""
	}
	if idx := strings.IndexByte(node.name, ':'); idx >= 0 {
		return node.name[idx+1:]
	}
	return node.name
}

func (node *xmlNode) prefix() string {
	if node == nil {
		return ""
	}
	if idx := strings.IndexByte(node.name, ':'); idx >= 0 {
		return node.name[:idx]
	}
	return ""
}

func (node *xmlNode) nodeName() string {
	if node == nil {
		return ""
	}
	switch node.nodeType {
	case 9:
		return "#document"
	case 3:
		return "#text"
	case 4:
		return "#cdata-section"
	case 8:
		return "#comment"
	default:
		return node.name
	}
}

func (node *xmlNode) textContent() string {
	if node == nil {
		return ""
	}
	switch node.nodeType {
	case 2, 3, 4:
		return node.value
	}
	var sb strings.Builder
	for _, child := range node.children {
		if child == nil {
			continue
		}
		sb.WriteString(child.textContent())
	}
	return sb.String()
}

func xmlEscapeTextValue(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

func xmlEscapeAttrValue(s string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return replacer.Replace(s)
}

func serializeXMLNode(node *xmlNode) string {
	if node == nil {
		return ""
	}
	switch node.nodeType {
	case 9, 11:
		var sb strings.Builder
		for _, child := range node.children {
			sb.WriteString(serializeXMLNode(child))
		}
		return sb.String()
	case 1:
		var sb strings.Builder
		sb.WriteByte('<')
		sb.WriteString(node.name)
		for _, attr := range node.attributes {
			if attr == nil {
				continue
			}
			sb.WriteByte(' ')
			sb.WriteString(attr.name)
			sb.WriteString(`="`)
			sb.WriteString(xmlEscapeAttrValue(attr.value))
			sb.WriteByte('"')
		}
		if len(node.children) == 0 {
			sb.WriteString("/>")
			return sb.String()
		}
		sb.WriteByte('>')
		for _, child := range node.children {
			sb.WriteString(serializeXMLNode(child))
		}
		sb.WriteString("</")
		sb.WriteString(node.name)
		sb.WriteByte('>')
		return sb.String()
	case 2:
		return xmlEscapeAttrValue(node.value)
	case 3:
		return xmlEscapeTextValue(node.value)
	case 4:
		return "<![CDATA[" + node.value + "]]>"
	case 7:
		if node.value == "" {
			return "<?" + node.name + "?>"
		}
		return "<?" + node.name + " " + node.value + "?>"
	case 8:
		return "<!--" + node.value + "-->"
	default:
		return xmlEscapeTextValue(node.value)
	}
}

func cloneXMLNode(node *xmlNode, owner *xmlDoc, parent *xmlNode) *xmlNode {
	if node == nil {
		return nil
	}
	clone := &xmlNode{
		name:     node.name,
		nodeType: node.nodeType,
		value:    node.value,
		parent:   parent,
		ownerDoc: owner,
	}
	for _, attr := range node.attributes {
		clonedAttr := cloneXMLNode(attr, owner, clone)
		clone.attributes = append(clone.attributes, clonedAttr)
	}
	for _, child := range node.children {
		clonedChild := cloneXMLNode(child, owner, clone)
		clone.children = append(clone.children, clonedChild)
	}
	return clone
}

func removeChildNode(parent *xmlNode, target *xmlNode) bool {
	if parent == nil || target == nil {
		return false
	}
	for i, child := range parent.children {
		if child == target {
			parent.children = append(parent.children[:i], parent.children[i+1:]...)
			target.parent = nil
			return true
		}
	}
	return false
}

func replaceChildNode(parent *xmlNode, oldNode *xmlNode, newNode *xmlNode) bool {
	if parent == nil || oldNode == nil || newNode == nil {
		return false
	}
	for i, child := range parent.children {
		if child == oldNode {
			newNode.parent = parent
			parent.children[i] = newNode
			oldNode.parent = nil
			return true
		}
	}
	return false
}

func insertBeforeNode(parent, newNode, refNode *xmlNode) bool {
	if parent == nil || newNode == nil {
		return false
	}
	if refNode == nil {
		newNode.parent = parent
		parent.children = append(parent.children, newNode)
		return true
	}
	for i, child := range parent.children {
		if child == refNode {
			newNode.parent = parent
			parent.children = append(parent.children[:i], append([]*xmlNode{newNode}, parent.children[i:]...)...)
			return true
		}
	}
	return false
}

func normalizeXMLNode(node *xmlNode) {
	if node == nil {
		return
	}
	var normalized []*xmlNode
	var pendingText *xmlNode
	flush := func() {
		if pendingText != nil {
			normalized = append(normalized, pendingText)
			pendingText = nil
		}
	}
	for _, child := range node.children {
		if child == nil {
			continue
		}
		normalizeXMLNode(child)
		if child.nodeType == 3 || child.nodeType == 4 {
			if pendingText == nil {
				pendingText = child
			} else {
				pendingText.value += child.value
			}
			continue
		}
		flush()
		normalized = append(normalized, child)
	}
	flush()
	node.children = normalized
}

func descendantsByTag(node *xmlNode, name string, out *[]*xmlNode) {
	if node == nil {
		return
	}
	for _, child := range node.children {
		if child == nil {
			continue
		}
		if child.nodeType == 1 {
			if name == "*" || strings.EqualFold(child.name, name) {
				*out = append(*out, child)
			}
			descendantsByTag(child, name, out)
		}
	}
}

func (node *xmlNode) getNamedItem(name string) *xmlNode {
	if node == nil {
		return nil
	}
	for _, attr := range node.attributes {
		if attr != nil && strings.EqualFold(attr.name, name) {
			return attr
		}
	}
	return nil
}

func splitXPath(xpath string) []string {
	xpath = strings.TrimSpace(xpath)
	if xpath == "" {
		return nil
	}
	parts := strings.Split(xpath, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func xpathMatchNodes(current []*xmlNode, part string) []*xmlNode {
	if part == "." {
		return append([]*xmlNode(nil), current...)
	}
	var next []*xmlNode
	for _, node := range current {
		if node == nil {
			continue
		}
		switch {
		case part == "..":
			if node.parent != nil {
				next = append(next, node.parent)
			}
		case strings.HasPrefix(part, "@"):
			if attr := node.getNamedItem(strings.TrimPrefix(part, "@")); attr != nil {
				next = append(next, attr)
			}
		case part == "text()":
			for _, child := range node.children {
				if child != nil && (child.nodeType == 3 || child.nodeType == 4) {
					next = append(next, child)
				}
			}
		default:
			for _, child := range node.children {
				if child != nil && child.nodeType == 1 && (part == "*" || strings.EqualFold(child.name, part)) {
					next = append(next, child)
				}
			}
		}
	}
	return next
}

func (node *xmlNode) selectNodes(xpath string) []*xmlNode {
	if node == nil {
		return nil
	}
	parts := splitXPath(xpath)
	if len(parts) == 0 {
		return nil
	}
	start := node
	if strings.HasPrefix(strings.TrimSpace(xpath), "/") && node.ownerDoc != nil {
		start = node.ownerDoc.root
	}
	current := []*xmlNode{start}
	for _, part := range parts {
		current = xpathMatchNodes(current, part)
		if len(current) == 0 {
			break
		}
	}
	return current
}

func (doc *xmlDoc) setParseError(err error) {
	if err == nil {
		doc.parseErr = xmlParseErrorData{}
		return
	}
	doc.parseErr = xmlParseErrorData{errorCode: -2147467259, reason: err.Error(), url: doc.url}
	if syn, ok := err.(*xml.SyntaxError); ok {
		doc.parseErr.line = int32(syn.Line)
		doc.parseErr.reason = syn.Msg
	}
}

func parseXMLToDOM(doc *xmlDoc, data []byte) (*xmlNode, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false
	root := &xmlNode{name: "#document", nodeType: 9, ownerDoc: doc}
	current := root
	stack := []*xmlNode{root}
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			node := &xmlNode{name: t.Name.Local, nodeType: 1, parent: current, ownerDoc: doc}
			for _, attr := range t.Attr {
				attrNode := &xmlNode{name: attr.Name.Local, nodeType: 2, value: attr.Value, parent: node, ownerDoc: doc}
				node.attributes = append(node.attributes, attrNode)
			}
			current.children = append(current.children, node)
			stack = append(stack, node)
			current = node
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
				current = stack[len(stack)-1]
			}
		case xml.CharData:
			text := string([]byte(t))
			if !doc.preserveWhiteSpace {
				trimmed := strings.TrimSpace(text)
				if trimmed == "" {
					continue
				}
				text = trimmed
			}
			textNode := &xmlNode{nodeType: 3, value: text, parent: current, ownerDoc: doc}
			current.children = append(current.children, textNode)
		case xml.Comment:
			comment := &xmlNode{nodeType: 8, value: string([]byte(t)), parent: current, ownerDoc: doc}
			current.children = append(current.children, comment)
		case xml.ProcInst:
			pi := &xmlNode{name: t.Target, nodeType: 7, value: string(t.Inst), parent: current, ownerDoc: doc}
			current.children = append(current.children, pi)
		}
	}
	return root, nil
}

func (doc *xmlDoc) loadFromData(data []byte, source string) bool {
	root, err := parseXMLToDOM(doc, data)
	doc.url = source
	if err != nil {
		doc.loaded = false
		doc.root = &xmlNode{name: "#document", nodeType: 9, ownerDoc: doc}
		doc.setParseError(err)
		return false
	}
	doc.root = root
	doc.root.ownerDoc = doc
	doc.loaded = true
	doc.setParseError(nil)
	return true
}

func resolveMSXMLHostPath(imagePath, filePath string) string {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return ""
	}
	if strings.Contains(filePath, `\`) || (len(filePath) >= 2 && filePath[1] == ':') {
		return winToLinuxPath(filePath)
	}
	if filepath.IsAbs(filePath) {
		return filepath.Clean(filePath)
	}
	base := "/"
	if imagePath != "" {
		base = filepath.Dir(winToLinuxPath(imagePath))
	}
	return filepath.Clean(filepath.Join(base, filePath))
}

// vfsReadFile reads filePath through the VFS first; falls back to os.ReadFile.
// vfsPath is the VFS-style path (e.g. "/npp/langs.xml") derived from the Windows path.
func vfsReadFile(fs *vfs.VFS, vfsPath string) ([]byte, error) {
	if fs != nil {
		fd, err := fs.Open(vfsPath, vfs.O_RDONLY)
		if err == nil {
			var buf []byte
			tmp := make([]byte, 4096)
			for {
				n, readErr := fs.Read(fd, tmp)
				if n > 0 {
					buf = append(buf, tmp[:n]...)
				}
				if readErr != nil {
					break
				}
			}
			fs.Close(fd)
			return buf, nil
		}
	}
	return os.ReadFile(vfsPath)
}

// vfsWriteFile writes data to filePath through the VFS first; falls back to os.WriteFile.
func vfsWriteFile(fs *vfs.VFS, vfsPath string, data []byte) error {
	if fs != nil {
		fd, err := fs.Open(vfsPath, vfs.O_CREAT|vfs.O_TRUNC|vfs.O_RDWR)
		if err == nil {
			fs.Write(fd, data)
			fs.Close(fd)
			return nil
		}
	}
	return os.WriteFile(vfsPath, data, 0644)
}

func (doc *xmlDoc) loadFromPath(imagePath, filePath string) bool {
	return doc.loadFromPathVFS(nil, imagePath, filePath)
}

func (doc *xmlDoc) loadFromPathVFS(fs *vfs.VFS, imagePath, filePath string) bool {
	hostPath := resolveMSXMLHostPath(imagePath, filePath)
	if hostPath == "" {
		doc.setParseError(hresultError(E_INVALIDARG))
		return false
	}
	data, err := vfsReadFile(fs, hostPath)
	if err != nil {
		doc.setParseError(err)
		doc.url = filePath
		doc.loaded = false
		return false
	}
	return doc.loadFromData(data, filePath)
}

func (doc *xmlDoc) saveToPath(imagePath, filePath string) error {
	return doc.saveToPathVFS(nil, imagePath, filePath)
}

func (doc *xmlDoc) saveToPathVFS(fs *vfs.VFS, imagePath, filePath string) error {
	hostPath := resolveMSXMLHostPath(imagePath, filePath)
	if hostPath == "" {
		return hresultError(E_INVALIDARG)
	}
	return vfsWriteFile(fs, hostPath, []byte(serializeXMLNode(doc.root)))
}

func variantStringValue(mem *mmu.MMU, addr uint64) (string, bool) {
	if addr == 0 {
		return "", false
	}
	vt := readVariantType(mem, addr)
	base := variantBaseType(vt)
	value := readVariantValue(mem, addr)
	if vt&VT_BYREF != 0 {
		switch base {
		case VT_BSTR:
			value, _ = mem.Read64(value)
		case VT_BOOL:
			v, _ := mem.Read16(value)
			if v != 0 {
				return "true", true
			}
			return "false", true
		case VT_I4, VT_INT:
			v, _ := mem.Read32(value)
			return strconv.FormatInt(int64(int32(v)), 10), true
		case VT_UI4, VT_UINT:
			v, _ := mem.Read32(value)
			return strconv.FormatUint(uint64(v), 10), true
		}
	}
	switch base {
	case VT_EMPTY, VT_NULL:
		return "", true
	case VT_BSTR:
		return readBSTRString(mem, value), true
	case VT_LPWSTR:
		return readGuestUTF16String(mem, value), true
	case VT_LPSTR:
		return readGuestANSIString(mem, value), true
	case VT_BOOL:
		if value != 0 {
			return "true", true
		}
		return "false", true
	case VT_I1:
		return strconv.FormatInt(int64(int8(value)), 10), true
	case VT_UI1:
		return strconv.FormatUint(uint64(uint8(value)), 10), true
	case VT_I2:
		return strconv.FormatInt(int64(int16(value)), 10), true
	case VT_UI2:
		return strconv.FormatUint(uint64(uint16(value)), 10), true
	case VT_I4, VT_INT:
		return strconv.FormatInt(int64(int32(value)), 10), true
	case VT_UI4, VT_UINT:
		return strconv.FormatUint(uint64(uint32(value)), 10), true
	case VT_I8:
		return strconv.FormatInt(int64(value), 10), true
	case VT_UI8:
		return strconv.FormatUint(value, 10), true
	default:
		return "", false
	}
}

func writeBSTRResult(cs *comState, mem *mmu.MMU, ptr uint64, s string) uint32 {
	if ptr == 0 {
		return E_POINTER
	}
	mem.Write64(ptr, cs.allocBSTRString(s))
	return S_OK
}

func writeNodeResult(cs *comState, mem *mmu.MMU, ptr uint64, node *xmlNode) uint32 {
	if ptr == 0 {
		return E_POINTER
	}
	mem.Write64(ptr, 0)
	if node == nil {
		return S_OK
	}
	obj, err := cs.createXMLNodeObject(node)
	if err != nil {
		return hresultFromError(err)
	}
	mem.Write64(ptr, obj.objectAddr)
	return S_OK
}

func writeNodeListResult(cs *comState, mem *mmu.MMU, ptr uint64, nodes []*xmlNode) uint32 {
	if ptr == 0 {
		return E_POINTER
	}
	mem.Write64(ptr, 0)
	obj, err := cs.createXMLNodeListObject(nodes)
	if err != nil {
		return hresultFromError(err)
	}
	mem.Write64(ptr, obj.objectAddr)
	return S_OK
}

func writeNamedNodeMapResult(cs *comState, mem *mmu.MMU, ptr uint64, node *xmlNode) uint32 {
	if ptr == 0 {
		return E_POINTER
	}
	mem.Write64(ptr, 0)
	obj, err := cs.createXMLNamedNodeMapObject(node)
	if err != nil {
		return hresultFromError(err)
	}
	mem.Write64(ptr, obj.objectAddr)
	return S_OK
}

func writeParseErrorResult(cs *comState, mem *mmu.MMU, ptr uint64, errData xmlParseErrorData) uint32 {
	if ptr == 0 {
		return E_POINTER
	}
	mem.Write64(ptr, 0)
	obj, err := cs.createXMLParseErrorObject(errData)
	if err != nil {
		return hresultFromError(err)
	}
	mem.Write64(ptr, obj.objectAddr)
	return S_OK
}

func nodeValueToVariant(cs *comState, mem *mmu.MMU, ptr uint64, node *xmlNode) uint32 {
	if ptr == 0 {
		return E_POINTER
	}
	switch {
	case node == nil:
		writeVariantEmpty(mem, ptr)
	case node.nodeType == 2 || node.nodeType == 3 || node.nodeType == 4 || node.nodeType == 7 || node.nodeType == 8:
		writeVariantScalar(mem, ptr, VT_BSTR, cs.allocBSTRString(node.value))
	default:
		writeVariantScalar(mem, ptr, VT_NULL, 0)
	}
	return S_OK
}

func writeBool16(mem *mmu.MMU, ptr uint64, v bool) uint32 {
	if ptr == 0 {
		return E_POINTER
	}
	mem.Write16(ptr, boolToVariantBool(v))
	return S_OK
}

func writeLong32(mem *mmu.MMU, ptr uint64, v int32) uint32 {
	if ptr == 0 {
		return E_POINTER
	}
	mem.Write32(ptr, uint32(v))
	return S_OK
}

func nodeTypeString(node *xmlNode) string {
	if node == nil {
		return ""
	}
	switch node.nodeType {
	case 1:
		return "element"
	case 2:
		return "attribute"
	case 3:
		return "text"
	case 4:
		return "cdatasection"
	case 7:
		return "processinginstruction"
	case 8:
		return "comment"
	case 9:
		return "document"
	case 11:
		return "documentfragment"
	default:
		return "node"
	}
}

func (cs *comState) dispatchXMLNode(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	node, _ := obj.data.(*xmlNode)
	if node == nil {
		return E_FAIL
	}
	if method >= 3 && method <= 6 {
		return cs.dispatchIDispatch(ctx, obj, method)
	}
	switch method {
	case 7:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), node.nodeName())
	case 8:
		return nodeValueToVariant(cs, ctx.Mem, ctx.Arg(1), node)
	case 9:
		s, ok := variantStringValue(ctx.Mem, ctx.Arg(1))
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		switch node.nodeType {
		case 2, 3, 4, 7, 8:
			node.value = s
			return S_OK
		default:
			return E_FAIL
		}
	case 10:
		return writeLong32(ctx.Mem, ctx.Arg(1), int32(node.nodeType))
	case 11:
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(1), node.parent)
	case 12:
		return writeNodeListResult(cs, ctx.Mem, ctx.Arg(1), node.children)
	case 13:
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(1), node.firstChild())
	case 14:
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(1), node.lastChild())
	case 15:
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(1), node.previousSibling())
	case 16:
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(1), node.nextSibling())
	case 17:
		return writeNamedNodeMapResult(cs, ctx.Mem, ctx.Arg(1), node)
	case 18:
		newNodeObj := cs.objects[ctx.Arg(1)]
		outOld := ctx.Arg(3)
		if outOld != 0 {
			ctx.Mem.Write64(outOld, 0)
		}
		if newNodeObj == nil {
			return E_POINTER
		}
		newNode, _ := newNodeObj.data.(*xmlNode)
		if newNode == nil {
			return E_FAIL
		}
		var refNode *xmlNode
		if refVariant := ctx.Arg(2); refVariant != 0 {
			vt := variantBaseType(readVariantType(ctx.Mem, refVariant))
			if vt == VT_DISPATCH || vt == VT_UNKNOWN {
				if refObj := cs.objects[readVariantValue(ctx.Mem, refVariant)]; refObj != nil {
					refNode, _ = refObj.data.(*xmlNode)
				}
			}
		}
		if !insertBeforeNode(node, newNode, refNode) {
			return E_FAIL
		}
		if outOld != 0 && refNode != nil {
			return writeNodeResult(cs, ctx.Mem, outOld, refNode)
		}
		return S_OK
	case 19:
		newObj := cs.objects[ctx.Arg(1)]
		oldObj := cs.objects[ctx.Arg(2)]
		if newObj == nil || oldObj == nil {
			return E_POINTER
		}
		newNode, _ := newObj.data.(*xmlNode)
		oldNode, _ := oldObj.data.(*xmlNode)
		if !replaceChildNode(node, oldNode, newNode) {
			return E_FAIL
		}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(3), oldNode)
	case 20:
		childObj := cs.objects[ctx.Arg(1)]
		if childObj == nil {
			return E_POINTER
		}
		child, _ := childObj.data.(*xmlNode)
		if !removeChildNode(node, child) {
			return E_FAIL
		}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), child)
	case 21:
		childObj := cs.objects[ctx.Arg(1)]
		if childObj == nil {
			return E_POINTER
		}
		child, _ := childObj.data.(*xmlNode)
		if !insertBeforeNode(node, child, nil) {
			return E_FAIL
		}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), child)
	case 22:
		return writeBool16(ctx.Mem, ctx.Arg(1), len(node.children) > 0)
	case 23:
		if node.ownerDoc == nil {
			return writeNodeResult(cs, ctx.Mem, ctx.Arg(1), nil)
		}
		if ptr := ctx.Arg(1); ptr != 0 {
			ctx.Mem.Write64(ptr, node.ownerDoc.objectAddr)
			cs.addRefPtr(node.ownerDoc.objectAddr)
			return S_OK
		}
		return E_POINTER
	case 24:
		deep := ctx.Arg(1) != 0
		clone := &xmlNode{name: node.name, nodeType: node.nodeType, value: node.value, ownerDoc: node.ownerDoc}
		for _, attr := range node.attributes {
			clone.attributes = append(clone.attributes, cloneXMLNode(attr, node.ownerDoc, clone))
		}
		if deep {
			for _, child := range node.children {
				clone.children = append(clone.children, cloneXMLNode(child, node.ownerDoc, clone))
			}
		}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), clone)
	case 25:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), nodeTypeString(node))
	case 26:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), node.textContent())
	case 27:
		text := readBSTRString(ctx.Mem, ctx.Arg(1))
		switch node.nodeType {
		case 2, 3, 4, 7, 8:
			node.value = text
		default:
			node.children = nil
			if text != "" {
				node.children = append(node.children, &xmlNode{nodeType: 3, value: text, parent: node, ownerDoc: node.ownerDoc})
			}
		}
		return S_OK
	case 28:
		return writeBool16(ctx.Mem, ctx.Arg(1), node.nodeType == 2)
	case 29:
		if ptr := ctx.Arg(1); ptr != 0 {
			ctx.Mem.Write64(ptr, 0)
			return S_OK
		}
		return E_POINTER
	case 30:
		if node.nodeType == 1 || node.nodeType == 9 || node.nodeType == 11 {
			writeVariantScalar(ctx.Mem, ctx.Arg(1), VT_BSTR, cs.allocBSTRString(node.textContent()))
			return S_OK
		}
		return nodeValueToVariant(cs, ctx.Mem, ctx.Arg(1), node)
	case 31:
		s, ok := variantStringValue(ctx.Mem, ctx.Arg(1))
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		node.value = s
		return S_OK
	case 32:
		writeVariantEmpty(ctx.Mem, ctx.Arg(1))
		return S_OK
	case 33:
		return S_OK
	case 34:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), serializeXMLNode(node))
	case 35:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(2), "")
	case 36:
		xpath := readBSTRString(ctx.Mem, ctx.Arg(1))
		return writeNodeListResult(cs, ctx.Mem, ctx.Arg(2), node.selectNodes(xpath))
	case 37:
		xpath := readBSTRString(ctx.Mem, ctx.Arg(1))
		matches := node.selectNodes(xpath)
		if len(matches) == 0 {
			return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), nil)
		}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), matches[0])
	case 38:
		return writeBool16(ctx.Mem, ctx.Arg(1), node.ownerDoc == nil || node.ownerDoc.loaded)
	case 39:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), "")
	case 40:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), node.prefix())
	case 41:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), node.baseName())
	case 42:
		return E_NOTIMPL
	}
	switch {
	case node.nodeType == 2:
		return cs.dispatchXMLAttribute(ctx, obj, method, node)
	case node.nodeType == 1:
		return cs.dispatchXMLElement(ctx, obj, method, node)
	case node.nodeType == 3 || node.nodeType == 4 || node.nodeType == 8:
		return cs.dispatchXMLCharacterData(ctx, obj, method, node)
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchXMLAttribute(ctx *ntapi.TrapContext, obj *comObject, method int, node *xmlNode) uint32 {
	switch method {
	case 43:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), node.name)
	case 44:
		writeVariantScalar(ctx.Mem, ctx.Arg(1), VT_BSTR, cs.allocBSTRString(node.value))
		return S_OK
	case 45:
		s, ok := variantStringValue(ctx.Mem, ctx.Arg(1))
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		node.value = s
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchXMLCharacterData(ctx *ntapi.TrapContext, obj *comObject, method int, node *xmlNode) uint32 {
	switch method {
	case 43:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), node.value)
	case 44:
		node.value = readBSTRString(ctx.Mem, ctx.Arg(1))
		return S_OK
	case 45:
		return writeLong32(ctx.Mem, ctx.Arg(1), int32(len([]rune(node.value))))
	case 46:
		offset := int(ctx.Arg(1))
		count := int(ctx.Arg(2))
		r := []rune(node.value)
		if offset < 0 {
			offset = 0
		}
		if offset > len(r) {
			offset = len(r)
		}
		end := offset + count
		if end > len(r) || count < 0 {
			end = len(r)
		}
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(3), string(r[offset:end]))
	case 47:
		node.value += readBSTRString(ctx.Mem, ctx.Arg(1))
		return S_OK
	case 48:
		offset := int(ctx.Arg(1))
		insert := []rune(readBSTRString(ctx.Mem, ctx.Arg(2)))
		r := []rune(node.value)
		if offset < 0 {
			offset = 0
		}
		if offset > len(r) {
			offset = len(r)
		}
		r = append(r[:offset], append(insert, r[offset:]...)...)
		node.value = string(r)
		return S_OK
	case 49:
		offset := int(ctx.Arg(1))
		count := int(ctx.Arg(2))
		r := []rune(node.value)
		if offset < 0 {
			offset = 0
		}
		if offset > len(r) {
			offset = len(r)
		}
		end := offset + count
		if end > len(r) || count < 0 {
			end = len(r)
		}
		r = append(r[:offset], r[end:]...)
		node.value = string(r)
		return S_OK
	case 50:
		offset := int(ctx.Arg(1))
		count := int(ctx.Arg(2))
		repl := []rune(readBSTRString(ctx.Mem, ctx.Arg(3)))
		r := []rune(node.value)
		if offset < 0 {
			offset = 0
		}
		if offset > len(r) {
			offset = len(r)
		}
		end := offset + count
		if end > len(r) || count < 0 {
			end = len(r)
		}
		r = append(r[:offset], append(repl, r[end:]...)...)
		node.value = string(r)
		return S_OK
	case 51:
		r := []rune(node.value)
		offset := int(ctx.Arg(1))
		if offset < 0 || offset > len(r) {
			return E_INVALIDARG
		}
		newNode := &xmlNode{name: node.name, nodeType: node.nodeType, value: string(r[offset:]), ownerDoc: node.ownerDoc}
		node.value = string(r[:offset])
		if node.parent != nil {
			insertBeforeNode(node.parent, newNode, node.nextSibling())
		}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), newNode)
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchXMLElement(ctx *ntapi.TrapContext, obj *comObject, method int, node *xmlNode) uint32 {
	switch method {
	case 43:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), node.name)
	case 44:
		name := readBSTRString(ctx.Mem, ctx.Arg(1))
		if attr := node.getNamedItem(name); attr != nil {
			writeVariantScalar(ctx.Mem, ctx.Arg(2), VT_BSTR, cs.allocBSTRString(attr.value))
		} else {
			writeVariantEmpty(ctx.Mem, ctx.Arg(2))
		}
		return S_OK
	case 45:
		name := readBSTRString(ctx.Mem, ctx.Arg(1))
		value, ok := variantStringValue(ctx.Mem, ctx.Arg(2))
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		if attr := node.getNamedItem(name); attr != nil {
			attr.value = value
		} else {
			node.attributes = append(node.attributes, &xmlNode{name: name, nodeType: 2, value: value, parent: node, ownerDoc: node.ownerDoc})
		}
		return S_OK
	case 46:
		name := readBSTRString(ctx.Mem, ctx.Arg(1))
		for i, attr := range node.attributes {
			if attr != nil && strings.EqualFold(attr.name, name) {
				node.attributes = append(node.attributes[:i], node.attributes[i+1:]...)
				break
			}
		}
		return S_OK
	case 47:
		name := readBSTRString(ctx.Mem, ctx.Arg(1))
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), node.getNamedItem(name))
	case 48:
		attrObj := cs.objects[ctx.Arg(1)]
		if attrObj == nil {
			return E_POINTER
		}
		attrNode, _ := attrObj.data.(*xmlNode)
		if attrNode == nil || attrNode.nodeType != 2 {
			return E_INVALIDARG
		}
		var replaced *xmlNode
		for i, attr := range node.attributes {
			if attr != nil && strings.EqualFold(attr.name, attrNode.name) {
				replaced = attr
				node.attributes[i] = attrNode
				attrNode.parent = node
				return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), replaced)
			}
		}
		attrNode.parent = node
		node.attributes = append(node.attributes, attrNode)
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), nil)
	case 49:
		attrObj := cs.objects[ctx.Arg(1)]
		if attrObj == nil {
			return E_POINTER
		}
		attrNode, _ := attrObj.data.(*xmlNode)
		if attrNode == nil {
			return E_INVALIDARG
		}
		for i, attr := range node.attributes {
			if attr == attrNode {
				node.attributes = append(node.attributes[:i], node.attributes[i+1:]...)
				attrNode.parent = nil
				return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), attrNode)
			}
		}
		return E_FAIL
	case 50:
		name := readBSTRString(ctx.Mem, ctx.Arg(1))
		var out []*xmlNode
		descendantsByTag(node, name, &out)
		return writeNodeListResult(cs, ctx.Mem, ctx.Arg(2), out)
	case 51:
		normalizeXMLNode(node)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchXMLDocument(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	doc, _ := obj.data.(*xmlDoc)
	if doc == nil {
		return E_FAIL
	}
	if method <= 42 {
		return cs.dispatchXMLNode(ctx, &comObject{data: doc.root, kind: "xml-node"}, method)
	}
	if method >= 3 && method <= 6 {
		return cs.dispatchIDispatch(ctx, obj, method)
	}
	switch method {
	case 43, 44:
		if ptr := ctx.Arg(1); ptr != 0 {
			ctx.Mem.Write64(ptr, 0)
			return S_OK
		}
		return E_POINTER
	case 45:
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(1), doc.documentElement())
	case 46:
		elemObj := cs.objects[ctx.Arg(1)]
		if elemObj == nil {
			return E_POINTER
		}
		elem, _ := elemObj.data.(*xmlNode)
		if elem == nil || elem.nodeType != 1 {
			return E_INVALIDARG
		}
		elem.parent = doc.root
		doc.root.children = []*xmlNode{elem}
		doc.loaded = true
		return S_OK
	case 47:
		node := &xmlNode{name: readBSTRString(ctx.Mem, ctx.Arg(1)), nodeType: 1, ownerDoc: doc}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), node)
	case 48:
		node := &xmlNode{name: "#document-fragment", nodeType: 11, ownerDoc: doc}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(1), node)
	case 49:
		node := &xmlNode{name: "#text", nodeType: 3, value: readBSTRString(ctx.Mem, ctx.Arg(1)), ownerDoc: doc}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), node)
	case 50:
		node := &xmlNode{name: "#comment", nodeType: 8, value: readBSTRString(ctx.Mem, ctx.Arg(1)), ownerDoc: doc}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), node)
	case 51:
		node := &xmlNode{name: "#cdata-section", nodeType: 4, value: readBSTRString(ctx.Mem, ctx.Arg(1)), ownerDoc: doc}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), node)
	case 52:
		node := &xmlNode{name: readBSTRString(ctx.Mem, ctx.Arg(1)), nodeType: 7, value: readBSTRString(ctx.Mem, ctx.Arg(2)), ownerDoc: doc}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(3), node)
	case 53:
		node := &xmlNode{name: readBSTRString(ctx.Mem, ctx.Arg(1)), nodeType: 2, ownerDoc: doc}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), node)
	case 54:
		node := &xmlNode{name: readBSTRString(ctx.Mem, ctx.Arg(1)), nodeType: 5, ownerDoc: doc}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), node)
	case 55:
		var out []*xmlNode
		descendantsByTag(doc.root, readBSTRString(ctx.Mem, ctx.Arg(1)), &out)
		return writeNodeListResult(cs, ctx.Mem, ctx.Arg(2), out)
	case 56:
		vt := variantBaseType(readVariantType(ctx.Mem, ctx.Arg(1)))
		kindNum := int32(1)
		switch vt {
		case VT_I2, VT_I4, VT_INT:
			kindNum = int32(readVariantValue(ctx.Mem, ctx.Arg(1)))
		}
		name := readBSTRString(ctx.Mem, ctx.Arg(2))
		uri := readBSTRString(ctx.Mem, ctx.Arg(3))
		if uri != "" && !strings.Contains(name, ":") {
			name = uri + ":" + name
		}
		node := &xmlNode{name: name, nodeType: int(kindNum), ownerDoc: doc}
		if node.nodeType == 0 {
			node.nodeType = 1
		}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(4), node)
	case 57:
		id := readBSTRString(ctx.Mem, ctx.Arg(1))
		var found *xmlNode
		var walk func(*xmlNode)
		walk = func(cur *xmlNode) {
			if cur == nil || found != nil {
				return
			}
			if attr := cur.getNamedItem("id"); attr != nil && attr.value == id {
				found = cur
				return
			}
			for _, child := range cur.children {
				walk(child)
			}
		}
		walk(doc.root)
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), found)
	case 58:
		path, ok := variantStringValue(ctx.Mem, ctx.Arg(1))
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		return writeBool16(ctx.Mem, ctx.Arg(2), doc.loadFromPathVFS(ctx.FS, cs.hctx.ImagePath, path))
	case 59:
		state := int32(0)
		if doc.loaded {
			state = 4
		}
		return writeLong32(ctx.Mem, ctx.Arg(1), state)
	case 60:
		return writeParseErrorResult(cs, ctx.Mem, ctx.Arg(1), doc.parseErr)
	case 61:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), doc.url)
	case 62:
		return writeBool16(ctx.Mem, ctx.Arg(1), doc.async)
	case 63:
		doc.async = ctx.Arg(1) != 0
		return S_OK
	case 64:
		doc.loaded = false
		return S_OK
	case 65:
		xmlText := readBSTRString(ctx.Mem, ctx.Arg(1))
		return writeBool16(ctx.Mem, ctx.Arg(2), doc.loadFromData([]byte(xmlText), doc.url))
	case 66:
		path, ok := variantStringValue(ctx.Mem, ctx.Arg(1))
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		if err := doc.saveToPathVFS(ctx.FS, cs.hctx.ImagePath, path); err != nil {
			return hresultFromError(err)
		}
		return S_OK
	case 67:
		return writeBool16(ctx.Mem, ctx.Arg(1), doc.validateOnParse)
	case 68:
		doc.validateOnParse = ctx.Arg(1) != 0
		return S_OK
	case 69:
		return writeBool16(ctx.Mem, ctx.Arg(1), doc.resolveExternals)
	case 70:
		doc.resolveExternals = ctx.Arg(1) != 0
		return S_OK
	case 71:
		return writeBool16(ctx.Mem, ctx.Arg(1), doc.preserveWhiteSpace)
	case 72:
		doc.preserveWhiteSpace = ctx.Arg(1) != 0
		return S_OK
	case 73, 74, 75:
		return S_OK
	case 76:
		if ptr := ctx.Arg(1); ptr != 0 {
			ctx.Mem.Write64(ptr, 0)
			return S_OK
		}
		return E_POINTER
	case 77:
		writeVariantEmpty(ctx.Mem, ctx.Arg(1))
		return S_OK
	case 78:
		return S_OK
	case 79:
		return writeParseErrorResult(cs, ctx.Mem, ctx.Arg(1), doc.parseErr)
	case 80:
		key := strings.ToLower(readBSTRString(ctx.Mem, ctx.Arg(1)))
		value, ok := variantStringValue(ctx.Mem, ctx.Arg(2))
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		doc.properties[key] = value
		switch key {
		case "selectionlanguage":
			doc.selectionLanguage = value
		case "selectionnamespaces":
			doc.selectionNS = value
		}
		return S_OK
	case 81:
		key := strings.ToLower(readBSTRString(ctx.Mem, ctx.Arg(1)))
		if value, ok := doc.properties[key]; ok {
			writeVariantScalar(ctx.Mem, ctx.Arg(2), VT_BSTR, cs.allocBSTRString(value))
		} else {
			writeVariantEmpty(ctx.Mem, ctx.Arg(2))
		}
		return S_OK
	case 82:
		return writeParseErrorResult(cs, ctx.Mem, ctx.Arg(2), doc.parseErr)
	case 83:
		nodeObj := cs.objects[ctx.Arg(1)]
		if nodeObj == nil {
			return E_POINTER
		}
		node, _ := nodeObj.data.(*xmlNode)
		if node == nil {
			return E_INVALIDARG
		}
		clone := cloneXMLNode(node, doc, nil)
		if ctx.Arg(2) == 0 {
			clone.children = nil
		}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(3), clone)
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchXMLNodeList(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	list, _ := obj.data.(*xmlNodeList)
	if list == nil {
		return E_FAIL
	}
	if method >= 3 && method <= 6 {
		return cs.dispatchIDispatch(ctx, obj, method)
	}
	switch method {
	case 7:
		index := int(int32(ctx.Arg(1)))
		if index < 0 || index >= len(list.nodes) {
			return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), nil)
		}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), list.nodes[index])
	case 8:
		return writeLong32(ctx.Mem, ctx.Arg(1), int32(len(list.nodes)))
	case 9:
		if list.index >= len(list.nodes) {
			return writeNodeResult(cs, ctx.Mem, ctx.Arg(1), nil)
		}
		node := list.nodes[list.index]
		list.index++
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(1), node)
	case 10:
		list.index = 0
		return S_OK
	case 11:
		if ptr := ctx.Arg(1); ptr != 0 {
			ctx.Mem.Write64(ptr, 0)
			return E_NOTIMPL
		}
		return E_POINTER
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchXMLNamedNodeMap(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	m, _ := obj.data.(*xmlNamedNodeMap)
	if m == nil {
		return E_FAIL
	}
	if method >= 3 && method <= 6 {
		return cs.dispatchIDispatch(ctx, obj, method)
	}
	switch method {
	case 7:
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), (&xmlNode{attributes: m.attrs}).getNamedItem(readBSTRString(ctx.Mem, ctx.Arg(1))))
	case 8:
		objNode := cs.objects[ctx.Arg(1)]
		if objNode == nil {
			return E_POINTER
		}
		attr, _ := objNode.data.(*xmlNode)
		if attr == nil || attr.nodeType != 2 {
			return E_INVALIDARG
		}
		var replaced *xmlNode
		for i, existing := range m.attrs {
			if existing != nil && strings.EqualFold(existing.name, attr.name) {
				replaced = existing
				m.attrs[i] = attr
				if m.node != nil {
					m.node.attributes[i] = attr
					attr.parent = m.node
				}
				return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), replaced)
			}
		}
		m.attrs = append(m.attrs, attr)
		if m.node != nil {
			attr.parent = m.node
			m.node.attributes = append(m.node.attributes, attr)
		}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), nil)
	case 9:
		name := readBSTRString(ctx.Mem, ctx.Arg(1))
		for i, attr := range m.attrs {
			if attr != nil && strings.EqualFold(attr.name, name) {
				m.attrs = append(m.attrs[:i], m.attrs[i+1:]...)
				if m.node != nil {
					m.node.attributes = append(m.node.attributes[:i], m.node.attributes[i+1:]...)
				}
				attr.parent = nil
				return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), attr)
			}
		}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), nil)
	case 10:
		index := int(int32(ctx.Arg(1)))
		if index < 0 || index >= len(m.attrs) {
			return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), nil)
		}
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(2), m.attrs[index])
	case 11:
		return writeLong32(ctx.Mem, ctx.Arg(1), int32(len(m.attrs)))
	case 12:
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(3), (&xmlNode{attributes: m.attrs}).getNamedItem(readBSTRString(ctx.Mem, ctx.Arg(1))))
	case 13:
		return cs.dispatchXMLNamedNodeMap(ctx, obj, 9)
	case 14:
		if m.index >= len(m.attrs) {
			return writeNodeResult(cs, ctx.Mem, ctx.Arg(1), nil)
		}
		attr := m.attrs[m.index]
		m.index++
		return writeNodeResult(cs, ctx.Mem, ctx.Arg(1), attr)
	case 15:
		m.index = 0
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchXMLParseError(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	data, _ := obj.data.(*xmlParseErrorData)
	if data == nil {
		return E_FAIL
	}
	if method >= 3 && method <= 6 {
		return cs.dispatchIDispatch(ctx, obj, method)
	}
	switch method {
	case 7:
		return writeLong32(ctx.Mem, ctx.Arg(1), data.errorCode)
	case 8:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), data.url)
	case 9:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), data.reason)
	case 10:
		return writeBSTRResult(cs, ctx.Mem, ctx.Arg(1), data.srcText)
	case 11:
		return writeLong32(ctx.Mem, ctx.Arg(1), data.line)
	case 12:
		return writeLong32(ctx.Mem, ctx.Arg(1), data.linePos)
	case 13:
		return writeLong32(ctx.Mem, ctx.Arg(1), data.filePos)
	default:
		return E_NOTIMPL
	}
}
