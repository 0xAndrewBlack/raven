package comctl32

import "sync"

// PropertySheet / PropertyPage state
// ReactOS: comctl32/propsheet.c

// PROPSHEETHEADER flags
const (
	PSH_PROPSHEETPAGE = 0x00000008
	PSH_USEHICON      = 0x00000010
	PSH_USEICONID     = 0x00000020
	PSH_PROPTITLE     = 0x00000080
	PSH_USECALLBACK   = 0x00000100
	PSH_MODELESS      = 0x00000400
	PSH_RTLREADING    = 0x00000800
	PSH_WIZARDHASFINISH = 0x00000010
	PSH_WIZARD        = 0x00002000
	PSH_USEPSTARTPAGE = 0x00004000
	PSH_NOAPPLYNOW    = 0x00000080
	PSH_AEROWIZARD    = 0x00004000
)

// PROPSHEETPAGE flags
const (
	PSP_DEFAULT      = 0x00000000
	PSP_DLGINDIRECT  = 0x00000001
	PSP_USEHICON     = 0x00000002
	PSP_USEICONID    = 0x00000004
	PSP_USETITLE     = 0x00000008
	PSP_RTLREADING   = 0x00000010
	PSP_HASHELP      = 0x00000020
	PSP_USEREFPARENT = 0x00000040
	PSP_USECALLBACK  = 0x00000080
	PSP_PREMATURE    = 0x00000400
	PSP_HIDEHEADER   = 0x00000800
	PSP_USEHEADERTITLE    = 0x00001000
	PSP_USEHEADERSUBTITLE = 0x00002000
)

// PropPage holds a single property page handle's state
type PropPage struct {
	Flags    uint32
	Title    string
	Template uint64 // guest ptr to DLGTEMPLATE
}

// PropSheet holds a property sheet dialog
type PropSheet struct {
	mu      sync.Mutex
	hwnd    uint64
	pages   []*PropPage
	curPage int
	caption string
}

var (
	psMu     sync.Mutex
	psMap    = map[uint64]*PropSheet{}
	psNextID uint64 = 0x70000
	ppMap    = map[uint64]*PropPage{}
	ppNextID uint64 = 0x71000
)

// CreatePropertySheetPage creates a property page handle (CreatePropertySheetPageW)
func CreatePropertySheetPage(flags uint32, title string, tmpl uint64) uint64 {
	pp := &PropPage{Flags: flags, Title: title, Template: tmpl}
	psMu.Lock()
	ppNextID++
	id := ppNextID
	ppMap[id] = pp
	psMu.Unlock()
	return id
}

// DestroyPropertySheetPage destroys a property page handle
func DestroyPropertySheetPage(h uint64) bool {
	psMu.Lock()
	defer psMu.Unlock()
	if _, ok := ppMap[h]; ok {
		delete(ppMap, h)
		return true
	}
	return false
}

// PropertySheet creates and runs a property sheet (returns IDOK=1 or error)
// In the emulator we just return 1 (modal OK) immediately.
func PropertySheet(_ string) int32 {
	return 1
}
