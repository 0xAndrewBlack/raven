package win32

// System metrics - ReactOS win32ss/user/user32/misc/misc.c → NtUserGetSystemMetrics
// Values match Windows defaults for a standard 96-DPI display (1:1 scale).
// ReactOS SDK: sdk/include/psdk/winuser.h SM_* constants.
const (
	SM_CXSCREEN         = 0
	SM_CYSCREEN         = 1
	SM_CXVSCROLL        = 2
	SM_CYHSCROLL        = 3
	SM_CYCAPTION        = 4
	SM_CXBORDER         = 5
	SM_CYBORDER         = 6
	SM_CXDLGFRAME       = 7
	SM_CYDLGFRAME       = 8
	SM_CYVTHUMB         = 9
	SM_CXHTHUMB         = 10
	SM_CXICON           = 11
	SM_CYICON           = 12
	SM_CXCURSOR         = 13
	SM_CYCURSOR         = 14
	SM_CYMENU           = 15
	SM_CXFULLSCREEN     = 16
	SM_CYFULLSCREEN     = 17
	SM_CYKANJIWINDOW    = 18
	SM_MOUSEPRESENT     = 19
	SM_CYVSCROLL        = 20
	SM_CXHSCROLL        = 21
	SM_DEBUG            = 22
	SM_SWAPBUTTON       = 23
	SM_RESERVED1        = 24
	SM_RESERVED2        = 25
	SM_RESERVED3        = 26
	SM_RESERVED4        = 27
	SM_CXMIN            = 28
	SM_CYMIN            = 29
	SM_CXSIZE           = 30
	SM_CYSIZE           = 31
	SM_CXFRAME          = 32
	SM_CYFRAME          = 33
	SM_CXMINTRACK       = 34
	SM_CYMINTRACK       = 35
	SM_CXDOUBLECLK      = 36
	SM_CYDOUBLECLK      = 37
	SM_CXICONSPACING    = 38
	SM_CYICONSPACING    = 39
	SM_MENUDROPALIGNMENT = 40
	SM_PENWINDOWS       = 41
	SM_DBCSENABLED      = 42
	SM_CMOUSEBUTTONS    = 43
	SM_CXFIXEDFRAME     = SM_CXDLGFRAME
	SM_CYFIXEDFRAME     = SM_CYDLGFRAME
	SM_CXSIZEFRAME      = SM_CXFRAME
	SM_CYSIZEFRAME      = SM_CYFRAME
	SM_SECURE           = 44
	SM_CXEDGE           = 45
	SM_CYEDGE           = 46
	SM_CXMINSPACING     = 47
	SM_CYMINSPACING     = 48
	SM_CXSMICON         = 49
	SM_CYSMICON         = 50
	SM_CYSMCAPTION      = 51
	SM_CXSMSIZE         = 52
	SM_CYSMSIZE         = 53
	SM_CXMENUSIZE       = 54
	SM_CYMENUSIZE       = 55
	SM_ARRANGE          = 56
	SM_CXMINIMIZED      = 57
	SM_CYMINIMIZED      = 58
	SM_CXMAXTRACK       = 59
	SM_CYMAXTRACK       = 60
	SM_CXMAXIMIZED      = 61
	SM_CYMAXIMIZED      = 62
	SM_NETWORK          = 63
	SM_CLEANBOOT        = 67
	SM_CXDRAG           = 68
	SM_CYDRAG           = 69
	SM_SHOWSOUNDS       = 70
	SM_CXMENUCHECK      = 71
	SM_CYMENUCHECK      = 72
	SM_SLOWMACHINE      = 73
	SM_MIDEASTENABLED   = 74
	SM_MOUSEWHEELPRESENT = 75
	SM_XVIRTUALSCREEN   = 76
	SM_YVIRTUALSCREEN   = 77
	SM_CXVIRTUALSCREEN  = 78
	SM_CYVIRTUALSCREEN  = 79
	SM_CMONITORS        = 80
	SM_SAMEDISPLAYFORMAT = 81
	SM_IMMENABLED       = 82
	SM_CXFOCUSBORDER    = 83
	SM_CYFOCUSBORDER    = 84
	SM_TABLETPC         = 86
	SM_MEDIACENTER      = 87
	SM_STARTER          = 88
	SM_SERVERR2         = 89
	SM_MOUSEHORIZONTALWHEELPRESENT = 91
	SM_CXPADDEDBORDER   = 92
	SM_DIGITIZER        = 94
	SM_MAXIMUMTOUCHES   = 95
	SM_REMOTESESSION    = 0x1000
	SM_SHUTTINGDOWN     = 0x2000
	SM_REMOTECONTROL    = 0x2001
)

// ScreenWidth and ScreenHeight are updated by the emulator when the Wayland
// window is created/resized.
var ScreenWidth int32 = 1920
var ScreenHeight int32 = 1080

// GetSystemMetrics returns the value for the requested SM_ index.
// Mirrors NtUserGetSystemMetrics in ReactOS win32k.
func GetSystemMetrics(nIndex int) int32 {
	switch nIndex {
	case SM_CXSCREEN:
		return ScreenWidth
	case SM_CYSCREEN:
		return ScreenHeight
	case SM_CXFULLSCREEN:
		return ScreenWidth
	case SM_CYFULLSCREEN:
		return ScreenHeight - GetSystemMetrics(SM_CYCAPTION) - GetSystemMetrics(SM_CYMENU)
	case SM_XVIRTUALSCREEN:
		return 0
	case SM_YVIRTUALSCREEN:
		return 0
	case SM_CXVIRTUALSCREEN:
		return ScreenWidth
	case SM_CYVIRTUALSCREEN:
		return ScreenHeight

	// Border widths.
	case SM_CXBORDER:
		return 1
	case SM_CYBORDER:
		return 1
	case SM_CXEDGE:
		return 2
	case SM_CYEDGE:
		return 2
	case SM_CXDLGFRAME: // == SM_CXFIXEDFRAME
		return 3
	case SM_CYDLGFRAME: // == SM_CYFIXEDFRAME
		return 3
	case SM_CXFRAME: // == SM_CXSIZEFRAME
		return 4
	case SM_CYFRAME: // == SM_CYSIZEFRAME
		return 4
	case SM_CXPADDEDBORDER:
		return 4

	// Caption / title bar.
	case SM_CYCAPTION:
		return 19
	case SM_CYSMCAPTION:
		return 15

	// Menu.
	case SM_CYMENU:
		return 19

	// Scrollbars.
	case SM_CXVSCROLL:
		return 17
	case SM_CYHSCROLL:
		return 17
	case SM_CYVSCROLL:
		return 17
	case SM_CXHSCROLL:
		return 17
	case SM_CYVTHUMB:
		return 17
	case SM_CXHTHUMB:
		return 17

	// Icons.
	case SM_CXICON:
		return 32
	case SM_CYICON:
		return 32
	case SM_CXSMICON:
		return 16
	case SM_CYSMICON:
		return 16
	case SM_CXICONSPACING:
		return 75
	case SM_CYICONSPACING:
		return 75

	// Cursor.
	case SM_CXCURSOR:
		return 32
	case SM_CYCURSOR:
		return 32

	// Window sizing.
	case SM_CXSIZE:
		return 18
	case SM_CYSIZE:
		return 18
	case SM_CXSMSIZE:
		return 15
	case SM_CYSMSIZE:
		return 15
	case SM_CXMENUSIZE:
		return 18
	case SM_CYMENUSIZE:
		return 18
	case SM_CXMIN:
		return 132
	case SM_CYMIN:
		return 38
	case SM_CXMINTRACK:
		return 132
	case SM_CYMINTRACK:
		return 38
	case SM_CXMINIMIZED:
		return 160
	case SM_CYMINIMIZED:
		return 28
	case SM_CXMAXIMIZED:
		return ScreenWidth
	case SM_CYMAXIMIZED:
		return ScreenHeight - GetSystemMetrics(SM_CYCAPTION) - GetSystemMetrics(SM_CYMENU)
	case SM_CXMAXTRACK:
		return ScreenWidth + 12
	case SM_CYMAXTRACK:
		return ScreenHeight + 12

	// Drag thresholds.
	case SM_CXDOUBLECLK:
		return 4
	case SM_CYDOUBLECLK:
		return 4
	case SM_CXDRAG:
		return 4
	case SM_CYDRAG:
		return 4

	// Checkmarks.
	case SM_CXMENUCHECK:
		return 13
	case SM_CYMENUCHECK:
		return 13

	// Focus border.
	case SM_CXFOCUSBORDER:
		return 1
	case SM_CYFOCUSBORDER:
		return 1

	// Presence flags.
	case SM_MOUSEPRESENT:
		return 1
	case SM_MOUSEWHEELPRESENT:
		return 1
	case SM_CMOUSEBUTTONS:
		return 3
	case SM_MOUSEHORIZONTALWHEELPRESENT:
		return 0
	case SM_CMONITORS:
		return 1
	case SM_SAMEDISPLAYFORMAT:
		return 1
	case SM_IMMENABLED:
		return 0
	case SM_DBCSENABLED:
		return 0
	case SM_DEBUG:
		return 0
	case SM_SLOWMACHINE:
		return 0
	case SM_SWAPBUTTON:
		return 0
	case SM_SECURE:
		return 0
	case SM_NETWORK:
		return 3
	case SM_CLEANBOOT:
		return 0
	case SM_PENWINDOWS:
		return 0
	case SM_MIDEASTENABLED:
		return 0
	case SM_TABLETPC:
		return 0
	case SM_MEDIACENTER:
		return 0
	case SM_STARTER:
		return 0
	case SM_SERVERR2:
		return 0
	case SM_DIGITIZER:
		return 0
	case SM_MAXIMUMTOUCHES:
		return 0
	case SM_REMOTESESSION:
		return 0
	case SM_REMOTECONTROL:
		return 0
	case SM_SHUTTINGDOWN:
		return 0
	case SM_SHOWSOUNDS:
		return 0
	case SM_ARRANGE:
		return 8
	case SM_MENUDROPALIGNMENT:
		return 0
	}
	return 0
}
