//go:build guest_windows

package win32

import "sync"

// clipboardState holds in-memory clipboard data for a single format.
// Mirrors ReactOS win32ss/user/user32/misc/clipbrd.c behaviour.
type clipboardState struct {
	mu        sync.Mutex
	open      bool
	openOwner uint64 // HWND that called OpenClipboard
	owner     uint64 // HWND that owns the current contents
	format    uint32
	data      []byte // CF_UNICODETEXT: UTF-16LE bytes; CF_TEXT: ANSI bytes
}

var globalClipboard clipboardState

// CF_* clipboard format constants (matches Windows values).
const (
	CF_TEXT            = 1
	CF_BITMAP          = 2
	CF_METAFILEPICT    = 3
	CF_SYLK            = 4
	CF_DIF             = 5
	CF_TIFF            = 6
	CF_OEMTEXT         = 7
	CF_DIB             = 8
	CF_PALETTE         = 9
	CF_PENDATA         = 10
	CF_RIFF            = 11
	CF_WAVE            = 12
	CF_UNICODETEXT     = 13
	CF_ENHMETAFILE     = 14
	CF_HDROP           = 15
	CF_LOCALE          = 16
	CF_DIBV5           = 17
	CF_MAX             = 18
	CF_OWNERDISPLAY    = 0x0080
	CF_DSPTEXT         = 0x0081
	CF_DSPBITMAP       = 0x0082
	CF_DSPMETAFILEPICT = 0x0083
	CF_DSPENHMETAFILE  = 0x008E
	CF_PRIVATEFIRST    = 0x0200
	CF_PRIVATELAST     = 0x02FF
	CF_GDIOBJFIRST     = 0x0300
	CF_GDIOBJLAST      = 0x03FF
)

// OpenClipboard marks the clipboard as open for hwnd. Returns true on success.
func OpenClipboard(hwnd uint64) bool {
	globalClipboard.mu.Lock()
	defer globalClipboard.mu.Unlock()
	if globalClipboard.open {
		return false
	}
	globalClipboard.open = true
	globalClipboard.openOwner = hwnd
	return true
}

// CloseClipboard releases the clipboard. Returns true on success.
func CloseClipboard() bool {
	globalClipboard.mu.Lock()
	defer globalClipboard.mu.Unlock()
	if !globalClipboard.open {
		return false
	}
	globalClipboard.open = false
	globalClipboard.openOwner = 0
	return true
}

// EmptyClipboard clears clipboard contents. Must be called while the clipboard is open.
func EmptyClipboard() bool {
	globalClipboard.mu.Lock()
	defer globalClipboard.mu.Unlock()
	if !globalClipboard.open {
		return false
	}
	globalClipboard.format = 0
	globalClipboard.data = nil
	globalClipboard.owner = globalClipboard.openOwner
	return true
}

// SetClipboardData stores a copy of data for format. The clipboard must be open.
// Only one format is retained at a time; the last call wins.
func SetClipboardData(format uint32, data []byte) bool {
	globalClipboard.mu.Lock()
	defer globalClipboard.mu.Unlock()
	if !globalClipboard.open {
		return false
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	globalClipboard.format = format
	globalClipboard.data = cp
	return true
}

// GetClipboardData returns a copy of the clipboard data for format, or nil if unavailable.
func GetClipboardData(format uint32) []byte {
	globalClipboard.mu.Lock()
	defer globalClipboard.mu.Unlock()
	if globalClipboard.format != format || globalClipboard.data == nil {
		return nil
	}
	cp := make([]byte, len(globalClipboard.data))
	copy(cp, globalClipboard.data)
	return cp
}

// CountClipboardFormats returns the number of distinct formats currently available (0 or 1).
func CountClipboardFormats() int {
	globalClipboard.mu.Lock()
	defer globalClipboard.mu.Unlock()
	if globalClipboard.data != nil {
		return 1
	}
	return 0
}

// IsClipboardFormatAvailable returns true if format is available.
func IsClipboardFormatAvailable(format uint32) bool {
	globalClipboard.mu.Lock()
	defer globalClipboard.mu.Unlock()
	return globalClipboard.format == format && globalClipboard.data != nil
}

// GetClipboardOwner returns the HWND that owns the clipboard contents.
func GetClipboardOwner() uint64 {
	globalClipboard.mu.Lock()
	defer globalClipboard.mu.Unlock()
	return globalClipboard.owner
}

// GetOpenClipboardWindow returns the HWND that currently has the clipboard open, or 0.
func GetOpenClipboardWindow() uint64 {
	globalClipboard.mu.Lock()
	defer globalClipboard.mu.Unlock()
	if !globalClipboard.open {
		return 0
	}
	return globalClipboard.openOwner
}
