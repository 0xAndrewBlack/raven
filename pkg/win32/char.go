package win32

import "unicode"

// CharUpperString converts all characters in s to uppercase.
func CharUpperString(s string) string {
	runes := []rune(s)
	for i, r := range runes {
		runes[i] = unicode.ToUpper(r)
	}
	return string(runes)
}

// CharLowerString converts all characters in s to lowercase.
func CharLowerString(s string) string {
	runes := []rune(s)
	for i, r := range runes {
		runes[i] = unicode.ToLower(r)
	}
	return string(runes)
}

// CharUpperBuff uppercases the first n WCHARs in chars in-place. Returns n.
func CharUpperBuff(chars []uint16, n int) int {
	if n > len(chars) {
		n = len(chars)
	}
	for i := 0; i < n; i++ {
		chars[i] = uint16(unicode.ToUpper(rune(chars[i])))
	}
	return n
}

// CharLowerBuff lowercases the first n WCHARs in chars in-place. Returns n.
func CharLowerBuff(chars []uint16, n int) int {
	if n > len(chars) {
		n = len(chars)
	}
	for i := 0; i < n; i++ {
		chars[i] = uint16(unicode.ToLower(rune(chars[i])))
	}
	return n
}

// IsCharAlpha returns true if c is an alphabetic character.
func IsCharAlpha(c rune) bool { return unicode.IsLetter(c) }

// IsCharAlphaNumeric returns true if c is alphanumeric.
func IsCharAlphaNumeric(c rune) bool { return unicode.IsLetter(c) || unicode.IsDigit(c) }

// IsCharLower returns true if c is a lowercase character.
func IsCharLower(c rune) bool { return unicode.IsLower(c) }

// IsCharUpper returns true if c is an uppercase character.
func IsCharUpper(c rune) bool { return unicode.IsUpper(c) }

// CharNextIdx returns pos+1, clamped to len(s).
func CharNextIdx(s []uint16, pos int) int {
	if pos < len(s) {
		return pos + 1
	}
	return len(s)
}

// CharPrevIdx returns pos-1, clamped to start.
func CharPrevIdx(s []uint16, start, pos int) int {
	if pos > start {
		return pos - 1
	}
	return start
}

// OemToCharString is a no-op in pure Unicode mode (OEM == Unicode).
func OemToCharString(s string) string { return s }

// CharToOemString is a no-op in pure Unicode mode (OEM == Unicode).
func CharToOemString(s string) string { return s }
