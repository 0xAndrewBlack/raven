//go:build guest_windows

package main

import (
	"strconv"
	"strings"
)

type formatMessageInsertResolver func(index int, format string) (string, bool)

func formatMessageUses64Bit(format string) bool {
	lower := strings.ToLower(format)
	return strings.Contains(lower, "i64") || strings.Contains(lower, "ll")
}

func formatMessageInsertFormats(template string) map[int]string {
	formats := make(map[int]string)
	for i := 0; i+1 < len(template); i++ {
		if template[i] != '%' || template[i+1] < '1' || template[i+1] > '9' {
			continue
		}
		end := i + 2
		index := int(template[i+1] - '0')
		if end < len(template) && template[end] >= '0' && template[end] <= '9' {
			index = index*10 + int(template[end]-'0')
			end++
		}
		format := "s"
		if end < len(template) && template[end] == '!' {
			close := strings.IndexByte(template[end+1:], '!')
			if close < 0 {
				continue
			}
			close += end + 1
			format = template[end+1 : close]
			i = close
		} else {
			i = end - 1
		}
		if _, exists := formats[index]; !exists {
			formats[index] = format
		}
	}
	return formats
}

func formatMessageArgumentSlot(template string, index int, is32 bool) uint64 {
	if index <= 1 {
		return 0
	}
	if !is32 {
		return uint64(index - 1)
	}
	formats := formatMessageInsertFormats(template)
	slot := uint64(0)
	for argument := 1; argument < index; argument++ {
		slot++
		if formatMessageUses64Bit(formats[argument]) {
			slot++
		}
	}
	return slot
}

func formatMessageFromTemplate(template string, ignoreInserts bool, resolve formatMessageInsertResolver) string {
	var out strings.Builder
	out.Grow(len(template))
	for i := 0; i < len(template); i++ {
		if template[i] != '%' || i+1 >= len(template) {
			out.WriteByte(template[i])
			continue
		}
		switch template[i+1] {
		case '0':
			return out.String()
		case '%':
			out.WriteByte('%')
			i++
			continue
		case 'n', 'N':
			out.WriteString("\r\n")
			i++
			continue
		case 'r', 'R':
			out.WriteByte('\r')
			i++
			continue
		case 't', 'T':
			out.WriteByte('\t')
			i++
			continue
		case 'b', 'B':
			out.WriteByte(' ')
			i++
			continue
		}
		if template[i+1] < '1' || template[i+1] > '9' {
			out.WriteByte(template[i])
			continue
		}
		end := i + 2
		index := int(template[i+1] - '0')
		if end < len(template) && template[end] >= '0' && template[end] <= '9' {
			index = index*10 + int(template[end]-'0')
			end++
		}
		format := "s"
		if end < len(template) && template[end] == '!' {
			close := strings.IndexByte(template[end+1:], '!')
			if close < 0 {
				out.WriteByte(template[i])
				continue
			}
			close += end + 1
			format = template[end+1 : close]
			end = close + 1
		}
		if ignoreInserts || resolve == nil {
			out.WriteString(template[i:end])
		} else if value, ok := resolve(index, format); ok {
			out.WriteString(value)
		} else {
			out.WriteString(template[i:end])
		}
		i = end - 1
	}
	return out.String()
}

func formatMessageInsertValue(value uint64, format string, wide bool, readANSI, readWide func(uint64) string) (string, bool) {
	format = strings.TrimSpace(format)
	if format == "" {
		format = "s"
	}
	verb := format[len(format)-1]
	switch verb {
	case 's':
		if value == 0 {
			return "(null)", true
		}
		if wide {
			return readWide(value), true
		}
		return readANSI(value), true
	case 'S':
		if value == 0 {
			return "(null)", true
		}
		if wide {
			return readANSI(value), true
		}
		return readWide(value), true
	case 'c', 'C':
		return string(rune(value)), true
	case 'd', 'i':
		return formatSignedDecimal(value, formatMessageUses64Bit(format)), true
	case 'u':
		return formatUnsignedDecimal(value, formatMessageUses64Bit(format)), true
	case 'x':
		return formatHex(value, formatMessageUses64Bit(format), false), true
	case 'X':
		return formatHex(value, formatMessageUses64Bit(format), true), true
	case 'p':
		return "0x" + formatHex(value, true, false), true
	default:
		return "", false
	}
}

func formatSignedDecimal(value uint64, is64 bool) string {
	if is64 {
		return strconv.FormatInt(int64(value), 10)
	}
	return strconv.FormatInt(int64(int32(value)), 10)
}

func formatUnsignedDecimal(value uint64, is64 bool) string {
	if !is64 {
		value = uint64(uint32(value))
	}
	return strconv.FormatUint(value, 10)
}

func formatHex(value uint64, is64, upper bool) string {
	if !is64 {
		value = uint64(uint32(value))
	}
	result := strconv.FormatUint(value, 16)
	if upper {
		result = strings.ToUpper(result)
	}
	return result
}
