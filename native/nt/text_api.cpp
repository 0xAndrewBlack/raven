#include "kernel_context.h"
#include "nls.h"
#include "text.h"

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <map>

namespace raven {

namespace {

constexpr uint32_t locale_return_number = 0x20000000;

const std::map<uint32_t, std::u16string> &locale_strings()
{
	static const std::map<uint32_t, std::u16string> table = [] {
		std::map<uint32_t, std::u16string> t{
			{0x1, u"0409"}, {0x2, u"English (United States)"}, {0x3, u"English (United States)"}, {0x4, u"English"}, {0x5, u"United States"},
			{0x6, u"United States"}, {0x7, u"English"}, {0x8, u"USA"}, {0x9, u"0409"}, {0xa, u"1"}, {0xb, u"437"},
			{0xc, u","}, {0xd, u"0"}, {0xe, u"."}, {0xf, u","}, {0x10, u"3;0"}, {0x11, u"1"}, {0x12, u"2"}, {0x13, u"1"},
			{0x14, u"$"}, {0x15, u"USD"}, {0x16, u"US Dollar"}, {0x17, u"."}, {0x18, u","}, {0x19, u"3;0"}, {0x1a, u"2"},
			{0x1b, u"0"}, {0x1c, u"0"}, {0x1d, u"/"}, {0x1e, u":"}, {0x1f, u"M/d/yyyy"}, {0x20, u"dddd, MMMM d, yyyy"},
			{0x21, u"0"}, {0x22, u"1"}, {0x23, u"0"}, {0x24, u"0"}, {0x25, u"0"}, {0x26, u"1"}, {0x27, u"1"}, {0x28, u"AM"},
			{0x29, u"PM"}, {0x1001, u"English"}, {0x1002, u"United States"}, {0x1003, u"h:mm:ss tt"}, {0x1004, u"1252"},
			{0x1005, u"437"}, {0x1006, u"437"}, {0x1007, u"1"}, {0x1008, u"1"}, {0x1009, u"6"}, {0x100c, u"6"},
			{0x100d, u"0"}, {0x59, u"en"}, {0x5a, u"US"}, {0x5b, u"ENU"}, {0x5c, u"en-US"}, {0x5d, u"USA"}, {0x66, u"en-US"},
			{0x6e, u"."}, {0x74, u"0"}, {0x75, u"0"}, {0x1000, u"0409"}, {0x4a, u"+"}, {0x4b, u"-"}, {0x50, u"-"},
		};
		static constexpr const char16_t *days[] = {u"Monday", u"Tuesday", u"Wednesday", u"Thursday", u"Friday", u"Saturday", u"Sunday"};
		static constexpr const char16_t *months[] = {u"January", u"February", u"March", u"April", u"May", u"June", u"July", u"August",
			u"September", u"October", u"November", u"December"};
		for (uint32_t index = 0; index < 7; ++index) {
			t[0x2a + index] = days[index];
			t[0x31 + index] = std::u16string(days[index]).substr(0, 3);
		}
		for (uint32_t index = 0; index < 12; ++index) {
			t[0x38 + index] = months[index];
			t[0x44 + index] = std::u16string(months[index]).substr(0, 3);
		}
		return t;
	}();
	return table;
}

std::optional<std::u16string> locale_text(uint32_t type)
{
	type &= ~locale_return_number & ~0x80000000U;
	const auto found = locale_strings().find(type);
	if (found == locale_strings().end())
		return std::nullopt;
	return found->second;
}

uint32_t as_number(const std::u16string &text)
{
	uint32_t value = 0;
	for (const auto character : text)
		if (character >= u'0' && character <= u'9')
			value = value * 10 + (character - u'0');
		else if (character == u';')
			break;
	return value;
}

// Reads a counted or zero-terminated UTF-16 argument; a count of -1 means "until the terminator".
std::u16string counted_wide(ApiCall &call, uint64_t address, int32_t count)
{
	if (count < 0)
		return call.wide(address);
	const auto bytes = call.read(address, size_t(count) * 2);
	std::u16string text(size_t(count), u'\0');
	std::memcpy(text.data(), bytes.data(), bytes.size());
	return text;
}

std::string counted_narrow(ApiCall &call, uint64_t address, int32_t count)
{
	if (count < 0)
		return call.narrow(address);
	const auto bytes = call.read(address, size_t(count));
	return std::string(bytes.begin(), bytes.end());
}

std::u16string decode_ansi(std::string_view text, uint32_t code_page)
{
	if (code_page == 65001)
		return from_utf8(text);
	std::u16string result;
	for (const auto byte : text) {
		const auto value = static_cast<unsigned char>(byte);
		if (value >= 0x80 && value < 0xa0 && code_page == 1252) {
			static constexpr char16_t high[32] = {0x20ac, 0x81, 0x201a, 0x192, 0x201e, 0x2026, 0x2020, 0x2021, 0x2c6, 0x2030, 0x160, 0x2039, 0x152,
				0x8d, 0x17d, 0x8f, 0x90, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014, 0x2dc, 0x2122, 0x161, 0x203a, 0x153, 0x9d, 0x17e, 0x178};
			result.push_back(high[value - 0x80]);
		} else {
			result.push_back(char16_t(value));
		}
	}
	return result;
}

int collate(std::u16string_view left, std::u16string_view right, uint32_t flags)
{
	const bool ignore_case = flags & (0x1 | 0x10000000 | 0x10);
	const int folded = compare_fold(left, right);
	if (folded || ignore_case)
		return folded;
	for (size_t at = 0; at < std::min(left.size(), right.size()); ++at)
		if (left[at] != right[at])
			return fold_case(left[at]) == left[at] ? -1 : 1;
	return 0;
}

// Windows date and time pictures: d dd ddd dddd M MM MMM MMMM y yy yyyy and quoted literals; h hh H HH m mm s ss t tt.
std::u16string picture(std::u16string_view format, const uint16_t *time, bool date)
{
	static const std::u16string_view days[] = {u"Sunday", u"Monday", u"Tuesday", u"Wednesday", u"Thursday", u"Friday", u"Saturday"};
	static const std::u16string_view months[] = {u"January", u"February", u"March", u"April", u"May", u"June", u"July", u"August", u"September",
		u"October", u"November", u"December"};
	std::u16string result;
	const auto two = [](unsigned value) { return std::u16string{char16_t(u'0' + value / 10 % 10), char16_t(u'0' + value % 10)}; };
	for (size_t at = 0; at < format.size();) {
		const char16_t letter = format[at];
		size_t run = 1;
		while (at + run < format.size() && format[at + run] == letter)
			++run;
		if (letter == u'\'') {
			size_t end = at + 1;
			while (end < format.size()) {
				if (format[end] == u'\'' && end + 1 < format.size() && format[end + 1] == u'\'')
					end += 2;
				else if (format[end] == u'\'')
					break;
				else
					result.push_back(format[end++]);
			}
			at = end + 1;
			continue;
		}
		if (date && letter == u'd') {
			if (run >= 4) result += days[time[2] % 7];
			else if (run == 3) result += days[time[2] % 7].substr(0, 3);
			else if (run == 2) result += two(time[3]);
			else result += widen_ascii(std::to_string(time[3]));
		} else if (date && letter == u'M') {
			if (run >= 4) result += months[(time[1] + 11) % 12];
			else if (run == 3) result += months[(time[1] + 11) % 12].substr(0, 3);
			else if (run == 2) result += two(time[1]);
			else result += widen_ascii(std::to_string(time[1]));
		} else if (date && letter == u'y') {
			if (run >= 3) result += widen_ascii(std::to_string(time[0]));
			else if (run == 2) result += two(time[0] % 100);
			else result += widen_ascii(std::to_string(time[0] % 100));
		} else if (!date && (letter == u'h' || letter == u'H')) {
			unsigned hour = time[4];
			if (letter == u'h') {
				hour %= 12;
				if (!hour) hour = 12;
			}
			result += run >= 2 ? two(hour) : widen_ascii(std::to_string(hour));
		} else if (!date && letter == u'm') {
			result += run >= 2 ? two(time[5]) : widen_ascii(std::to_string(time[5]));
		} else if (!date && letter == u's') {
			result += run >= 2 ? two(time[6]) : widen_ascii(std::to_string(time[6]));
		} else if (!date && letter == u't') {
			const std::u16string marker = time[4] < 12 ? u"AM" : u"PM";
			result += run >= 2 ? marker : marker.substr(0, 1);
		} else {
			result.append(run, letter);
		}
		at += run;
	}
	return result;
}

std::optional<std::u16string> system_message(uint32_t id)
{
	static const std::map<uint32_t, std::u16string> messages{
		{0, u"The operation completed successfully.\r\n"}, {1, u"Incorrect function.\r\n"},
		{2, u"The system cannot find the file specified.\r\n"}, {3, u"The system cannot find the path specified.\r\n"},
		{4, u"The system cannot open the file.\r\n"}, {5, u"Access is denied.\r\n"}, {6, u"The handle is invalid.\r\n"},
		{8, u"Not enough memory resources are available to process this command.\r\n"}, {12, u"The access code is invalid.\r\n"},
		{15, u"The system cannot find the drive specified.\r\n"}, {18, u"There are no more files.\r\n"},
		{19, u"The media is write protected.\r\n"}, {21, u"The device is not ready.\r\n"},
		{32, u"The process cannot access the file because it is being used by another process.\r\n"},
		{33, u"The process cannot access the file because another process has locked a portion of the file.\r\n"},
		{50, u"The request is not supported.\r\n"}, {53, u"The network path was not found.\r\n"},
		{80, u"The file exists.\r\n"}, {82, u"The directory or file cannot be created.\r\n"},
		{87, u"The parameter is incorrect.\r\n"}, {112, u"There is not enough space on the disk.\r\n"},
		{122, u"The data area passed to a system call is too small.\r\n"}, {123, u"The filename, directory name, or volume label syntax is incorrect.\r\n"},
		{126, u"The specified module could not be found.\r\n"}, {127, u"The specified procedure could not be found.\r\n"},
		{145, u"The directory is not empty.\r\n"}, {183, u"Cannot create a file when that file already exists.\r\n"},
		{206, u"The filename or extension is too long.\r\n"}, {267, u"The directory name is invalid.\r\n"},
		{995, u"The I/O operation has been aborted because of either a thread exit or an application request.\r\n"},
		{998, u"Invalid access to memory location.\r\n"}, {1223, u"The operation was canceled by the user.\r\n"},
		{1400, u"Invalid window handle.\r\n"}, {1460, u"This operation returned because the timeout period expired.\r\n"},
		{1813, u"The specified resource type cannot be found in the image file.\r\n"},
	};
	const auto found = messages.find(id);
	if (found == messages.end())
		return std::nullopt;
	return found->second;
}

// Replaces %1..%99 (with optional !printf! formats), %n, %r, %t, %% and %0 in a message template.
std::u16string insert_arguments(std::u16string_view text, const std::vector<std::u16string> &inserts, const std::vector<uint64_t> &raw)
{
	std::u16string result;
	for (size_t at = 0; at < text.size(); ++at) {
		if (text[at] != u'%' || at + 1 >= text.size()) {
			result.push_back(text[at]);
			continue;
		}
		const char16_t next = text[at + 1];
		if (next >= u'1' && next <= u'9') {
			size_t end = at + 1;
			unsigned index = 0;
			while (end < text.size() && text[end] >= u'0' && text[end] <= u'9' && index < 100)
				index = index * 10 + (text[end++] - u'0');
			std::u16string format;
			if (end < text.size() && text[end] == u'!') {
				const auto close = text.find(u'!', end + 1);
				if (close != text.npos) {
					format = text.substr(end + 1, close - end - 1);
					end = close + 1;
				}
			}
			if (index >= 1 && index <= inserts.size()) {
				if (format.empty() || format == u"s")
					result += inserts[index - 1];
				else {
					const char16_t kind = format.back();
					const uint64_t value = raw[index - 1];
					if (kind == u'd' || kind == u'i') result += widen_ascii(std::to_string(int32_t(value)));
					else if (kind == u'u') result += widen_ascii(std::to_string(uint32_t(value)));
					else if (kind == u'x' || kind == u'X') {
						char digits[17];
						std::snprintf(digits, sizeof digits, kind == u'x' ? "%x" : "%X", uint32_t(value));
						result += widen_ascii(digits);
					} else result += inserts[index - 1];
				}
			}
			at = end - 1;
		} else if (next == u'n') {
			result += u"\r\n";
			++at;
		} else if (next == u'r') {
			result.push_back(u'\r');
			++at;
		} else if (next == u't') {
			result.push_back(u'\t');
			++at;
		} else if (next == u'0') {
			break;
		} else {
			result.push_back(next);
			++at;
		}
	}
	return result;
}

}

void register_text_api(ApiRegistry &registry, KernelContext &context)
{
	auto &memory = context.memory;
	const auto ansi_page = [&](uint32_t code_page) {
		return code_page == 0 || code_page == 3 ? context.launch.ansi_code_page : code_page == 1 ? 437 : code_page;
	};

	registry.add("lstrlenW", 1, [](ApiCall &call) { call.ret(call[0] ? call.wide(call[0], 1 << 24).size() : 0); });
	registry.add("lstrlenA", 1, [](ApiCall &call) { call.ret(call[0] ? call.narrow(call[0], 1 << 24).size() : 0); });
	registry.add("lstrcpyW", 2, [](ApiCall &call) {
		const auto text = call.wide(call[1], 1 << 24);
		call.put_wide(call[0], text, text.size() + 1);
		call.ret(call[0]);
	});
	registry.add("lstrcpyA", 2, [](ApiCall &call) {
		const auto text = call.narrow(call[1], 1 << 24);
		call.put_narrow(call[0], text, text.size() + 1);
		call.ret(call[0]);
	});
	registry.add("lstrcpynW", 3, [](ApiCall &call) {
		const int32_t capacity = call.i32(2);
		if (capacity <= 0) {
			call.ret(0);
			return;
		}
		const auto text = call.wide(call[1], 1 << 24);
		call.put_wide(call[0], text.substr(0, size_t(capacity) - 1), size_t(capacity));
		call.ret(call[0]);
	});
	registry.add("lstrcpynA", 3, [](ApiCall &call) {
		const int32_t capacity = call.i32(2);
		if (capacity <= 0) {
			call.ret(0);
			return;
		}
		const auto text = call.narrow(call[1], 1 << 24);
		call.put_narrow(call[0], text.substr(0, size_t(capacity) - 1), size_t(capacity));
		call.ret(call[0]);
	});
	registry.add("lstrcmpW", 2, [](ApiCall &call) { call.ret(uint32_t(collate(call.wide(call[0]), call.wide(call[1]), 0))); });
	registry.add("lstrcmpiW", 2, [](ApiCall &call) { call.ret(uint32_t(collate(call.wide(call[0]), call.wide(call[1]), 1))); });
	registry.add("lstrcmpiA", 2, [](ApiCall &call) {
		call.ret(uint32_t(collate(widen_ascii(call.narrow(call[0])), widen_ascii(call.narrow(call[1])), 1)));
	});
	registry.add("lstrcmpA", 2, [](ApiCall &call) {
		call.ret(uint32_t(collate(widen_ascii(call.narrow(call[0])), widen_ascii(call.narrow(call[1])), 0)));
	});

	registry.add("WideCharToMultiByte", 8, [&, ansi_page](ApiCall &call) {
		const uint32_t page = ansi_page(call.u32(0));
		const int32_t count = call.i32(3);
		const int32_t capacity = call.i32(5);
		if (!call[2] || !count || capacity < 0 || (capacity && !call[4])) {
			call.fail(87);
			return;
		}
		const auto source = counted_wide(call, call[2], count);
		std::string encoded;
		bool replaced = false;
		if (page == 65001) {
			encoded = encode_utf8(source, true);
		} else if (page == 1252 || page == 437 || page == 850 || page == 28591 || page == 20127) {
			encoded = encode_ansi(source, 1252);
			for (size_t at = 0; at < source.size(); ++at)
				if (source[at] > 0xff && !(source[at] >= 0x2013 && source[at] <= 0x2122) && encoded[at] == '?')
					replaced = true;
		} else {
			call.fail(87);
			return;
		}
		if (count < 0)
			encoded.push_back('\0');
		if (call[7]) call.store<uint32_t>(call[7], replaced);
		if (!capacity) {
			call.ret(encoded.size());
			return;
		}
		if (size_t(capacity) < encoded.size()) {
			call.fail(122);
			return;
		}
		call.write(call[4], std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(encoded.data()), encoded.size()));
		call.ret(encoded.size());
	});

	registry.add("CompareStringW", 6, [](ApiCall &call) {
		const auto left = counted_wide(call, call[2], call.i32(3)), right = counted_wide(call, call[4], call.i32(5));
		call.ret(uint32_t(collate(left, right, call.u32(1)) + 2));
	});
	registry.add("CompareStringEx", 9, [](ApiCall &call) {
		const auto left = counted_wide(call, call[2], call.i32(3)), right = counted_wide(call, call[4], call.i32(5));
		call.ret(uint32_t(collate(left, right, call.u32(1)) + 2));
	});
	const auto map_string = [](ApiCall &call, uint32_t flags, std::u16string text, uint64_t destination, int32_t capacity) {
		if (flags & 0x100) for (auto &character : text) character = fold_case(character);
		else if (flags & 0x200) for (auto &character : text) character = upper_case(character);
		const size_t needed = text.size();
		if (!capacity) {
			call.ret(needed);
			return;
		}
		if (size_t(capacity) < needed) {
			call.fail(122);
			return;
		}
		call.put_wide(destination, text, size_t(capacity) + 1);
		std::vector<uint8_t> bytes(text.size() * 2);
		std::memcpy(bytes.data(), text.data(), bytes.size());
		call.write(destination, bytes);
		call.ret(needed);
	};
	registry.add("LCMapStringW", 6, [map_string](ApiCall &call) {
		const int32_t length = call.i32(3);
		auto text = counted_wide(call, call[2], length);
		if (length < 0) text.push_back(u'\0');
		const auto zero = length < 0;
		if (zero) text.pop_back();
		map_string(call, call.u32(1), text, call[4], call.i32(5));
		if (zero && call.result) call.ret(call.result + 1);
	});
	registry.add("LCMapStringEx", 9, [map_string](ApiCall &call) {
		const int32_t length = call.i32(3);
		auto text = counted_wide(call, call[2], length);
		map_string(call, call.u32(1), text, call[4], call.i32(5));
		if (length < 0 && call.result) call.ret(call.result + 1);
	});
	registry.add("LCMapStringA", 6, [&, map_string, ansi_page](ApiCall &call) {
		const int32_t length = call.i32(3);
		const auto narrow = counted_narrow(call, call[2], length);
		const auto page = ansi_page(0);
		auto text = decode_ansi(narrow, page);
		const uint32_t flags = call.u32(1);
		if (flags & 0x100) for (auto &character : text) character = fold_case(character);
		else if (flags & 0x200) for (auto &character : text) character = upper_case(character);
		auto result = encode_ansi(text, page);
		const int32_t capacity = call.i32(5);
		if (!capacity) {
			call.ret(result.size());
			return;
		}
		if (size_t(capacity) < result.size()) {
			call.fail(122);
			return;
		}
		call.write(call[4], std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(result.data()), result.size()));
		call.ret(result.size());
	});
	registry.add("GetStringTypeW", 5, [](ApiCall &call) {
		const uint32_t kind = call.u32(0);
		if (!call[1] || !call[4] || (kind != 1 && kind != 2 && kind != 4)) {
			call.fail(87);
			return;
		}
		const auto text = counted_wide(call, call[1], call.i32(2));
		static const bool unicode = std::setlocale(LC_CTYPE, "C.UTF-8") != nullptr;
		(void)unicode;
		std::vector<uint8_t> bytes(text.size() * 2);
		for (size_t at = 0; at < text.size(); ++at) {
			const wint_t c = text[at];
			uint16_t value = 0;
			if (kind == 1) {
				if (std::iswupper(c)) value |= 0x1 | 0x100;
				if (std::iswlower(c)) value |= 0x2 | 0x100;
				if (std::iswdigit(c)) value |= 0x4;
				if (std::iswspace(c)) value |= 0x8;
				if (std::iswpunct(c)) value |= 0x10;
				if (std::iswcntrl(c)) value |= 0x20;
				if (c == u' ' || c == u'\t') value |= 0x40;
				if (std::iswxdigit(c)) value |= 0x80;
				if (std::iswalpha(c) && !(value & 0x100)) value |= 0x100;
				if (c >= 0x20 || std::iswcntrl(c)) value |= 0x200;
			} else if (kind == 2) {
				value = std::iswalpha(c) ? 1 : std::iswdigit(c) ? 3 : std::iswspace(c) ? 12 : 11;
			} else {
				if (std::iswalpha(c)) value |= 0x8000;
				if (std::iswpunct(c)) value |= 0x10;
				if (std::iswspace(c)) value |= 0x8;
				if (c >= 0x300 && c < 0x370) value |= 0x1;
			}
			std::memcpy(bytes.data() + at * 2, &value, 2);
		}
		call.write(call[4], bytes);
		call.ret(1);
	});
	registry.add("GetStringTypeExW", 5, [](ApiCall &call) {
		call.fail(120);
	});

	registry.add("GetCPInfo", 2, [](ApiCall &call) {
		const uint32_t page = call.u32(0);
		if (page != 0 && page != 1 && page != 437 && page != 850 && page != 1252 && page != 28591 && page != 20127 && page != 65001) {
			call.fail(87);
			return;
		}
		std::vector<uint8_t> bytes(20);
		const uint32_t maximum = page == 65001 ? 4 : 1;
		std::memcpy(bytes.data(), &maximum, 4);
		bytes[4] = '?';
		call.write(call[1], bytes);
		call.ret(1);
	});
	registry.add("IsValidCodePage", 1, [](ApiCall &call) {
		const uint32_t page = call.u32(0);
		call.ret(page == 437 || page == 850 || page == 1252 || page == 28591 || page == 20127 || page == 65001 || page == 1200 || page == 1201);
	});
	registry.add("GetOEMCP", 0, [](ApiCall &call) { call.ret(437); });
	registry.add("GetConsoleOutputCP", 0, [](ApiCall &call) { call.ret(437); });
	registry.add("GetConsoleCP", 0, [](ApiCall &call) { call.ret(437); });
	registry.add("GetConsoleMode", 2, [](ApiCall &call) { call.fail(6); });
	registry.add("SetConsoleMode", 2, [](ApiCall &call) { call.fail(6); });
	registry.add("WriteConsoleW", 5, [](ApiCall &call) { call.fail(6); });
	registry.add("ReadConsoleW", 5, [](ApiCall &call) { call.fail(6); });

	registry.add("GetUserDefaultLCID", 0, [](ApiCall &call) { call.ret(0x409); });
	registry.add("GetSystemDefaultLCID", 0, [](ApiCall &call) { call.ret(0x409); });
	registry.add("GetUserDefaultLangID", 0, [](ApiCall &call) { call.ret(0x409); });
	registry.add("GetSystemDefaultLangID", 0, [](ApiCall &call) { call.ret(0x409); });
	registry.add("GetThreadLocale", 0, [](ApiCall &call) { call.ret(0x409); });
	registry.add("SetThreadLocale", 1, [](ApiCall &call) { call.ret(1); });
	registry.add("IsValidLocale", 2, [](ApiCall &call) { call.ret(call.u32(0) == 0x409 || call.u32(0) == 0x400 || call.u32(0) == 0x800); });
	const auto locale_name = [](ApiCall &call, uint64_t buffer, int32_t capacity) {
		const std::u16string name = u"en-US";
		if (capacity && size_t(capacity) <= name.size()) {
			call.fail(122);
			return;
		}
		call.put_wide(buffer, name, size_t(capacity));
		call.ret(name.size() + 1);
	};
	registry.add("GetUserDefaultLocaleName", 2, [locale_name](ApiCall &call) { locale_name(call, call[0], call.i32(1)); });
	registry.add("GetSystemDefaultLocaleName", 2, [locale_name](ApiCall &call) { locale_name(call, call[0], call.i32(1)); });
	registry.add("LocaleNameToLCID", 2, [](ApiCall &call) { call.ret(0x409); });
	registry.add("LCIDToLocaleName", 4, [](ApiCall &call) {
		const std::u16string name = u"en-US";
		const int32_t capacity = call.i32(2);
		if (capacity && size_t(capacity) <= name.size()) {
			call.fail(122);
			return;
		}
		call.put_wide(call[1], name, size_t(capacity));
		call.ret(name.size() + 1);
	});
	const auto locale_info = [](ApiCall &call, uint32_t type, uint64_t buffer, int32_t capacity, bool wide) {
		const auto text = locale_text(type);
		if (!text) {
			call.fail(87);
			return;
		}
		if (type & locale_return_number) {
			if (capacity < 4) {
				call.fail(122);
				return;
			}
			call.store<uint32_t>(buffer, as_number(*text));
			call.ret(2);
			return;
		}
		const size_t needed = text->size() + 1;
		if (!capacity) {
			call.ret(needed);
			return;
		}
		if (size_t(capacity) < needed) {
			call.fail(122);
			return;
		}
		if (wide)
			call.put_wide(buffer, *text, size_t(capacity));
		else
			call.put_narrow(buffer, to_utf8(*text), size_t(capacity));
		call.ret(needed);
	};
	registry.add("GetLocaleInfoW", 4, [locale_info](ApiCall &call) { locale_info(call, call.u32(1), call[2], call.i32(3), true); });
	registry.add("GetLocaleInfoA", 4, [locale_info](ApiCall &call) { locale_info(call, call.u32(1), call[2], call.i32(3), false); });
	registry.add("GetLocaleInfoEx", 4, [locale_info](ApiCall &call) { locale_info(call, call.u32(1), call[2], call.i32(3), true); });
	registry.add("EnumSystemLocalesW", 2, [&](ApiCall &call) {
		const auto scratch = memory.allocate(0, 4096, 0x3000, 4);
		if (scratch.status) {
			call.fail(8);
			return;
		}
		const std::u16string name = u"00000409";
		std::vector<uint8_t> bytes((name.size() + 1) * 2);
		std::memcpy(bytes.data(), name.data(), name.size() * 2);
		call.write(scratch.address, bytes);
		const uint64_t arguments[] = {scratch.address};
		const auto result = context.call(call[0], arguments);
		memory.free(scratch.address, 0, 0x8000);
		if (result.stop != NativeStop::returned)
			throw result;
		call.ret(1);
	});

	const auto format_date_time = [](ApiCall &call, bool date, uint64_t flags_index, uint64_t time_index, uint64_t format_index,
		uint64_t buffer_index, uint64_t size_index) {
		const uint32_t flags = call.u32(flags_index);
		uint16_t fields[8];
		if (call[time_index]) {
			const auto bytes = call.read(call[time_index], 16);
			std::memcpy(fields, bytes.data(), 16);
		} else {
			timespec now{};
			::clock_gettime(CLOCK_REALTIME, &now);
			tm local{};
			::localtime_r(&now.tv_sec, &local);
			const uint16_t current[8] = {uint16_t(local.tm_year + 1900), uint16_t(local.tm_mon + 1), uint16_t(local.tm_wday), uint16_t(local.tm_mday),
				uint16_t(local.tm_hour), uint16_t(local.tm_min), uint16_t(local.tm_sec), uint16_t(now.tv_nsec / 1000000)};
			std::memcpy(fields, current, 16);
		}
		std::u16string pattern;
		if (call[format_index])
			pattern = call.wide(call[format_index]);
		else if (date)
			pattern = flags & 2 ? u"dddd, MMMM d, yyyy" : u"M/d/yyyy";
		else {
			pattern = flags & 0x8 ? u"HH:mm:ss" : u"h:mm:ss tt";
			if (flags & 2) pattern = flags & 0x8 ? u"HH:mm" : u"h:mm tt";
			if (flags & 1) pattern = flags & 0x8 ? u"HH" : u"h tt";
			if (flags & 4) {
				const auto marker = pattern.find(u" tt");
				if (marker != pattern.npos) pattern.erase(marker);
			}
		}
		const auto text = picture(pattern, fields, date);
		const int32_t capacity = call.i32(size_index);
		if (!capacity) {
			call.ret(text.size() + 1);
			return;
		}
		if (size_t(capacity) <= text.size()) {
			call.fail(122);
			return;
		}
		call.put_wide(call[buffer_index], text, size_t(capacity));
		call.ret(text.size() + 1);
	};
	registry.add("GetDateFormatW", 6, [format_date_time](ApiCall &call) { format_date_time(call, true, 1, 2, 3, 4, 5); });
	registry.add("GetDateFormatEx", 7, [format_date_time](ApiCall &call) { format_date_time(call, true, 1, 2, 3, 4, 5); });
	registry.add("GetTimeFormatW", 6, [format_date_time](ApiCall &call) { format_date_time(call, false, 1, 2, 3, 4, 5); });
	registry.add("GetTimeFormatEx", 6, [format_date_time](ApiCall &call) { format_date_time(call, false, 1, 2, 3, 4, 5); });

	registry.add("FormatMessageW", 7, [&](ApiCall &call) {
		const uint32_t flags = call.u32(0);
		std::u16string text;
		if (flags & 0x400) {
			text = call.wide(call[1]);
		} else if (flags & 0x1000) {
			const auto found = system_message(call.u32(2));
			if (!found) {
				call.fail(317);
				return;
			}
			text = *found;
		} else {
			call.fail(1812);
			return;
		}
		if (!(flags & 0x200)) {
			std::vector<std::u16string> inserts;
			std::vector<uint64_t> raw;
			if (call[6]) {
				// Without an argument array the inserts follow as a va_list; only an explicit array is read here.
				if (flags & 0x2000) {
					for (unsigned index = 0; index < 99; ++index) {
						uint64_t value = 0;
						try { value = call.load<uint64_t>(call[6] + index * 8); } catch (const ApiFault &) { break; }
						raw.push_back(value);
						inserts.push_back(value ? [&] { try { return call.wide(value, 4096); } catch (const ApiFault &) { return std::u16string(); } }() : u"");
						if (index >= 8) break;
					}
				}
			}
			text = insert_arguments(text, inserts, raw);
		}
		const uint32_t width = flags & 0xff;
		if (width && width != 0xff) {
			(void)width;
		}
		if (flags & 0x100) {
			const auto address = context.allocator.allocate((text.size() + 1) * 2, false);
			if (!address) {
				call.fail(8);
				return;
			}
			call.put_wide(address, text, text.size() + 1);
			call.store<uint64_t>(call[4], address);
			call.ret(text.size());
			return;
		}
		const size_t capacity = call.u32(5);
		if (capacity <= text.size()) {
			call.fail(122);
			return;
		}
		call.put_wide(call[4], text, capacity);
		call.ret(text.size());
	});
	registry.add("FormatMessageA", 7, [&](ApiCall &call) {
		const uint32_t flags = call.u32(0);
		std::u16string text;
		if (flags & 0x400) text = from_utf8(call.narrow(call[1]));
		else if (flags & 0x1000) {
			const auto found = system_message(call.u32(2));
			if (!found) {
				call.fail(317);
				return;
			}
			text = *found;
		} else {
			call.fail(1812);
			return;
		}
		const auto narrow = to_utf8(text);
		if (flags & 0x100) {
			const auto address = context.allocator.allocate(narrow.size() + 1, false);
			if (!address) {
				call.fail(8);
				return;
			}
			call.put_narrow(address, narrow, narrow.size() + 1);
			call.store<uint64_t>(call[4], address);
			call.ret(narrow.size());
			return;
		}
		if (call.u32(5) <= narrow.size()) {
			call.fail(122);
			return;
		}
		call.put_narrow(call[4], narrow, call.u32(5));
		call.ret(narrow.size());
	});
}

}
