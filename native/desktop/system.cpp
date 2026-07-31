#include "windows.h"
#include "nt/nls.h"

#include <algorithm>
#include <stdexcept>

namespace raven {

namespace {

uint64_t read_le(std::span<const uint8_t> bytes, size_t at, size_t width)
{
	uint64_t value = 0;
	for (size_t byte = 0; byte < width; ++byte)
		value |= uint64_t(bytes[at + byte]) << (byte * 8);
	return value;
}

void write_le(std::span<uint8_t> bytes, size_t at, uint64_t value, size_t width)
{
	for (size_t byte = 0; byte < width; ++byte)
		bytes[at + byte] = uint8_t(value >> (byte * 8));
}

// One printf-style conversion of Win32 wsprintf: flags, width, precision, size prefix and type.
struct Conversion {
	bool left = false, zero = false, plus = false, space = false, alternate = false;
	int64_t width = 0, precision = -1;
	bool wide_size = false, narrow_size = false;
	char type = 0;
	bool width_argument = false, precision_argument = false;
};

std::optional<Conversion> parse_conversion(std::u16string_view format, size_t &at)
{
	Conversion item;
	for (; at < format.size(); ++at) {
		const auto c = format[at];
		if (c == u'-') item.left = true;
		else if (c == u'0') item.zero = true;
		else if (c == u'+') item.plus = true;
		else if (c == u' ') item.space = true;
		else if (c == u'#') item.alternate = true;
		else break;
	}
	if (at < format.size() && format[at] == u'*') {
		item.width_argument = true;
		++at;
	} else {
		for (; at < format.size() && format[at] >= u'0' && format[at] <= u'9'; ++at)
			item.width = std::min<int64_t>(item.width * 10 + (format[at] - u'0'), 1024);
	}
	if (at < format.size() && format[at] == u'.') {
		++at;
		item.precision = 0;
		if (at < format.size() && format[at] == u'*') {
			item.precision_argument = true;
			++at;
		} else {
			for (; at < format.size() && format[at] >= u'0' && format[at] <= u'9'; ++at)
				item.precision = std::min<int64_t>(item.precision * 10 + (format[at] - u'0'), 1024);
		}
	}
	for (; at < format.size(); ++at) {
		if (format[at] == u'l') item.wide_size = true;
		else if (format[at] == u'h') item.narrow_size = true;
		else break;
	}
	if (at >= format.size())
		return std::nullopt;
	const auto type = format[at++];
	if (type > 127 || std::string_view("cCdiuxXsS").find(char(type)) == std::string_view::npos)
		return std::nullopt;
	item.type = char(type);
	return item;
}

}

uint64_t NativeWindows::desktop_window()
{
	if (desktop && objects.window(desktop))
		return desktop;
	// The class needs a non-zero procedure to register; the window itself carries none and is answered by the system.
	DesktopClass definition{"#32769", 0, 1};
	const auto id = objects.register_class(std::move(definition));
	if (!id)
		throw uint32_t(8);
	const auto &screen = objects.nonclient_metrics();
	DesktopWindow record{id, 0, {}, 0, 0, screen.screen_x, screen.screen_y};
	record.style = 0x96000000;
	record.visible = true;
	desktop = objects.add(std::move(record));
	if (!desktop)
		throw uint32_t(8);
	return desktop;
}

bool NativeWindows::system_dispatch(std::string_view name)
{
	const bool format = name == "wsprintfW";
	if (name != "GetDesktopWindow" && name != "PtInRect" && name != "SetRect" && name != "TranslateAcceleratorW" && !format)
		return false;
	uint64_t result = 0;
	try {
		if (name == "GetDesktopWindow") {
			process.api_arguments(0);
			result = desktop_window();
		} else if (name == "PtInRect") {
			const auto args = process.api_arguments(3);
			const auto bytes = process.read_memory(args[0], 16);
			const auto left = int32_t(read_le(bytes, 0, 4)), top = int32_t(read_le(bytes, 4, 4));
			const auto right = int32_t(read_le(bytes, 8, 4)), bottom = int32_t(read_le(bytes, 12, 4));
			const auto x = int32_t(uint32_t(args[1])), y = int32_t(uint32_t(args[2]));
			result = x >= left && x < right && y >= top && y < bottom;
		} else if (name == "TranslateAcceleratorW") {
			const auto args = process.api_arguments(3);
			const auto *table = objects.accelerators(args[1]);
			if (!table || !objects.window(args[0]))
				throw uint32_t(1400);
			const bool narrow = process.mode() == NativeMode::x86;
			const auto bytes = process.read_memory(args[2], narrow ? 28 : 48);
			const auto message = uint32_t(read_le(bytes, narrow ? 4 : 8, 4));
			const auto wparam = read_le(bytes, narrow ? 8 : 16, narrow ? 4 : 8);
			const auto state = modifier_state();
			for (const auto &entry : *table) {
				const bool virtual_key = entry.flags & 1;
				bool match = false;
				if (virtual_key && (message == 0x100 || message == 0x104))
					match = wparam == entry.key && bool(entry.flags & 4) == state.shift && bool(entry.flags & 8) == state.control &&
						bool(entry.flags & 0x10) == state.alt;
				else if (!virtual_key && message == 0x102 && !state.alt)
					match = wparam == entry.key;
				if (match) {
					send(args[0], 0x111, uint64_t(entry.command) | (uint64_t(1) << 16), 0);
					result = 1;
					break;
				}
			}
		} else if (name == "SetRect") {
			const auto args = process.api_arguments(5);
			std::array<uint8_t, 16> bytes{};
			for (size_t index = 0; index < 4; ++index)
				write_le(bytes, index * 4, uint32_t(args[1 + index]), 4);
			process.write_memory(args[0], bytes);
			result = 1;
		} else {
			// cdecl variadic: count the consumed words from the format string before reading them off the stack.
			const auto head = process.api_arguments(2);
			const auto pattern = window_text(head[1]);
			size_t words = 0;
			for (size_t at = 0; at < pattern.size();) {
				if (pattern[at++] != u'%')
					continue;
				if (at < pattern.size() && pattern[at] == u'%') {
					++at;
					continue;
				}
				const auto item = parse_conversion(pattern, at);
				if (!item)
					break;
				words += 1 + item->width_argument + item->precision_argument;
			}
			if (words > 64)
				throw uint32_t(87);
			const auto args = process.api_arguments(2 + words);
			size_t next = 2;
			const auto take = [&] { return args[next++]; };
			std::u16string output;
			for (size_t at = 0; at < pattern.size();) {
				const auto c = pattern[at++];
				if (c != u'%') {
					output.push_back(c);
					continue;
				}
				if (at < pattern.size() && pattern[at] == u'%') {
					output.push_back(u'%');
					++at;
					continue;
				}
				auto item = parse_conversion(pattern, at);
				if (!item)
					break;
				if (item->width_argument) {
					const auto value = int32_t(uint32_t(take()));
					item->left |= value < 0;
					item->width = std::min<int64_t>(std::abs(int64_t(value)), 1024);
				}
				if (item->precision_argument) {
					const auto value = int32_t(uint32_t(take()));
					item->precision = value < 0 ? -1 : std::min<int64_t>(value, 1024);
				}
				const auto value = take();
				std::u16string body;
				if (item->type == 'c' || item->type == 'C') {
					body.push_back(char16_t(uint16_t(value)));
				} else if (item->type == 's' || item->type == 'S') {
					// %s takes the string width of the function (UTF-16); %S, %hs and %ls swap it.
					bool wide = item->type == 's';
					if (item->narrow_size) wide = false;
					if (item->wide_size) wide = true;
					if (!value) {
						body = u"(null)";
					} else {
						for (size_t index = 0; index < 4096; ++index) {
							const auto bytes = process.read_memory(value + index * (wide ? 2 : 1), wide ? 2 : 1);
							const char16_t character = wide ? char16_t(bytes[0] | bytes[1] << 8) : char16_t(bytes[0]);
							if (!character || (item->precision >= 0 && int64_t(index) >= item->precision))
								break;
							body.push_back(character);
						}
					}
				} else {
					const bool signed_type = item->type == 'd' || item->type == 'i';
					uint32_t raw = uint32_t(value);
					if (item->narrow_size)
						raw = signed_type ? uint32_t(int32_t(int16_t(raw))) : uint32_t(uint16_t(raw));
					const bool negative = signed_type && int32_t(raw) < 0;
					uint64_t magnitude = signed_type ? (negative ? uint64_t(-int64_t(int32_t(raw))) : raw) : raw;
					std::string digits;
					const bool hexadecimal = item->type == 'x' || item->type == 'X';
					do {
						const auto digit = unsigned(magnitude % (hexadecimal ? 16 : 10));
						digits.push_back(char((digit < 10 ? '0' : (item->type == 'X' ? 'A' : 'a') - 10) + digit));
						magnitude /= hexadecimal ? 16 : 10;
					} while (magnitude);
					while (item->precision >= 0 && int64_t(digits.size()) < item->precision)
						digits.push_back('0');
					std::string prefix;
					if (negative) prefix = "-";
					else if (signed_type && item->plus) prefix = "+";
					else if (signed_type && item->space) prefix = " ";
					if (hexadecimal && item->alternate && raw) prefix = item->type == 'X' ? "0X" : "0x";
					if (item->zero && !item->left && item->precision < 0)
						while (int64_t(prefix.size() + digits.size()) < item->width)
							digits.push_back('0');
					std::reverse(digits.begin(), digits.end());
					for (const char character : prefix + digits)
						body.push_back(char16_t(character));
				}
				while (int64_t(body.size()) < item->width)
					body.insert(item->left ? body.end() : body.begin(), u' ');
				output += body;
			}
			if (output.size() > 1023)
				output.resize(1023);
			std::vector<uint8_t> bytes((output.size() + 1) * 2);
			for (size_t index = 0; index < output.size(); ++index)
				write_le(bytes, index * 2, output[index], 2);
			process.write_memory(head[0], bytes);
			result = output.size();
		}
	} catch (uint32_t error) { environment.set_last_error(error); }
	catch (const std::runtime_error &failure) {
		const std::string_view message = failure.what();
		if (message.find("readable") == message.npos && message.find("writable") == message.npos) throw;
		environment.set_last_error(998);
		result = 0;
	}
	process.return_api(result);
	return true;
}

}
