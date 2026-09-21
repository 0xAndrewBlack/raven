#include "kernel_context.h"
#include "nls.h"
#include "text.h"
#include "pe/resources.h"

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <functional>
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
	// Standard English wording of the system message table; every entry ends with the CR LF Windows appends.
	static const std::map<uint32_t, const char16_t *> messages{
		{0, u"The operation completed successfully."}, {1, u"Incorrect function."}, {2, u"The system cannot find the file specified."},
		{3, u"The system cannot find the path specified."}, {4, u"The system cannot open the file."}, {5, u"Access is denied."},
		{6, u"The handle is invalid."}, {7, u"The storage control blocks were destroyed."}, {8, u"Not enough memory resources are available to process this command."},
		{9, u"The storage control block address is invalid."}, {10, u"The environment is incorrect."}, {11, u"An attempt was made to load a program with an incorrect format."},
		{12, u"The access code is invalid."}, {13, u"The data is invalid."}, {14, u"Not enough memory resources are available to complete this operation."},
		{15, u"The system cannot find the drive specified."}, {16, u"The directory cannot be removed."}, {17, u"The system cannot move the file to a different disk drive."},
		{18, u"There are no more files."}, {19, u"The media is write protected."}, {20, u"The system cannot find the device specified."},
		{21, u"The device is not ready."}, {22, u"The device does not recognize the command."}, {23, u"Data error (cyclic redundancy check)."},
		{24, u"The program issued a command but the command length is incorrect."}, {25, u"The drive cannot locate a specific area or track on the disk."},
		{26, u"The specified disk or diskette cannot be accessed."}, {27, u"The drive cannot find the sector requested."}, {28, u"The printer is out of paper."},
		{29, u"The system cannot write to the specified device."}, {30, u"The system cannot read from the specified device."}, {31, u"A device attached to the system is not functioning."},
		{32, u"The process cannot access the file because it is being used by another process."},
		{33, u"The process cannot access the file because another process has locked a portion of the file."},
		{36, u"Too many files opened for sharing."}, {38, u"Reached the end of the file."}, {39, u"The disk is full."},
		{50, u"The request is not supported."}, {51, u"Windows cannot find the network path. Verify that the network path is correct and the destination computer is not busy or turned off."},
		{53, u"The network path was not found."}, {54, u"The network is busy."}, {55, u"The specified network resource or device is no longer available."},
		{65, u"Network access is denied."}, {67, u"The network name cannot be found."}, {80, u"The file exists."}, {82, u"The directory or file cannot be created."},
		{86, u"The specified network password is not correct."}, {87, u"The parameter is incorrect."}, {88, u"A write fault occurred on the network."},
		{109, u"The pipe has been ended."}, {110, u"The system cannot open the device or file specified."}, {111, u"The file name is too long."},
		{112, u"There is not enough space on the disk."}, {120, u"This function is not supported on this system."}, {122, u"The data area passed to a system call is too small."},
		{123, u"The filename, directory name, or volume label syntax is incorrect."}, {126, u"The specified module could not be found."},
		{127, u"The specified procedure could not be found."}, {129, u"%1 is not a valid Win32 application."}, {131, u"An attempt was made to move the file pointer before the beginning of the file."},
		{145, u"The directory is not empty."}, {161, u"The specified path is invalid."}, {170, u"The requested resource is in use."}, {175, u"The specified device does not exist."},
		{183, u"Cannot create a file when that file already exists."}, {193, u"%1 is not a valid Win32 application."}, {203, u"The system could not find the environment option that was entered."},
		{206, u"The filename or extension is too long."}, {234, u"More data is available."}, {258, u"The wait operation timed out."}, {259, u"No more data is available."},
		{267, u"The directory name is invalid."}, {287, u"The specified file is not a reparse point."}, {288, u"Attempt to release mutex not owned by caller."},
		{298, u"Too many posts were made to a semaphore."}, {299, u"Only part of a ReadProcessMemory or WriteProcessMemory request was completed."},
		{317, u"The system cannot find message text for message number 0x%1 in the message file for %2."}, {487, u"Attempt to access invalid address."},
		{534, u"Arithmetic result exceeded 32 bits."}, {535, u"There is a process on other end of the pipe."}, {536, u"Waiting for a process to open the other end of the pipe."},
		{740, u"The requested operation requires elevation."}, {995, u"The I/O operation has been aborted because of either a thread exit or an application request."},
		{996, u"Overlapped I/O event is not in a signaled state."}, {997, u"Overlapped I/O operation is in progress."}, {998, u"Invalid access to memory location."},
		{1004, u"Invalid flags."}, {1008, u"An attempt was made to reference a token that does not exist."}, {1010, u"The configuration registry key is invalid."},
		{1018, u"Illegal operation attempted on a registry key that has been marked for deletion."}, {1060, u"The specified service does not exist as an installed service."},
		{1150, u"The specified program requires a newer version of Windows."}, {1168, u"Element not found."}, {1223, u"The operation was canceled by the user."},
		{1235, u"The request was aborted."}, {1314, u"A required privilege is not held by the client."}, {1400, u"Invalid window handle."}, {1401, u"Invalid menu handle."},
		{1402, u"Invalid cursor handle."}, {1403, u"Invalid accelerator table handle."}, {1404, u"Invalid hook handle."}, {1405, u"Invalid handle to a multiple-window position structure."},
		{1406, u"Cannot create a top-level child window."}, {1407, u"Cannot find window class."}, {1408, u"Invalid window; it belongs to other thread."},
		{1409, u"Hot key is already registered."}, {1410, u"Class already exists."}, {1411, u"Class does not exist."}, {1412, u"Class still has open windows."},
		{1413, u"Invalid index."}, {1414, u"Invalid icon handle."}, {1415, u"Using private DIALOG window words."}, {1416, u"The list box identifier was not found."},
		{1417, u"No wildcards were found."}, {1418, u"Thread does not have a clipboard open."}, {1419, u"Hot key is not registered."}, {1420, u"The window is not a valid dialog window."},
		{1421, u"Control ID not found."}, {1422, u"Invalid message for a combo box because it does not have an edit control."}, {1423, u"The window is not a combo box."},
		{1424, u"Height must be less than 256."}, {1425, u"Invalid device context (DC) handle."}, {1426, u"Invalid hook procedure type."}, {1427, u"Invalid hook procedure."},
		{1428, u"Cannot set nonlocal hook without a module handle."}, {1429, u"This hook procedure can only be set globally."}, {1430, u"The journal hook procedure is already installed."},
		{1431, u"The hook procedure is not installed."}, {1432, u"Invalid message for single-selection list box."}, {1433, u"LB_SETCOUNT sent to non-lazy list box."},
		{1434, u"This list box does not support tab stops."}, {1435, u"Cannot destroy object created by another thread."}, {1436, u"Child windows cannot have menus."},
		{1437, u"The window does not have a system menu."}, {1438, u"Invalid message box style."}, {1439, u"Invalid system-wide (SPI_*) parameter."},
		{1440, u"Screen already locked."}, {1441, u"All handles to windows in a multiple-window position structure must have the same parent."},
		{1442, u"The window is not a child window."}, {1443, u"Invalid GW_* command."}, {1444, u"Invalid thread identifier."},
		{1445, u"Cannot process a message from a window that is not a multiple document interface (MDI) window."}, {1446, u"Popup menu already active."},
		{1447, u"The window does not have scroll bars."}, {1448, u"Scroll bar range cannot be greater than MAXLONG."}, {1449, u"Cannot show or remove the window in the way specified."},
		{1450, u"Insufficient system resources exist to complete the requested service."}, {1460, u"This operation returned because the timeout period expired."},
		{1627, u"Function failed during execution."}, {1629, u"Data of this type is not supported."}, {1813, u"The specified resource type cannot be found in the image file."},
		{1814, u"The specified resource name cannot be found in the image file."}, {1815, u"The specified resource language ID cannot be found in the image file."},
		{1816, u"Not enough quota is available to process this command."}, {2250, u"The network connection does not exist."}, {5023, u"The group or resource is not in the correct state to perform the requested operation."},
		{0x80004001U, u"Not implemented"}, {0x80004002U, u"No such interface supported"}, {0x80004003U, u"Invalid pointer"}, {0x80004004U, u"Operation aborted"},
		{0x80004005U, u"Unspecified error"}, {0x8000ffffU, u"Catastrophic failure"}, {0x8007000eU, u"Not enough memory resources are available to complete this operation."},
		{0x80070005U, u"Access is denied."}, {0x80070006U, u"The handle is invalid."}, {0x80070057U, u"The parameter is incorrect."},
		{0x80040154U, u"Class not registered"}, {0x800401f3U, u"Invalid class string"}, {0x800b0100U, u"No signature was present in the subject."},
		{0x80092004U, u"Cannot find object or property."}, {0x80092009U, u"Cannot find the requested object."}, {0x80091004U, u"Invalid cryptographic message type."},
		{0x80090008U, u"The parameter is incorrect."}, {0x80090016U, u"Keyset does not exist"},
	};
	const auto found = messages.find(id);
	if (found == messages.end())
		return std::nullopt;
	return std::u16string(found->second) + u"\r\n";
}

// Replaces %1..%99 (with optional !printf! formats), %n, %r, %t, %% and %0 in a message template.
// The inserts of a message: %1 to %99, each with an optional printf format between exclamation marks, which `argument` turns into
// text; and the escapes %n, %r, %t, %0 and a doubled character.
std::u16string insert_arguments(std::u16string_view text, const std::function<std::u16string(unsigned, std::u16string_view)> &argument)
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
			std::u16string_view format;
			if (end < text.size() && text[end] == u'!') {
				const auto close = text.find(u'!', end + 1);
				if (close != text.npos) {
					format = text.substr(end + 1, close - end - 1);
					end = close + 1;
				}
			}
			if (index >= 1 && index <= 99)
				result += argument(index, format);
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

// The text of message `id` in a module's message table, the RT_MESSAGETABLE resource named 1: blocks of consecutive identifiers, each
// pointing at entries that carry their length and whether they are UTF-16. The language asked for is preferred, any other serves.
std::optional<std::u16string> module_message(KernelContext &context, uint64_t base, uint32_t id, uint32_t language)
{
	const PEModule *image = !base || base == context.entry.loaded.base() ? &context.entry : nullptr;
	for (auto found = context.modules.all().begin(); !image && found != context.modules.all().end(); ++found)
		if (found->second->loaded.base() == base)
			image = found->second.get();
	if (!image || image->runtime_api)
		return std::nullopt;
	const auto directory = image->image.directories[2];
	if (!directory.address || !directory.size || directory.size > 16 * 1024 * 1024)
		return std::nullopt;
	const auto resources = read_resources(directory, context.process.read_memory(image->loaded.base() + directory.address, directory.size),
		image->image.image_size);
	const PEResource *table = nullptr;
	for (const auto &resource : resources)
		if (resource.type == ResourceKey(uint32_t(11)) && resource.name == ResourceKey(uint32_t(1)) &&
			(!table || (language && resource.language == language)))
			table = &resource;
	if (!table || table->size < 4)
		return std::nullopt;
	const auto data = context.process.read_memory(image->loaded.base() + table->data_address, table->size);
	const auto word = [&](size_t at) -> uint32_t {
		if (at + 4 > data.size())
			return 0;
		return uint32_t(data[at]) | uint32_t(data[at + 1]) << 8 | uint32_t(data[at + 2]) << 16 | uint32_t(data[at + 3]) << 24;
	};
	const uint32_t blocks = word(0);
	for (uint32_t block = 0; block < blocks && 4 + size_t(block + 1) * 12 <= data.size(); ++block) {
		const uint32_t low = word(4 + block * 12), high = word(8 + block * 12);
		if (id < low || id > high)
			continue;
		size_t at = word(12 + block * 12);
		for (uint32_t skip = low; skip < id && at + 4 <= data.size(); ++skip)
			at += uint16_t(word(at));
		if (at + 4 > data.size())
			return std::nullopt;
		const size_t length = uint16_t(word(at)), flags = uint16_t(word(at) >> 16);
		if (length < 4 || at + length > data.size())
			return std::nullopt;
		std::u16string text;
		if (flags & 1) {
			for (size_t offset = at + 4; offset + 1 < at + length; offset += 2)
				text.push_back(char16_t(data[offset] | data[offset + 1] << 8));
		} else {
			text = decode_ansi(std::string_view(reinterpret_cast<const char *>(data.data() + at + 4), length - 4), 0);
		}
		while (!text.empty() && !text.back())
			text.pop_back();
		return text;
	}
	return std::nullopt;
}

}

std::vector<uint8_t> locale_table()
{
	std::vector<uint8_t> table(locale_table_entries * 8, 0xff);
	std::u16string pool;
	for (uint32_t index = 0; index < locale_table_entries; ++index) {
		const auto text = locale_text(index < 0x80 ? index : 0x1000 + index - 0x80);
		if (!text)
			continue;
		const uint16_t offset = uint16_t(pool.size()), length = uint16_t(text->size());
		const uint32_t number = as_number(*text);
		std::memcpy(table.data() + index * 8, &offset, 2);
		std::memcpy(table.data() + index * 8 + 2, &length, 2);
		std::memcpy(table.data() + index * 8 + 4, &number, 4);
		pool += *text;
		pool += u'\0';
	}
	const size_t start = table.size();
	table.resize(start + pool.size() * 2);
	std::memcpy(table.data() + start, pool.data(), pool.size() * 2);
	return table;
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
	// Code unit by code unit, optionally after upper-casing both, as file systems and the registry compare names.
	registry.add("CompareStringOrdinal", 5, [](ApiCall &call) {
		if (!call[0] || !call[2]) {
			call.fail(87);
			return;
		}
		auto left = counted_wide(call, call[0], call.i32(1)), right = counted_wide(call, call[2], call.i32(3));
		if (call.u32(4)) {
			for (auto &character : left)
				character = upper_case(character);
			for (auto &character : right)
				character = upper_case(character);
		}
		call.ret(left < right ? 1 : left == right ? 2 : 3);
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
	// The character classes of a text for CT_CTYPE1, CT_CTYPE2 and CT_CTYPE3.
	const auto classify = [](uint32_t kind, const std::u16string &text) {
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
		return bytes;
	};
	// GetStringTypeW(kind, text, count, types): four arguments.
	registry.add("GetStringTypeW", 4, [classify](ApiCall &call) {
		const uint32_t kind = call.u32(0);
		if (!call[1] || !call[3] || (kind != 1 && kind != 2 && kind != 4)) {
			call.fail(87);
			return;
		}
		call.write(call[3], classify(kind, counted_wide(call, call[1], call.i32(2))));
		call.ret(1);
	});
	// GetStringTypeExW(locale, kind, text, count, types) and GetStringTypeA(locale, kind, text, count, types): five.
	registry.add("GetStringTypeExW", 5, [classify](ApiCall &call) {
		const uint32_t kind = call.u32(1);
		if (!call[2] || !call[4] || (kind != 1 && kind != 2 && kind != 4)) {
			call.fail(87);
			return;
		}
		call.write(call[4], classify(kind, counted_wide(call, call[2], call.i32(3))));
		call.ret(1);
	});
	registry.add("GetStringTypeA", 5, [classify, ansi_page](ApiCall &call) {
		const uint32_t kind = call.u32(1);
		if (!call[2] || !call[4] || (kind != 1 && kind != 2 && kind != 4)) {
			call.fail(87);
			return;
		}
		const auto text = decode_ansi(counted_narrow(call, call[2], call.i32(3)), ansi_page(call.u32(0)));
		call.write(call[4], classify(kind, text));
		call.ret(1);
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
	registry.add("GetUserDefaultUILanguage", 0, [](ApiCall &call) { call.ret(0x409); });
	registry.add("GetSystemDefaultUILanguage", 0, [](ApiCall &call) { call.ret(0x409); });
	registry.add("GetThreadUILanguage", 0, [](ApiCall &call) { call.ret(0x409); });
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
			// The capacity counts characters: two wide ones hold the number.
			if (capacity < (wide ? 2 : 4)) {
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

	// The message comes from the text given, a module's message table or the system's; its inserts from an array of arguments or from the
	// caller's va_list, one pointer-wide slot each.
	const auto format_message = [&](ApiCall &call, bool wide) {
		const uint32_t flags = call.u32(0);
		std::optional<std::u16string> text;
		if (flags & 0x400)
			text = wide ? call.wide(call[1]) : decode_ansi(call.narrow(call[1]), 0);
		else {
			if (flags & 0x800)
				text = module_message(context, call[1], call.u32(2), call.u32(3));
			if (!text && (flags & 0x1000))
				text = system_message(call.u32(2));
			if (!text && !(flags & 0x1800)) {
				call.fail(87);
				return;
			}
			if (!text) {
				call.fail(317);
				return;
			}
		}
		if (!(flags & 0x200)) {
			const size_t width = call.pointer_width();
			uint64_t arguments = 0;
			if (call[6])
				arguments = flags & 0x2000 ? call[6] : call.load_pointer(call[6]);
			text = insert_arguments(*text, [&](unsigned index, std::u16string_view format) -> std::u16string {
				if (!arguments)
					return u"";
				uint64_t value = 0;
				try {
					value = width == 4 ? call.load<uint32_t>(arguments + (index - 1) * 4) : call.load<uint64_t>(arguments + (index - 1) * 8);
				} catch (const ApiFault &) {
					return u"";
				}
				const char16_t kind = format.empty() ? u's' : format.back();
				if (kind == u's' || kind == u'S') {
					// A string is wide in the wide call unless the format says h; S swaps the width.
					const bool narrow = format.find(u'h') != format.npos || (format.find(u'l') == format.npos && (wide == (kind == u'S')));
					if (!value)
						return u"(null)";
					try {
						return narrow ? decode_ansi(call.narrow(value, 32768), 0) : call.wide(value, 32768);
					} catch (const ApiFault &) {
						return u"";
					}
				}
				if (kind == u'c' || kind == u'C')
					return std::u16string(1, char16_t(value));
				char digits[32];
				const auto spec = to_utf8(std::u16string(format));
				const bool large = spec.find("I64") != spec.npos || spec.find("ll") != spec.npos;
				std::string pattern = "%";
				pattern += spec.substr(0, spec.size() - 1);
				for (const char *size : {"I64", "ll", "l", "h", "I32"})
					if (const auto found = pattern.find(size); found != pattern.npos)
						pattern.erase(found, std::strlen(size));
				pattern += large ? "ll" : "";
				pattern += char(kind);
				if (large)
					std::snprintf(digits, sizeof digits, pattern.c_str(), (unsigned long long)value);
				else if (kind == u'd' || kind == u'i')
					std::snprintf(digits, sizeof digits, pattern.c_str(), int32_t(value));
				else
					std::snprintf(digits, sizeof digits, pattern.c_str(), uint32_t(value));
				return widen_ascii(digits);
			});
		}
		if (wide) {
			if (flags & 0x100) {
				const auto address = context.allocator.allocate((text->size() + 1) * 2, false);
				if (!address) {
					call.fail(8);
					return;
				}
				call.put_wide(address, *text, text->size() + 1);
				call.store_pointer(call[4], address);
				call.ret(text->size());
				return;
			}
			if (call.u32(5) <= text->size()) {
				call.fail(122);
				return;
			}
			call.put_wide(call[4], *text, call.u32(5));
			call.ret(text->size());
			return;
		}
		const auto narrow = to_utf8(*text);
		if (flags & 0x100) {
			const auto address = context.allocator.allocate(narrow.size() + 1, false);
			if (!address) {
				call.fail(8);
				return;
			}
			call.put_narrow(address, narrow, narrow.size() + 1);
			call.store_pointer(call[4], address);
			call.ret(narrow.size());
			return;
		}
		if (call.u32(5) <= narrow.size()) {
			call.fail(122);
			return;
		}
		call.put_narrow(call[4], narrow, call.u32(5));
		call.ret(narrow.size());
	};
	registry.add("FormatMessageW", 7, [format_message](ApiCall &call) { format_message(call, true); });
	registry.add("FormatMessageA", 7, [format_message](ApiCall &call) { format_message(call, false); });
}

}
