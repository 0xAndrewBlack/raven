#include "registry.h"
#include "nls.h"

#include <fstream>
#include <stdexcept>

namespace raven {

namespace {

constexpr uint32_t file_not_found = 2, bad_handle = 6, invalid_parameter = 87, key_deleted = 1018;

bool predefined(uint64_t key)
{
	return key >= 0x80000000ULL && key <= 0x80000003ULL;
}

std::u16string fold(std::u16string_view text)
{
	std::u16string result(text);
	for (auto &character : result)
		if (character >= u'a' && character <= u'z')
			character = char16_t(character - (u'a' - u'A'));
	return result;
}

std::u16string decode_utf8(std::string_view text)
{
	std::u16string result;
	for (size_t index = 0; index < text.size();) {
		const auto lead = static_cast<unsigned char>(text[index]);
		const size_t extra = lead < 0x80 ? 0 : lead < 0xe0 ? 1 : lead < 0xf0 ? 2 : 3;
		if (extra && index + extra >= text.size())
			throw std::runtime_error("registry hive contains truncated UTF-8");
		uint32_t value = extra == 0 ? lead : lead & (0x3fU >> extra);
		for (size_t part = 1; part <= extra; ++part)
			value = (value << 6) | (static_cast<unsigned char>(text[index + part]) & 0x3fU);
		index += extra + 1;
		if (value >= 0x10000) {
			value -= 0x10000;
			result.push_back(char16_t(0xd800 + (value >> 10)));
			result.push_back(char16_t(0xdc00 + (value & 0x3ff)));
		} else {
			result.push_back(char16_t(value));
		}
	}
	return result;
}

std::string hex(std::span<const uint8_t> bytes)
{
	static constexpr char digits[] = "0123456789abcdef";
	std::string result;
	for (const auto byte : bytes) {
		result.push_back(digits[byte >> 4]);
		result.push_back(digits[byte & 15]);
	}
	return result;
}

std::vector<uint8_t> unhex(std::string_view text)
{
	if (text.size() % 2)
		throw std::runtime_error("registry hive contains odd hexadecimal data");
	const auto nibble = [](char c) -> uint8_t {
		if (c >= '0' && c <= '9') return uint8_t(c - '0');
		if (c >= 'a' && c <= 'f') return uint8_t(c - 'a' + 10);
		throw std::runtime_error("registry hive contains invalid hexadecimal data");
	};
	std::vector<uint8_t> result;
	for (size_t index = 0; index < text.size(); index += 2)
		result.push_back(uint8_t(nibble(text[index]) << 4 | nibble(text[index + 1])));
	return result;
}

std::string escape(std::u16string_view text)
{
	std::string result;
	for (const char character : encode_utf8(text)) {
		if (character == '\\' || character == '\t' || character == '\n' || character == '\r') {
			result.push_back('\\');
			result.push_back(character == '\\' ? '\\' : character == '\t' ? 't' : character == '\n' ? 'n' : 'r');
		} else {
			result.push_back(character);
		}
	}
	return result;
}

std::string unescape(std::string_view text)
{
	std::string result;
	for (size_t index = 0; index < text.size(); ++index) {
		if (text[index] != '\\') {
			result.push_back(text[index]);
			continue;
		}
		if (++index >= text.size())
			throw std::runtime_error("registry hive ends inside an escape");
		result.push_back(text[index] == 't' ? '\t' : text[index] == 'n' ? '\n' : text[index] == 'r' ? '\r' : text[index]);
	}
	return result;
}

}

NativeRegistry::NativeRegistry(std::filesystem::path file) : file(std::move(file))
{
	load();
}

bool NativeRegistry::resolve(uint64_t parent, std::u16string_view path, std::u16string &folded, std::u16string &display) const
{
	std::u16string base;
	std::u16string shown;
	if (predefined(parent)) {
		static const char16_t *const names[] = {u"HKEY_CLASSES_ROOT", u"HKEY_CURRENT_USER", u"HKEY_LOCAL_MACHINE", u"HKEY_USERS"};
		shown = names[parent - 0x80000000ULL];
		base = fold(shown);
	} else {
		const auto found = open_keys.find(parent);
		if (found == open_keys.end())
			return false;
		base = found->second;
		shown = keys.at(base).path;
	}
	std::u16string tail(path);
	while (!tail.empty() && tail.front() == u'\\')
		tail.erase(0, 1);
	while (!tail.empty() && tail.back() == u'\\')
		tail.pop_back();
	display = shown;
	folded = base;
	if (!tail.empty()) {
		display += u'\\';
		display += tail;
		folded += u'\\';
		folded += fold(tail);
	}
	return true;
}

uint32_t NativeRegistry::create(uint64_t parent, std::u16string_view path, uint64_t &key, uint32_t &disposition)
{
	std::u16string folded, display;
	if (!resolve(parent, path, folded, display))
		return bad_handle;
	if (display.find(u"\\\\") != display.npos)
		return invalid_parameter;
	if (next > UINT32_MAX - 4 || open_keys.size() >= 10000)
		return 8;
	disposition = 2;
	// Every ancestor exists once a key does, so enumeration of parents stays consistent.
	size_t end = 0;
	while (end != folded.npos) {
		end = folded.find(u'\\', end + 1);
		const auto partial = folded.substr(0, end);
		if (!keys.contains(partial)) {
			keys.emplace(partial, Key{display.substr(0, end), {}});
			if (partial == folded)
				disposition = 1;
		}
	}
	key = next;
	next += 4;
	open_keys.emplace(key, folded);
	save();
	return 0;
}

uint32_t NativeRegistry::open(uint64_t parent, std::u16string_view path, uint64_t &key)
{
	std::u16string folded, display;
	if (!resolve(parent, path, folded, display))
		return bad_handle;
	if (!keys.contains(folded))
		return file_not_found;
	if (next > UINT32_MAX - 4 || open_keys.size() >= 10000)
		return 8;
	key = next;
	next += 4;
	open_keys.emplace(key, folded);
	return 0;
}

uint32_t NativeRegistry::close(uint64_t key)
{
	if (predefined(key))
		return 0;
	return open_keys.erase(key) ? 0 : bad_handle;
}

uint32_t NativeRegistry::query(uint64_t key, std::u16string_view name, uint32_t &type, std::vector<uint8_t> &data) const
{
	const auto found = open_keys.find(key);
	if (found == open_keys.end())
		return predefined(key) ? file_not_found : bad_handle;
	const auto &values = keys.at(found->second).values;
	const auto value = values.find(fold(name));
	if (value == values.end())
		return file_not_found;
	type = value->second.type;
	data = value->second.data;
	return 0;
}

uint32_t NativeRegistry::set(uint64_t key, std::u16string_view name, uint32_t type, std::span<const uint8_t> data)
{
	const auto found = open_keys.find(key);
	if (found == open_keys.end())
		return predefined(key) ? 5 : bad_handle;
	if (!keys.contains(found->second))
		return key_deleted;
	if (data.size() > 1024 * 1024)
		return 234;
	keys.at(found->second).values[fold(name)] = Value{std::u16string(name), type, std::vector<uint8_t>(data.begin(), data.end())};
	save();
	return 0;
}

void NativeRegistry::save() const
{
	if (file.empty())
		return;
	auto temporary = file;
	temporary += ".tmp";
	{
		std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
		if (!output)
			throw std::runtime_error("cannot write the registry hive");
		for (const auto &[folded, key] : keys) {
			output << "K\t" << escape(key.path) << '\n';
			for (const auto &[value_folded, value] : key.values)
				output << "V\t" << escape(key.path) << '\t' << escape(value.name) << '\t' << value.type << '\t' << hex(value.data) << '\n';
		}
		output.flush();
		if (!output)
			throw std::runtime_error("cannot write the registry hive");
	}
	std::filesystem::rename(temporary, file);
}

void NativeRegistry::load()
{
	if (file.empty() || !std::filesystem::exists(file))
		return;
	std::ifstream input(file, std::ios::binary);
	std::string line;
	while (std::getline(input, line)) {
		std::vector<std::string> fields;
		size_t start = 0;
		for (size_t tab; (tab = line.find('\t', start)) != line.npos; start = tab + 1)
			fields.push_back(line.substr(start, tab - start));
		fields.push_back(line.substr(start));
		if (fields[0] == "K" && fields.size() == 2) {
			const auto path = decode_utf8(unescape(fields[1]));
			keys.emplace(fold(path), Key{path, {}});
		} else if (fields[0] == "V" && fields.size() == 5) {
			const auto path = decode_utf8(unescape(fields[1]));
			const auto name = decode_utf8(unescape(fields[2]));
			const auto found = keys.find(fold(path));
			if (found == keys.end())
				throw std::runtime_error("registry hive value precedes its key");
			found->second.values[fold(name)] = Value{name, uint32_t(std::stoul(fields[3])), unhex(fields[4])};
		} else if (!line.empty()) {
			throw std::runtime_error("registry hive contains an unknown record");
		}
	}
}

}
