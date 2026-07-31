#include "profile_api.h"
#include "nls.h"

#include <fstream>
#include <stdexcept>

namespace raven {

namespace {

std::u16string fold(std::u16string_view value)
{
	std::u16string result(value);
	for (auto &character : result)
		if (character >= u'a' && character <= u'z')
			character = char16_t(character - (u'a' - u'A'));
	return result;
}

std::u16string widen(std::string_view value)
{
	std::u16string result;
	for (const char character : value)
		result.push_back(char16_t(static_cast<unsigned char>(character)));
	return result;
}

std::u16string trim(std::u16string value)
{
	while (!value.empty() && (value.front() == u' ' || value.front() == u'\t'))
		value.erase(0, 1);
	while (!value.empty() && (value.back() == u' ' || value.back() == u'\t' || value.back() == u'\r'))
		value.pop_back();
	return value;
}

// First matching value, or nullopt when the file, section or key is absent.
std::optional<std::u16string> lookup(const std::filesystem::path &file, std::u16string_view section, std::u16string_view key)
{
	std::ifstream input(file, std::ios::binary);
	if (!input)
		return std::nullopt;
	const auto wanted_section = fold(section), wanted_key = fold(key);
	bool inside = false;
	std::string line;
	while (std::getline(input, line)) {
		const auto text = trim(widen(line));
		if (text.empty() || text[0] == u';')
			continue;
		if (text[0] == u'[') {
			const auto close = text.find(u']');
			inside = close != text.npos && fold(trim(text.substr(1, close - 1))) == wanted_section;
			continue;
		}
		const auto equals = text.find(u'=');
		if (inside && equals != text.npos && fold(trim(text.substr(0, equals))) == wanted_key) {
			auto value = trim(text.substr(equals + 1));
			if (value.size() >= 2 && value.front() == value.back() && (value.front() == u'"' || value.front() == u'\''))
				value = value.substr(1, value.size() - 2);
			return value;
		}
	}
	return std::nullopt;
}


std::vector<std::u16string> section_names(const std::filesystem::path &file)
{
	std::vector<std::u16string> names;
	std::ifstream input(file, std::ios::binary);
	std::string line;
	while (input && std::getline(input, line)) {
		const auto text = trim(widen(line));
		if (text.empty() || text[0] != u'[')
			continue;
		if (const auto close = text.find(u']'); close != text.npos)
			names.push_back(trim(text.substr(1, close - 1)));
	}
	return names;
}

}

NativeProfile::NativeProfile(NativeProcess &process, NativeEnvironment &environment, const NativePrefix &prefix)
	: process(process), environment(environment), prefix(prefix) {}

std::optional<std::u16string> NativeProfile::text(uint64_t address) const
{
	if (!address)
		return std::nullopt;
	std::u16string result;
	for (size_t index = 0; index < 32768; ++index) {
		const auto bytes = process.read_memory(address + index * 2, 2);
		const char16_t character = char16_t(bytes[0] | bytes[1] << 8);
		if (!character)
			return result;
		result.push_back(character);
	}
	throw std::runtime_error("native profile string exceeds policy limit");
}

bool NativeProfile::execute(std::string_view name, const std::vector<uint64_t> &args, uint64_t &result)
{
	if (name == "GetPrivateProfileSectionNamesW") {
		std::u16string joined;
		if (const auto file_name = text(args[2]))
			if (const auto path = prefix.resolve(encode_utf8(*file_name)))
				for (const auto &entry : section_names(*path))
					joined += entry + u'\0';
		const size_t capacity = uint32_t(args[1]);
		result = 0;
		if (capacity >= 2) {
			// A buffer that is too small is filled and ends in two terminators.
			const bool fits = joined.size() + 1 <= capacity;
			if (!fits)
				joined.resize(capacity - 2);
			joined.push_back(u'\0');
			if (!fits)
				joined.push_back(u'\0');
			std::vector<uint8_t> bytes;
			for (const auto character : joined) {
				bytes.push_back(uint8_t(character));
				bytes.push_back(uint8_t(character >> 8));
			}
			process.write_memory(args[0], bytes);
			result = fits ? (joined.empty() ? 0 : joined.size() - 1) : capacity - 2;
		}
		return true;
	}
	const bool integer = name == "GetPrivateProfileIntW";
	if (!integer && name != "GetPrivateProfileStringW")
		return false;
	result = 0;
	try {
		const auto section = text(args[0]), key = text(args[1]), file_name = text(integer ? args[3] : args[5]);
		std::optional<std::u16string> value;
		if (section && key && file_name)
			if (const auto path = prefix.resolve(encode_utf8(*file_name)))
				value = lookup(*path, *section, *key);
		if (integer) {
			result = uint32_t(args[2]);
			if (value) {
				// Decimal digits with an optional sign; parsing stops at the first other character.
				size_t at = 0;
				const bool negative = !value->empty() && (*value)[0] == u'-';
				if (negative)
					++at;
				int64_t number = 0;
				for (; at < value->size() && (*value)[at] >= u'0' && (*value)[at] <= u'9'; ++at)
					number = std::min<int64_t>(number * 10 + ((*value)[at] - u'0'), 0xffffffffLL);
				result = uint32_t(negative ? -number : number);
			}
		} else {
			const auto fallback = text(args[2]).value_or(std::u16string{});
			const auto &chosen = value ? *value : fallback;
			const size_t capacity = uint32_t(args[4]);
			if (capacity) {
				const auto length = std::min(chosen.size(), capacity - 1);
				std::vector<uint8_t> bytes((length + 1) * 2);
				for (size_t index = 0; index < length; ++index) {
					bytes[index * 2] = uint8_t(chosen[index]);
					bytes[index * 2 + 1] = uint8_t(chosen[index] >> 8);
				}
				process.write_memory(args[3], bytes);
				result = length;
			}
		}
	} catch (const std::runtime_error &failure) {
		const std::string_view message = failure.what();
		if (message.find("readable") == message.npos && message.find("writable") == message.npos)
			throw;
		environment.set_last_error(998);
		result = 0;
	}
	return true;
}

bool NativeProfile::dispatch(std::string_view name)
{
	const uint32_t count = name == "GetPrivateProfileSectionNamesW" ? 3 : name == "GetPrivateProfileIntW" ? 4 : 6;
	if (name != "GetPrivateProfileSectionNamesW" && name != "GetPrivateProfileIntW" && name != "GetPrivateProfileStringW")
		return false;
	uint64_t result = 0;
	execute(name, process.api_arguments(count), result);
	process.return_api(result);
	return true;
}

void register_profile_api(ApiRegistry &registry, NativeProfile &profile)
{
	registry.add("GetPrivateProfileSectionNamesW", 3, [&profile](ApiCall &call) {
		uint64_t result = 0;
		profile.execute("GetPrivateProfileSectionNamesW", {call[0], call[1], call[2]}, result);
		call.ret(result);
	});
	registry.add("GetPrivateProfileIntW", 4, [&profile](ApiCall &call) {
		uint64_t result = 0;
		profile.execute("GetPrivateProfileIntW", {call[0], call[1], call[2], call[3]}, result);
		call.ret(result);
	});
	registry.add("GetPrivateProfileStringW", 6, [&profile](ApiCall &call) {
		uint64_t result = 0;
		profile.execute("GetPrivateProfileStringW", {call[0], call[1], call[2], call[3], call[4], call[5]}, result);
		call.ret(result);
	});
}

}
