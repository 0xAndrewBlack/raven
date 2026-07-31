#include "advapi_api.h"
#include "nls.h"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace raven {

namespace {

constexpr uint32_t invalid_parameter = 87, more_data = 234, no_access = 998;

constexpr std::array<std::string_view, 6> names{"RegCloseKey", "RegCreateKeyExW", "RegOpenKeyExA", "RegQueryValueExA",
	"RegQueryValueExW", "RegSetValueExW"};

bool is_text(uint32_t type)
{
	return type == 1 || type == 2 || type == 7;
}

}

NativeAdvapi::NativeAdvapi(NativeProcess &process, NativeEnvironment &environment, NativeRegistry &registry)
	: process(process), environment(environment), registry(registry) {}

std::span<const std::string_view> NativeAdvapi::exports()
{
	return names;
}

uint32_t NativeAdvapi::argument_count(std::string_view name)
{
	if (name == "RegCloseKey") return 1;
	if (name == "RegCreateKeyExW") return 9;
	if (name == "RegOpenKeyExA") return 5;
	return 6;
}

std::optional<std::u16string> NativeAdvapi::guest_string(uint64_t address, bool wide, uint32_t &error) const
{
	std::u16string result;
	if (!address)
		return result;
	const size_t width = wide ? 2 : 1;
	for (size_t index = 0; index < 32768; ++index) {
		const auto bytes = process.read_memory(address + index * width, width);
		const uint32_t character = uint32_t(bytes[0]) | (wide ? uint32_t(bytes[1]) << 8 : 0);
		if (!character)
			return result;
		if (!wide && character > 127) {
			error = invalid_parameter;
			return std::nullopt;
		}
		result.push_back(char16_t(character));
	}
	error = 123;
	return std::nullopt;
}

void NativeAdvapi::write_value(uint64_t address, uint64_t value, size_t width)
{
	std::vector<uint8_t> bytes(width);
	for (size_t index = 0; index < width; ++index)
		bytes[index] = uint8_t(value >> (index * 8));
	process.write_memory(address, bytes);
}

bool NativeAdvapi::dispatch(std::string_view name)
{
	if (std::find(names.begin(), names.end(), name) == names.end())
		return false;
	const auto args = process.api_arguments(argument_count(name));
	const size_t handle_width = process.mode() == NativeMode::x86 ? 4 : 8;
	uint32_t status = 0;
	try {
		if (name == "RegCloseKey") {
			status = registry.close(args[0]);
		} else if (name == "RegCreateKeyExW" || name == "RegOpenKeyExA") {
			const bool create = name == "RegCreateKeyExW";
			const auto path = guest_string(args[1], create, status);
			const uint64_t output = args[create ? 7 : 4];
			if (!status && !output)
				status = invalid_parameter;
			if (!status) {
				process.validate_write_memory(output, handle_width);
				if (create && args[8])
					process.validate_write_memory(args[8], 4);
				uint64_t key = 0;
				uint32_t disposition = 0;
				status = create ? registry.create(args[0], *path, key, disposition) : registry.open(args[0], *path, key);
				if (!status) {
					write_value(output, key, handle_width);
					if (create && args[8])
						write_value(args[8], disposition, 4);
				}
			}
		} else if (name == "RegSetValueExW") {
			const auto value_name = guest_string(args[1], true, status);
			const auto size = uint32_t(args[5]);
			if (!status && args[4] == 0 && size)
				status = invalid_parameter;
			if (!status) {
				const auto data = size ? process.read_memory(args[4], size) : std::vector<uint8_t>{};
				status = registry.set(args[0], *value_name, uint32_t(args[3]), data);
			}
		} else {
			const bool wide = name == "RegQueryValueExW";
			const auto value_name = guest_string(args[1], wide, status);
			if (!status && args[4] && !args[5])
				status = invalid_parameter;
			if (!status) {
				uint32_t type = 0;
				std::vector<uint8_t> data;
				status = registry.query(args[0], *value_name, type, data);
				if (!status && !wide && is_text(type)) {
					// ANSI callers see stored UTF-16 strings in the process code page, always terminated.
					std::u16string text;
					for (size_t index = 0; index + 1 < data.size(); index += 2)
						text.push_back(char16_t(data[index] | data[index + 1] << 8));
					auto ansi = encode_ansi(text, 1252);
					if (ansi.empty() || ansi.back() != '\0')
						ansi.push_back('\0');
					data.assign(ansi.begin(), ansi.end());
				}
				if (!status) {
					uint32_t capacity = 0;
					if (args[5])
					{
						const auto bytes = process.read_memory(args[5], 4);
						capacity = uint32_t(bytes[0]) | uint32_t(bytes[1]) << 8 | uint32_t(bytes[2]) << 16 | uint32_t(bytes[3]) << 24;
					}
					if (args[3])
						write_value(args[3], type, 4);
					if (args[4] && data.size() > capacity) {
						write_value(args[5], data.size(), 4);
						status = more_data;
					} else {
						if (args[4])
							process.write_memory(args[4], data);
						if (args[5])
							write_value(args[5], data.size(), 4);
					}
				}
			}
		}
	} catch (const std::runtime_error &failure) {
		const std::string_view message = failure.what();
		if (message.find("readable") == message.npos && message.find("writable") == message.npos)
			throw;
		status = no_access;
	}
	process.return_api(status);
	return true;
}

}
