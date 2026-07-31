#include "kernel_context.h"
#include "nls.h"
#include "registry.h"
#include "text.h"

#include <algorithm>
#include <cstring>

namespace raven {

namespace {

constexpr uint32_t error_more_data = 234, error_no_more_items = 259, error_invalid_parameter = 87, error_file_not_found = 2;
constexpr uint32_t type_sz = 1, type_expand_sz = 2, type_multi_sz = 7, type_dword = 4, type_qword = 11, type_binary = 3;

bool is_text(uint32_t type)
{
	return type == type_sz || type == type_expand_sz || type == type_multi_sz;
}

// Registry text is stored as UTF-16; ANSI callers receive the process code page, always terminated.
std::vector<uint8_t> to_ansi_bytes(const std::vector<uint8_t> &wide, uint32_t code_page)
{
	std::u16string text;
	for (size_t index = 0; index + 1 < wide.size(); index += 2)
		text.push_back(char16_t(wide[index] | wide[index + 1] << 8));
	auto ansi = encode_ansi(text, code_page == 1252 ? 1252 : 1252);
	if (ansi.empty() || ansi.back() != '\0')
		ansi.push_back('\0');
	return std::vector<uint8_t>(ansi.begin(), ansi.end());
}

std::vector<uint8_t> from_ansi_bytes(std::span<const uint8_t> ansi, uint32_t code_page)
{
	const auto text = from_ansi(std::string_view(reinterpret_cast<const char *>(ansi.data()), ansi.size()), code_page);
	std::vector<uint8_t> bytes(text.size() * 2);
	std::memcpy(bytes.data(), text.data(), bytes.size());
	return bytes;
}

}

void register_registry_api(ApiRegistry &registry, KernelContext &context, NativeRegistry &hive)
{
	const uint32_t ansi_page = context.launch.ansi_code_page;
	const size_t handle_width = context.process.mode() == NativeMode::x86 ? 4 : 8;
	const auto text_of = [](ApiCall &call, uint64_t address, bool wide) {
		if (!address)
			return std::u16string();
		return wide ? call.wide(address, 16384) : from_ansi(call.narrow(address, 16384), 1252);
	};
	const auto put_handle = [handle_width](ApiCall &call, uint64_t address, uint64_t value) {
		std::vector<uint8_t> bytes(handle_width);
		std::memcpy(bytes.data(), &value, handle_width);
		call.write(address, bytes);
	};
	for (const bool wide : {true, false}) {
		const std::string suffix = wide ? "W" : "A";
		registry.add("RegOpenKeyEx" + suffix, 5, [&hive, text_of, put_handle, wide](ApiCall &call) {
			if (!call[4]) {
				call.ret(error_invalid_parameter);
				return;
			}
			uint64_t key = 0;
			const auto status = hive.open(call[0], text_of(call, call[1], wide), key);
			if (!status)
				put_handle(call, call[4], key);
			call.ret(status);
		});
		registry.add("RegCreateKeyEx" + suffix, 9, [&hive, text_of, put_handle, wide](ApiCall &call) {
			if (!call[7]) {
				call.ret(error_invalid_parameter);
				return;
			}
			uint64_t key = 0;
			uint32_t disposition = 0;
			const auto status = hive.create(call[0], text_of(call, call[1], wide), key, disposition);
			if (!status) {
				put_handle(call, call[7], key);
				if (call[8]) call.store<uint32_t>(call[8], disposition);
			}
			call.ret(status);
		});
		registry.add("RegSetValueEx" + suffix, 6, [&hive, text_of, wide, ansi_page](ApiCall &call) {
			const auto name = text_of(call, call[1], wide);
			const uint32_t type = call.u32(3), size = call.u32(5);
			if (!call[4] && size) {
				call.ret(error_invalid_parameter);
				return;
			}
			auto data = size ? call.read(call[4], size) : std::vector<uint8_t>{};
			if (!wide && is_text(type))
				data = from_ansi_bytes(data, ansi_page);
			call.ret(hive.set(call[0], name, type, data));
		});
		registry.add("RegQueryValueEx" + suffix, 6, [&hive, text_of, wide, ansi_page](ApiCall &call) {
			const auto name = text_of(call, call[1], wide);
			if (call[4] && !call[5]) {
				call.ret(error_invalid_parameter);
				return;
			}
			uint32_t type = 0;
			std::vector<uint8_t> data;
			const auto status = hive.query(call[0], name, type, data);
			if (status) {
				call.ret(status);
				return;
			}
			if (!wide && is_text(type))
				data = to_ansi_bytes(data, ansi_page);
			if (call[3]) call.store<uint32_t>(call[3], type);
			if (!call[4]) {
				if (call[5]) call.store<uint32_t>(call[5], uint32_t(data.size()));
				call.ret(0);
				return;
			}
			const uint32_t capacity = call.load<uint32_t>(call[5]);
			call.store<uint32_t>(call[5], uint32_t(data.size()));
			if (data.size() > capacity) {
				call.ret(error_more_data);
				return;
			}
			call.write(call[4], data);
			call.ret(0);
		});
		registry.add("RegDeleteValue" + suffix, 2, [&hive, text_of, wide](ApiCall &call) { call.ret(hive.remove_value(call[0], text_of(call, call[1], wide))); });
		registry.add("RegDeleteKey" + suffix, 2, [&hive, text_of, wide](ApiCall &call) { call.ret(hive.remove_key(call[0], text_of(call, call[1], wide))); });
		registry.add("RegEnumKeyEx" + suffix, 8, [&hive, wide](ApiCall &call) {
			std::u16string name;
			const auto status = hive.enum_key(call[0], call.u32(1), name);
			if (status) {
				call.ret(status);
				return;
			}
			const uint32_t capacity = call.load<uint32_t>(call[3]);
			const auto narrow = wide ? std::string() : encode_ansi(name, 1252);
			const size_t length = wide ? name.size() : narrow.size();
			if (capacity <= length) {
				call.ret(error_more_data);
				return;
			}
			if (wide) call.put_wide(call[2], name, capacity);
			else call.put_narrow(call[2], narrow, capacity);
			call.store<uint32_t>(call[3], uint32_t(length));
			if (call[5] && call[6]) {
				if (call.load<uint32_t>(call[6]) > 0)
					call.store<uint16_t>(call[5], 0);
				call.store<uint32_t>(call[6], 0);
			}
			if (call[7]) call.store<uint64_t>(call[7], 0);
			call.ret(0);
		});
		registry.add("RegEnumValue" + suffix, 8, [&hive, wide, ansi_page](ApiCall &call) {
			std::u16string name;
			uint32_t type = 0;
			std::vector<uint8_t> data;
			const auto status = hive.enum_value(call[0], call.u32(1), name, type, data);
			if (status) {
				call.ret(status);
				return;
			}
			if (!wide && is_text(type))
				data = to_ansi_bytes(data, ansi_page);
			const uint32_t name_capacity = call.load<uint32_t>(call[3]);
			const auto narrow = wide ? std::string() : encode_ansi(name, 1252);
			const size_t length = wide ? name.size() : narrow.size();
			if (name_capacity <= length) {
				call.ret(error_more_data);
				return;
			}
			if (call[4]) call.ret(error_invalid_parameter);
			if (call[5]) call.store<uint32_t>(call[5], type);
			if (call[6]) {
				if (!call[7]) {
					call.ret(error_invalid_parameter);
					return;
				}
				const uint32_t capacity = call.load<uint32_t>(call[7]);
				call.store<uint32_t>(call[7], uint32_t(data.size()));
				if (data.size() > capacity) {
					call.ret(error_more_data);
					return;
				}
				call.write(call[6], data);
			} else if (call[7]) {
				call.store<uint32_t>(call[7], uint32_t(data.size()));
			}
			if (wide) call.put_wide(call[2], name, name_capacity);
			else call.put_narrow(call[2], narrow, name_capacity);
			call.store<uint32_t>(call[3], uint32_t(length));
			call.ret(0);
		});
	}
	registry.add("RegDeleteKeyExW", 4, [&hive, text_of](ApiCall &call) { call.ret(hive.remove_key(call[0], text_of(call, call[1], true))); });
	registry.add("RegCloseKey", 1, [&hive](ApiCall &call) { call.ret(hive.close(call[0])); });
	registry.add("RegFlushKey", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("RegNotifyChangeKeyValue", 5, [](ApiCall &call) { call.ret(0); });
	registry.add("RegOpenCurrentUser", 2, [put_handle](ApiCall &call) {
		put_handle(call, call[1], 0x80000001ULL);
		call.ret(0);
	});
	registry.add("RegQueryInfoKeyW", 12, [&hive](ApiCall &call) {
		NativeRegistry::Info info;
		const auto status = hive.info(call[0], info);
		if (status) {
			call.ret(status);
			return;
		}
		if (call[2]) call.store<uint32_t>(call[2], 0);
		if (call[4]) call.store<uint32_t>(call[4], info.subkeys);
		if (call[5]) call.store<uint32_t>(call[5], info.longest_subkey);
		if (call[6]) call.store<uint32_t>(call[6], 0);
		if (call[7]) call.store<uint32_t>(call[7], info.values);
		if (call[8]) call.store<uint32_t>(call[8], info.longest_name);
		if (call[9]) call.store<uint32_t>(call[9], info.longest_data);
		if (call[10]) call.store<uint32_t>(call[10], 0);
		if (call[11]) call.store<uint64_t>(call[11], 0);
		call.ret(0);
	});
	// RegGetValue filters by type (RRF_RT_*), opens the subkey itself and expands REG_EXPAND_SZ unless told not to.
	registry.add("RegGetValueW", 7, [&hive, text_of](ApiCall &call) {
		const uint32_t flags = call.u32(3);
		uint64_t key = call[0];
		uint64_t opened = 0;
		const auto subkey = text_of(call, call[1], true);
		if (!subkey.empty()) {
			const auto status = hive.open(key, subkey, opened);
			if (status) {
				call.ret(status);
				return;
			}
			key = opened;
		}
		uint32_t type = 0;
		std::vector<uint8_t> data;
		auto status = hive.query(key, text_of(call, call[2], true), type, data);
		if (opened)
			hive.close(opened);
		if (status) {
			call.ret(status);
			return;
		}
		const auto allowed = [&](uint32_t value) {
			switch (value) {
			case type_sz: return flags & 0x2; case type_expand_sz: return flags & 0x4; case type_multi_sz: return flags & 0x20;
			case type_dword: return flags & 0x10; case type_qword: return flags & 0x40; case type_binary: return flags & 0x8;
			default: return 0U;
			}
		};
		if ((flags & 0xffff) && !allowed(type) && !(flags & 1)) {
			call.ret(1629);
			return;
		}
		if (call[4]) call.store<uint32_t>(call[4], type);
		if (!call[5]) {
			if (call[6]) call.store<uint32_t>(call[6], uint32_t(data.size()));
			call.ret(0);
			return;
		}
		const uint32_t capacity = call.load<uint32_t>(call[6]);
		call.store<uint32_t>(call[6], uint32_t(data.size()));
		if (data.size() > capacity) {
			call.ret(error_more_data);
			return;
		}
		call.write(call[5], data);
		call.ret(0);
	});
	(void)error_no_more_items;
	(void)error_file_not_found;
}

}
