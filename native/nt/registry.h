#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace raven {

// Win32 registry state shared by every guest handle. Status values are Win32 error codes.
class NativeRegistry {
public:
	// A registry that never touches the host file system.
	NativeRegistry() = default;
	// Loads the hive file when present and rewrites it atomically after every change.
	explicit NativeRegistry(std::filesystem::path file);
	uint32_t create(uint64_t parent, std::u16string_view path, uint64_t &key, uint32_t &disposition);
	uint32_t open(uint64_t parent, std::u16string_view path, uint64_t &key);
	uint32_t close(uint64_t key);
	uint32_t query(uint64_t key, std::u16string_view name, uint32_t &type, std::vector<uint8_t> &data) const;
	uint32_t set(uint64_t key, std::u16string_view name, uint32_t type, std::span<const uint8_t> data);
	size_t handles() const { return open_keys.size(); }
	// Enumeration, deletion and statistics for the advapi32 surface; names sort case-insensitively like the real hive.
	uint32_t remove_key(uint64_t parent, std::u16string_view path);
	uint32_t remove_value(uint64_t key, std::u16string_view name);
	uint32_t enum_key(uint64_t key, uint32_t index, std::u16string &name) const;
	uint32_t enum_value(uint64_t key, uint32_t index, std::u16string &name, uint32_t &type, std::vector<uint8_t> &data) const;
	struct Info {
		uint32_t subkeys = 0, longest_subkey = 0, values = 0, longest_name = 0, longest_data = 0;
	};
	uint32_t info(uint64_t key, Info &result) const;

private:
	struct Value { std::u16string name; uint32_t type; std::vector<uint8_t> data; };
	struct Key { std::u16string path; std::map<std::u16string, Value> values; };
	std::filesystem::path file;
	std::map<std::u16string, Key> keys;
	std::map<uint64_t, std::u16string> open_keys;
	uint64_t next = 0x300;
	bool resolve(uint64_t parent, std::u16string_view path, std::u16string &folded, std::u16string &display) const;
	// Folded paths of the immediate subkeys of a folded key path, in key order.
	std::vector<std::u16string> children(const std::u16string &folded) const;
	void save() const;
	void load();
};

}
