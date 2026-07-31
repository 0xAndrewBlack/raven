#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace raven {

struct PEResource;

struct PESection {
	std::string name;
	uint32_t address;
	uint32_t virtual_size;
	uint32_t file_offset;
	uint32_t file_size;
	uint32_t characteristics;
};

struct PEDirectory {
	uint32_t address;
	uint32_t size;
};

struct PEImport {
	std::string module;
	std::string name;
	uint16_t ordinal;
	bool by_ordinal;
	uint32_t iat_address;
};

struct PEExport {
	uint32_t ordinal;
	uint32_t address;
	std::vector<std::string> names;
	std::string forwarder;
};

struct PEDelayImport {
	std::string module;
	uint32_t descriptor_address;
	uint32_t module_handle_address;
	uint32_t iat_address;
	uint32_t lookup_address;
	uint32_t bound_address;
	uint32_t unload_address;
	uint32_t timestamp;
	std::vector<PEImport> imports;
};

// The caller owns the file bytes for the lifetime of this view.
class PEImage {
public:
	explicit PEImage(std::span<const uint8_t> bytes);
	std::span<const uint8_t> file_span(uint32_t rva, size_t size) const;
	std::vector<PEImport> imports() const;
	std::vector<PEDelayImport> delay_imports() const;
	std::vector<PEExport> exports() const;
	std::vector<PEResource> resources() const;

	bool is_64;
	uint16_t machine;
	uint16_t characteristics;
	uint64_t image_base;
	uint64_t heap_reserve;
	uint64_t heap_commit;
	uint32_t image_size;
	uint32_t headers_size;
	uint32_t entry;
	uint32_t section_alignment;
	uint32_t file_alignment;
	std::array<PEDirectory, 16> directories{};
	std::vector<PESection> sections;

private:
	std::span<const uint8_t> bytes;
	std::string string_at(uint32_t rva) const;
};

}
