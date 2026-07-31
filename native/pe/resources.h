#pragma once

#include "pe.h"

#include <variant>

namespace raven {

using ResourceKey = std::variant<uint32_t, std::u16string>;

struct PEResource {
	ResourceKey type;
	ResourceKey name;
	uint32_t language;
	uint32_t entry_address;
	uint32_t data_address;
	uint32_t size;
	uint32_t code_page;
};

// Directory offsets are relative to the resource root; payload RVAs are image-relative.
std::vector<PEResource> read_resources(PEDirectory directory,
	std::span<const uint8_t> bytes, uint32_t image_size);

}
