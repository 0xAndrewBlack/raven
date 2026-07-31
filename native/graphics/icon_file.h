#pragma once

#include "icon_group.h"
#include "pe/resources.h"
#include <optional>

namespace raven {

struct FileIcon {
	std::span<const uint8_t> bytes;
	uint32_t id;
};

// Payload spans borrow the input file; decoded icon objects own their pixels.
class IconFile {
public:
	explicit IconFile(std::span<const uint8_t> bytes);
	size_t count() const;
	std::optional<size_t> group(int32_t index) const;
	std::optional<FileIcon> image(size_t group,uint32_t width,uint32_t height,IconDisplay display) const;

private:
	std::span<const uint8_t> bytes;
	std::optional<PEImage> pe;
	std::vector<PEResource> resources;
	std::vector<ResourceKey> groups;
	std::vector<IconEntry> entries;
	std::vector<std::span<const uint8_t>> images;
	const PEResource *resource(uint32_t type,const ResourceKey &name,uint32_t language) const;
};

}
