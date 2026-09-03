#include "elevation.h"

#include "pe/resources.h"

#include <string_view>

namespace raven {

namespace {

bool elevated = false;

}

bool manifest_requests_elevation(const PEImage &image)
{
	for (const auto &resource : image.resources()) {
		if (resource.type != ResourceKey{uint32_t(24)} || !resource.size)
			continue;
		const auto bytes = image.file_span(resource.data_address, resource.size);
		const std::string_view text(reinterpret_cast<const char *>(bytes.data()), bytes.size());
		const auto element = text.find("requestedExecutionLevel");
		if (element == text.npos)
			continue;
		const auto attribute = text.find("level=", element);
		if (attribute == text.npos || attribute + 7 >= text.size())
			continue;
		const char quote = text[attribute + 6];
		const auto end = text.find(quote, attribute + 7);
		if (end == text.npos)
			continue;
		const auto level = text.substr(attribute + 7, end - attribute - 7);
		return level == "requireAdministrator" || level == "highestAvailable";
	}
	return false;
}

void set_process_elevated(bool value)
{
	elevated = value;
}

bool process_elevated()
{
	return elevated;
}

}
