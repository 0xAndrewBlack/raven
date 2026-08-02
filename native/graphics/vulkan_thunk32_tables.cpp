// Tables describing how Vulkan structures and commands cross from the 32-bit ABI; see scripts/generate-vulkan-thunk32.py.
#include "vulkan_thunk32.h"

#include <vulkan/vulkan.h>

#include <algorithm>
#include <cstddef>
#include <cstring>

namespace raven::thunk32 {

#pragma GCC diagnostic ignored "-Winvalid-offsetof"
#include "vulkan_thunk32.inc"

const std::span<const FieldInfo> fields{field_rows};
const std::span<const StructInfo> structs{struct_rows};
const std::span<const LenOp> lengths{length_rows};
const std::span<const ParamInfo> params{param_rows};
const std::span<const CommandInfo> commands{command_rows};

const CommandInfo *find_command(std::string_view name)
{
	const auto found = std::lower_bound(std::begin(command_rows), std::end(command_rows), name,
		[](const CommandInfo &row, std::string_view key) { return std::string_view(row.name) < key; });
	return found != std::end(command_rows) && std::string_view(found->name) == name ? found : nullptr;
}

}
