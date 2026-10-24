// Checks the 32-bit translation tables against the host layouts they are meant to match.
#include "vulkan_thunk32.h"

#include <iostream>
#include <string>

using namespace raven::thunk32;

int main()
{
	int failures = 0;
	const auto fail = [&](const StructInfo &structure, size_t at, const std::string &why) {
		std::cerr << structure.name << " field " << at << ": " << why << '\n';
		++failures;
	};
	size_t supported = 0;
	for (const auto &structure : structs) {
		if (!structure.supported)
			continue;
		++supported;
		for (size_t at = 0; at < structure.field_count; ++at) {
			const auto &field = fields[structure.first_field + at];
			if (field.off32 + field.size32 > structure.size32 || field.off64 + field.size64 > structure.size64)
				fail(structure, at, "member outside its structure");
			switch (field.kind) {
			case Field::scalar:
				if (field.size32 != field.size64)
					fail(structure, at, "scalar of different sizes " + std::to_string(field.size32) + "/" + std::to_string(field.size64));
				break;
			case Field::raw_union:
			case Field::descriptor_data:
				if (field.size32 != field.size64)
					fail(structure, at, "union of different sizes " + std::to_string(field.size32) + "/" + std::to_string(field.size64));
				break;
			case Field::dhandle:
				if (field.size32 != 4 || field.size64 != 8)
					fail(structure, at, "dispatchable handle of unexpected size");
				break;
			case Field::dhandles:
				if (field.size32 / 4 != field.size64 / 8)
					fail(structure, at, "handle arrays of different lengths");
				break;
			case Field::widen_value:
			case Field::widen_pointer:
			case Field::pnext:
			case Field::pointer_struct:
			case Field::pointer_struct_pointers:
			case Field::pointer_strings:
			case Field::pointer_dhandles:
				if (field.size32 != 4 || field.size64 != 8)
					fail(structure, at, "pointer-width member of unexpected size " + std::to_string(field.size32) + "/" + std::to_string(field.size64));
				break;
			case Field::nested: {
				const auto &inner = structs[field.target];
				if (field.size32 % inner.size32 || field.size64 % inner.size64 || field.size32 / inner.size32 != field.size64 / inner.size64)
					fail(structure, at, "nested structure counts differ");
				break;
			}
			}
		}
	}
	for (const auto &command : commands) {
		size_t words = 0;
		for (size_t at = 0; at < command.param_count; ++at)
			words += params[command.first_param + at].kind == Param::words ? 2 : 1;
		if (words != command.words) {
			std::cerr << command.name << ": " << words << " words counted, " << command.words << " recorded\n";
			++failures;
		}
	}
	if (supported < 1000 || commands.size() < 300) {
		std::cerr << "too few entries: " << supported << " structures, " << commands.size() << " commands\n";
		++failures;
	}
	std::cout << supported << " structures and " << commands.size() << " commands checked, " << failures << " problems\n";
	return failures ? 1 : 0;
}
