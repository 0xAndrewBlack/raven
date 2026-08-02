#include "vulkan_thunk32_engine.h"

#include <algorithm>
#include <cstring>
#include <sys/mman.h>
#include <stdexcept>

namespace raven {

using namespace thunk32;

namespace {

constexpr size_t scratch_bytes = 16 << 20;

uint64_t little(const uint8_t *bytes, size_t size)
{
	uint64_t value = 0;
	for (size_t index = 0; index < size && index < 8; ++index)
		value |= uint64_t(bytes[index]) << (index * 8);
	return value;
}

void put_little(uint8_t *bytes, size_t size, uint64_t value)
{
	for (size_t index = 0; index < size; ++index)
		bytes[index] = uint8_t(value >> (index * 8));
}

// Ends a translated call whichever way the handler leaves.
struct TranslatedCall {
	NativeProcess &process;
	bool open = true;
	TranslatedCall(NativeProcess &process, std::vector<uint64_t> words, std::array<uint64_t, 4> floats) : process(process)
	{
		process.begin_translated_call(std::move(words), floats);
	}
	uint64_t finish()
	{
		open = false;
		return process.end_translated_call();
	}
	~TranslatedCall()
	{
		if (open)
			process.end_translated_call();
	}
};

}

VulkanThunk32::VulkanThunk32(NativeProcess &process, VulkanBridge &bridge) : process(process), bridge(bridge) {}

std::vector<std::pair<std::string_view, uint32_t>> VulkanThunk32::exports(std::span<const std::string_view> bridge_names)
{
	std::vector<std::pair<std::string_view, uint32_t>> result;
	for (const auto &command : commands)
		if (std::binary_search(bridge_names.begin(), bridge_names.end(), std::string_view(command.name)))
			result.emplace_back(command.name, command.words);
	// The Windows surface commands come from a header the registry tables do not cover; the bridge implements them by hand.
	if (std::binary_search(bridge_names.begin(), bridge_names.end(), std::string_view("vkCreateWin32SurfaceKHR")))
		result.emplace_back("vkCreateWin32SurfaceKHR", 4);
	if (std::binary_search(bridge_names.begin(), bridge_names.end(), std::string_view("vkGetPhysicalDeviceWin32PresentationSupportKHR")))
		result.emplace_back("vkGetPhysicalDeviceWin32PresentationSupportKHR", 2);
	std::sort(result.begin(), result.end());
	return result;
}

uint64_t VulkanThunk32::allocate(size_t bytes)
{
	if (!scratch) {
		scratch = process.map_memory(scratch_bytes, PROT_READ | PROT_WRITE);
		cursor = scratch;
	}
	cursor = (cursor + 15) & ~uint64_t(15);
	if (cursor + bytes > scratch + scratch_bytes)
		throw std::runtime_error("Vulkan call exceeds the translation buffer");
	const auto address = cursor;
	cursor += std::max<size_t>(bytes, 16);
	return address;
}

uint64_t VulkanThunk32::token_of(uint32_t handle)
{
	if (!handle)
		return 0;
	const auto found = tokens.find(handle);
	if (found == tokens.end())
		throw std::runtime_error("unknown Vulkan handle in a 32-bit call");
	return found->second;
}

uint32_t VulkanThunk32::handle_of(uint64_t token)
{
	if (!token)
		return 0;
	const auto found = handles.find(token);
	if (found != handles.end())
		return found->second;
	const uint32_t handle = next_handle;
	next_handle += 8;
	handles.emplace(token, handle);
	tokens.emplace(handle, token);
	return handle;
}

uint64_t VulkanThunk32::evaluate(uint32_t program, const Context &context)
{
	std::vector<uint64_t> stack;
	for (size_t at = program; lengths[at].op != Op::end; ++at) {
		const auto &op = lengths[at];
		switch (op.op) {
		case Op::constant: stack.push_back(op.a); break;
		case Op::field: {
			const auto &field = fields[op.a];
			stack.push_back(little(context.image + field.off32, field.size32));
			break;
		}
		case Op::param: stack.push_back(uint32_t(context.words->at(op.a))); break;
		case Op::deref: {
			const auto address = context.words->at(op.a);
			stack.push_back(address ? little(process.read_memory(address, 4).data(), 4) : 0);
			break;
		}
		case Op::arrow: {
			const auto address = context.words->at(op.a);
			const auto &parameter = params[context.first_param + op.a];
			const auto &field = fields[structs[parameter.target].first_field + op.b];
			stack.push_back(address ? little(process.read_memory(address + field.off32, field.size32).data(), field.size32) : 0);
			break;
		}
		case Op::divide: {
			const auto right = stack.back(); stack.pop_back();
			stack.back() = right ? stack.back() / right : 0;
			break;
		}
		case Op::add: {
			const auto right = stack.back(); stack.pop_back();
			stack.back() += right;
			break;
		}
		case Op::end: break;
		}
	}
	return stack.empty() ? 0 : stack.back();
}

uint64_t VulkanThunk32::convert(uint16_t index, uint64_t guest, size_t count, bool track)
{
	const auto &structure = structs[index];
	if (!structure.supported)
		throw std::runtime_error(std::string("Vulkan structure is not available to 32-bit programs: ") + structure.name);
	count = std::max<size_t>(count, 1);
	if (count > (1 << 20))
		throw std::runtime_error("Vulkan array too large for a 32-bit call");
	const auto source = process.read_memory(guest, structure.size32 * count);
	std::vector<uint8_t> image(size_t(structure.size64) * count);
	for (size_t element = 0; element < count; ++element)
		convert_elements(structure, source.data() + element * structure.size32, image.data() + element * structure.size64, track);
	const auto address = allocate(image.size());
	process.write_memory(address, image);
	if (track)
		tracked.push_back({index, guest, address, count});
	return address;
}

uint64_t VulkanThunk32::convert_chain(uint64_t guest, bool track)
{
	// Elements the bridge has no description of are dropped from the chain, as a layer that does not know an extension would.
	while (guest) {
		const auto head = process.read_memory(guest, 8);
		const uint32_t type = uint32_t(little(head.data(), 4));
		const auto found = std::find_if(structs.begin(), structs.end(), [&](const StructInfo &item) { return item.stype == type && item.supported; });
		if (found != structs.end() && type)
			return convert(uint16_t(found - structs.begin()), guest, 1, track);
		guest = little(head.data() + 4, 4);
	}
	return 0;
}

void VulkanThunk32::convert_elements(const StructInfo &structure, const uint8_t *source, uint8_t *target, bool track)
{
	const Context context{source, nullptr, 0};
	for (size_t at = 0; at < structure.field_count; ++at) {
		const auto &field = fields[structure.first_field + at];
		const uint8_t *from = source + field.off32;
		uint8_t *to = target + field.off64;
		switch (field.kind) {
		case Field::scalar:
		case Field::raw_union:
			std::memcpy(to, from, std::min<size_t>(field.size32, field.size64));
			break;
		case Field::dhandle:
			put_little(to, 8, token_of(uint32_t(little(from, 4))));
			break;
		case Field::dhandles:
			for (size_t element = 0; element < field.size32 / 4; ++element)
				put_little(to + element * 8, 8, token_of(uint32_t(little(from + element * 4, 4))));
			break;
		case Field::widen_value:
		case Field::widen_pointer:
			put_little(to, 8, little(from, 4));
			break;
		case Field::nested: {
			const auto &inner = structs[field.target];
			for (size_t element = 0; element < size_t(field.size32) / inner.size32; ++element)
				convert_elements(inner, from + element * inner.size32, to + element * inner.size64, track);
			break;
		}
		case Field::pnext:
			put_little(to, 8, convert_chain(little(from, 4), track));
			break;
		case Field::pointer_struct: {
			const auto pointer = little(from, 4);
			const size_t count = field.len == no_length ? 1 : size_t(evaluate(field.len, context));
			put_little(to, 8, pointer && count ? convert(field.target, pointer, count, track) : 0);
			break;
		}
		case Field::pointer_struct_pointers: {
			const auto pointer = little(from, 4);
			const size_t count = field.len == no_length ? 1 : size_t(evaluate(field.len, context));
			if (!pointer || !count) {
				put_little(to, 8, 0);
				break;
			}
			const auto list = process.read_memory(pointer, count * 4);
			const auto array = allocate(count * 8);
			std::vector<uint8_t> converted(count * 8);
			for (size_t element = 0; element < count; ++element) {
				const auto item = little(list.data() + element * 4, 4);
				put_little(converted.data() + element * 8, 8, item ? convert(field.target, item, 1, track) : 0);
			}
			process.write_memory(array, converted);
			put_little(to, 8, array);
			break;
		}
		case Field::pointer_strings:
		case Field::pointer_dhandles: {
			const auto pointer = little(from, 4);
			const size_t count = field.len == no_length ? 1 : size_t(evaluate(field.len, context));
			if (!pointer || !count) {
				put_little(to, 8, 0);
				break;
			}
			const auto list = process.read_memory(pointer, count * 4);
			std::vector<uint8_t> converted(count * 8);
			for (size_t element = 0; element < count; ++element) {
				const auto item = little(list.data() + element * 4, 4);
				put_little(converted.data() + element * 8, 8, field.kind == Field::pointer_dhandles ? token_of(uint32_t(item)) : item);
			}
			const auto array = allocate(count * 8);
			process.write_memory(array, converted);
			put_little(to, 8, array);
			break;
		}
		}
	}
}

void VulkanThunk32::restore(const StructInfo &structure, const uint8_t *source, uint8_t *target)
{
	for (size_t at = 0; at < structure.field_count; ++at) {
		const auto &field = fields[structure.first_field + at];
		const uint8_t *from = source + field.off64;
		uint8_t *to = target + field.off32;
		switch (field.kind) {
		case Field::scalar:
		case Field::raw_union:
			std::memcpy(to, from, std::min<size_t>(field.size32, field.size64));
			break;
		case Field::dhandle:
			put_little(to, 4, handle_of(little(from, 8)));
			break;
		case Field::dhandles:
			for (size_t element = 0; element < field.size32 / 4; ++element)
				put_little(to + element * 4, 4, handle_of(little(from + element * 8, 8)));
			break;
		case Field::widen_value:
			put_little(to, 4, little(from, 8));
			break;
		case Field::nested: {
			const auto &inner = structs[field.target];
			for (size_t element = 0; element < size_t(field.size32) / inner.size32; ++element)
				restore(inner, from + element * inner.size64, to + element * inner.size32);
			break;
		}
		default:
			// Addresses and chains stay as the program wrote them.
			break;
		}
	}
}

void VulkanThunk32::write_back()
{
	for (const auto &record : tracked) {
		const auto &structure = structs[record.structure];
		const auto image = process.read_memory(record.converted, size_t(structure.size64) * record.count);
		auto original = process.read_memory(record.guest, size_t(structure.size32) * record.count);
		for (size_t element = 0; element < record.count; ++element)
			restore(structure, image.data() + element * structure.size64, original.data() + element * structure.size32);
		process.write_memory(record.guest, original);
	}
}

bool VulkanThunk32::dispatch(std::string_view name)
{
	cursor = scratch;
	tracked.clear();
	if (name == "vkCreateWin32SurfaceKHR" || name == "vkGetPhysicalDeviceWin32PresentationSupportKHR")
		return dispatch_surface(name);
	const auto *command = find_command(name);
	if (!command)
		return false;
	const auto words = process.api_arguments(command->words);
	std::vector<uint64_t> raw(command->param_count), arguments(command->param_count);
	std::array<uint64_t, 4> floats{};
	// The first word of every parameter, which the lengths of the others may refer to.
	{
		size_t at = 0;
		for (size_t index = 0; index < command->param_count; ++index) {
			raw[index] = words[at];
			at += params[command->first_param + index].kind == Param::words ? 2 : 1;
		}
	}
	struct Output {
		size_t index;
		uint64_t guest, converted;
		size_t capacity;
	};
	std::vector<Output> outputs;
	const Context context{nullptr, &raw, command->first_param};
	size_t at = 0;
	for (size_t index = 0; index < command->param_count; ++index) {
		const auto &parameter = params[command->first_param + index];
		const size_t count = parameter.len == no_length ? 1 : size_t(evaluate(parameter.len, context));
		switch (parameter.kind) {
		case Param::word:
			arguments[index] = uint32_t(words[at++]);
			break;
		case Param::words:
			arguments[index] = words[at] | words[at + 1] << 32;
			at += 2;
			break;
		case Param::dhandle:
			arguments[index] = token_of(uint32_t(words[at++]));
			break;
		case Param::in_struct:
		case Param::inout_struct: {
			const auto pointer = words[at++];
			arguments[index] = pointer ? convert(parameter.target, pointer, count, parameter.kind == Param::inout_struct) : 0;
			break;
		}
		case Param::pass:
			arguments[index] = words[at++];
			break;
		case Param::out_dhandles: {
			const auto pointer = words[at++];
			arguments[index] = pointer ? allocate(std::max<size_t>(count, 1) * 8) : 0;
			if (pointer) {
				process.write_memory(arguments[index], std::vector<uint8_t>(std::max<size_t>(count, 1) * 8));
				outputs.push_back({index, pointer, arguments[index], count});
			}
			break;
		}
		case Param::in_dhandles: {
			const auto pointer = words[at++];
			if (!pointer || !count) {
				arguments[index] = 0;
				break;
			}
			const auto list = process.read_memory(pointer, count * 4);
			std::vector<uint8_t> converted(count * 8);
			for (size_t element = 0; element < count; ++element)
				put_little(converted.data() + element * 8, 8, token_of(uint32_t(little(list.data() + element * 4, 4))));
			arguments[index] = allocate(converted.size());
			process.write_memory(arguments[index], converted);
			break;
		}
		case Param::out_pointer: {
			const auto pointer = words[at++];
			arguments[index] = pointer ? allocate(8) : 0;
			if (pointer) {
				process.write_memory(arguments[index], std::vector<uint8_t>(8));
				outputs.push_back({index, pointer, arguments[index], 0});
			}
			break;
		}
		}
		if (parameter.floating && index < 4)
			floats[index] = arguments[index];
	}
	uint64_t result = 0;
	bool known = false;
	{
		TranslatedCall call(process, arguments, floats);
		known = bridge.dispatch(name);
		result = call.finish();
	}
	if (!known)
		return false;
	write_back();
	for (const auto &output : outputs) {
		const auto &parameter = params[command->first_param + output.index];
		if (parameter.kind == Param::out_pointer) {
			process.write_memory(output.guest, process.read_memory(output.converted, 4));
			continue;
		}
		size_t produced = output.capacity;
		if (parameter.len != no_length)
			produced = std::min<size_t>(produced, size_t(evaluate(parameter.len, context)));
		if (!produced)
			continue;
		const auto tokens_written = process.read_memory(output.converted, produced * 8);
		std::vector<uint8_t> narrowed(produced * 4);
		for (size_t element = 0; element < produced; ++element)
			put_little(narrowed.data() + element * 4, 4, handle_of(little(tokens_written.data() + element * 8, 8)));
		process.write_memory(output.guest, narrowed);
	}
	switch (command->ret) {
	case Ret::none: process.return_api(0); break;
	case Ret::word: process.return_api(uint32_t(result)); break;
	case Ret::words: process.return_api(result); break;
	case Ret::pointer: process.return_api(uint32_t(result)); break;
	}
	return true;
}

bool VulkanThunk32::dispatch_surface(std::string_view name)
{
	std::vector<uint64_t> arguments;
	if (name == "vkCreateWin32SurfaceKHR") {
		const auto words = process.api_arguments(4);
		// VkWin32SurfaceCreateInfoKHR: sType, pNext, flags, hinstance, hwnd; the 32-bit one has four-byte pointers.
		const auto source = process.read_memory(words[1], 20);
		std::vector<uint8_t> image(40);
		put_little(image.data(), 4, little(source.data(), 4));
		put_little(image.data() + 16, 4, little(source.data() + 8, 4));
		put_little(image.data() + 24, 8, little(source.data() + 12, 4));
		put_little(image.data() + 32, 8, little(source.data() + 16, 4));
		const auto converted = allocate(image.size());
		process.write_memory(converted, image);
		arguments = {token_of(uint32_t(words[0])), converted, words[2], words[3]};
	} else {
		const auto words = process.api_arguments(2);
		arguments = {token_of(uint32_t(words[0])), uint32_t(words[1])};
	}
	uint64_t result = 0;
	bool known = false;
	{
		TranslatedCall call(process, arguments, {});
		known = bridge.dispatch(name);
		result = call.finish();
	}
	if (!known)
		return false;
	process.return_api(uint32_t(result));
	return true;
}

}
