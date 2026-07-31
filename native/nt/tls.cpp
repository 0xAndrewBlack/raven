#include "tls.h"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <sys/mman.h>

namespace raven {

static uint64_t integer(NativeProcess &process, uint64_t address, size_t width)
{
	const auto bytes = process.read_memory(address, width);
	uint64_t result = 0;
	for (size_t index = 0; index < width; ++index)
		result |= uint64_t(bytes[index]) << (index * 8);
	return result;
}

static void put(NativeProcess &process, uint64_t address, uint64_t value, size_t width)
{
	std::array<uint8_t, 8> bytes{};
	for (size_t index = 0; index < width; ++index)
		bytes[index] = static_cast<uint8_t>(value >> (index * 8));
	process.write_memory(address, std::span(bytes).first(width));
}

std::optional<NativeTLS::Template> NativeTLS::parse(const PEModule *module, size_t total) const
{
	std::vector<uint64_t> functions;
	const auto directory = module->image.directories[9];
	if (!directory.address && !directory.size)
		return std::nullopt;
	const uint64_t base = module->loaded.base();
	const auto within = [&](uint64_t address, uint64_t size) {
		if (address < base || address - base > module->image.image_size || size > module->image.image_size - (address - base))
			throw std::runtime_error("static TLS address is outside its module: " + module->name);
	};
	if (!module->image.is_64 || directory.size < 40)
		throw std::runtime_error("invalid PE64 TLS directory: " + module->name);
	within(base + directory.address, directory.size);
	const auto raw = process.read_memory(base + directory.address, 40);
	const auto field = [&](size_t offset, size_t width = 8) {
		uint64_t result = 0;
		for (size_t index = 0; index < width; ++index)
			result |= uint64_t(raw[offset + index]) << (index * 8);
		return result;
	};
	const uint64_t start = field(0), end = field(8), index = field(16);
	uint64_t array = field(24);
	const uint64_t zero_fill = field(32, 4), characteristics = field(36, 4);
	const uint64_t alignment_code = (characteristics >> 20) & 15;
	if (end < start || (characteristics & ~uint64_t(0xf00000)) || alignment_code == 15)
		throw std::runtime_error("invalid static TLS size or alignment: " + module->name);
	if (end - start > 64 * 1024 * 1024)
		throw std::runtime_error("static TLS template exceeds allocation limit");
	const uint64_t size = end - start + zero_fill;
	if (size > 64 * 1024 * 1024 || total > 64 * 1024 * 1024 - size)
		throw std::runtime_error("static TLS exceeds initial thread allocation limit");
	within(index, 4);
	// Validate all template and index permissions before publishing any slot.
	process.write_memory(index, process.read_memory(index, 4));
	std::vector<uint8_t> bytes;
	if (start || end) {
		within(start, end - start);
		bytes = process.read_memory(start, static_cast<size_t>(end - start));
	}
	if (array) {
		for (size_t position = 0;; ++position) {
			if (position == 1024)
				throw std::runtime_error("unterminated static TLS callback array");
			within(array, 8);
			const auto function = integer(process, array, 8);
			if (!function)
				break;
			within(function, 1);
			const auto mappings = module->loaded.mappings();
			if (!std::any_of(mappings.begin(), mappings.end(), [&](const auto &mapping) {
				return function >= mapping.address && function - mapping.address < mapping.size && (mapping.protection & PROT_EXEC);
			}))
				throw std::runtime_error("static TLS callback is not executable");
			functions.push_back(function);
			array += 8;
		}
	}
	const size_t alignment = alignment_code ? size_t(1) << (alignment_code - 1) : 16;
	return Template{index, static_cast<size_t>(size), alignment, std::move(bytes), std::move(functions)};
}

NativeTLS::NativeTLS(NativeProcess &process, const NativeEnvironment &environment,
	std::span<const PEModule *const> order)
	: process(process), environment(environment)
{
	if (process.active() || process.context().registers.gs_base != environment.teb() || order.size() > 10000)
		throw std::runtime_error("invalid static TLS initialization state");
	if (integer(process, environment.teb() + 0x58, 8))
		throw std::runtime_error("initial thread static TLS already exists");
	std::map<const PEModule *, std::optional<Template>> prepared;
	size_t allocated = 0;
	for (const auto *module : order) {
		if (!module || prepared.contains(module))
			throw std::runtime_error("invalid static TLS module order");
		auto item = parse(module, allocated);
		if (item)
			allocated += item->size;
		prepared.emplace(module, std::move(item));
	}
	for (const auto *module : order)
		if (prepared.at(module)) {
			process.write_memory(environment.teb() + 0x58, process.read_memory(environment.teb() + 0x58, 8));
			break;
		}
	for (const auto *module : order)
		install(*module, prepared.at(module));
	if (vector)
		put(process, environment.teb() + 0x58, vector, 8);
}

void NativeTLS::validate() const
{
	if (process.context().registers.gs_base != environment.teb() ||
		integer(process, environment.teb() + 0x58, 8) != vector)
		throw std::runtime_error("native loader TLS vector identity was modified");
	for (const auto &[module, entry] : entries)
		if (entry.slot != UINT32_MAX && (integer(process, entry.index, 4) != entry.slot ||
			integer(process, vector + uint64_t(entry.slot) * 8, 8) != entry.block))
			throw std::runtime_error("native loader TLS slot identity was modified");
}

void NativeTLS::install(const PEModule &module, const std::optional<Template> &item)
{
	if (!item) {
		entries.emplace(&module, Entry{});
		return;
	}
	uint32_t slot = 0;
	while (slot < 10000 && occupied.test(slot))
		++slot;
	if (slot == 10000)
		throw std::runtime_error("native loader TLS slots exceed initial limit");
	const auto old_index = process.read_memory(item->index, 4);
	const bool new_vector = !vector;
	uint64_t storage = 0;
	bool index_written = false;
	try {
		// Keep the initial thread's vector stable across late DLL loads, within the existing slot limit.
		if (new_vector)
			vector = process.map_memory((10000 * 8 + 4095) & ~size_t(4095), PROT_READ | PROT_WRITE);
		const size_t allocation = (std::max(item->size, size_t(1)) + item->alignment - 1 + 4095) & ~size_t(4095);
		storage = process.map_memory(allocation, PROT_READ | PROT_WRITE);
		const uint64_t block = (storage + item->alignment - 1) & ~uint64_t(item->alignment - 1);
		process.write_memory(block, item->bytes);
		entries.emplace(&module, Entry{slot, item->index, storage, block, item->size, item->callbacks, item->alignment, item->bytes});
		put(process, item->index, slot, 4);
		index_written = true;
		put(process, vector + uint64_t(slot) * 8, block, 8);
		occupied.set(slot);
		total += item->size;
	} catch (...) {
		entries.erase(&module);
		if (index_written)
			process.write_memory(item->index, old_index);
		if (storage)
			process.unmap_memory(storage);
		if (new_vector && vector) {
			process.unmap_memory(vector);
			vector = 0;
		}
		throw;
	}
}

void NativeTLS::add(const PEModule &module)
{
	validate();
	if (!module.image.is_64 || entries.contains(&module) || entries.size() >= 10000 ||
		std::any_of(entries.begin(), entries.end(), [&](const auto &entry) { return entry.first->loaded.base() == module.loaded.base(); }))
		throw std::runtime_error("invalid dynamic native loader TLS module");
	if (process.read_memory(module.loaded.base(), 2) != std::vector<uint8_t>{0x4d, 0x5a})
		throw std::runtime_error("dynamic native loader TLS image is not mapped");
	const auto item = parse(&module, total);
	const bool new_vector = !vector;
	if (new_vector && item)
		process.write_memory(environment.teb() + 0x58, process.read_memory(environment.teb() + 0x58, 8));
	install(module, item);
	if (new_vector && vector)
		put(process, environment.teb() + 0x58, vector, 8);
}

void NativeTLS::remove(const PEModule &module)
{
	validate();
	const auto found = entries.find(&module);
	if (found == entries.end())
		throw std::runtime_error("native loader TLS module is not registered");
	const auto &entry = found->second;
	if (entry.slot != UINT32_MAX) {
		process.write_memory(entry.index, process.read_memory(entry.index, 4));
		put(process, vector + uint64_t(entry.slot) * 8, 0, 8);
		process.unmap_memory(entry.allocation);
		occupied.reset(entry.slot);
		total -= entry.size;
	}
	entries.erase(found);
}

void NativeTLS::create_thread(uint64_t teb)
{
	if (!vector)
		return;
	std::vector<uint64_t> owned;
	try {
		const uint64_t slots = process.map_memory((10000 * 8 + 4095) & ~size_t(4095), PROT_READ | PROT_WRITE);
		owned.push_back(slots);
		for (const auto &[module, entry] : entries) {
			if (entry.slot == UINT32_MAX)
				continue;
			const size_t allocation = (std::max(entry.size, size_t(1)) + entry.alignment - 1 + 4095) & ~size_t(4095);
			const uint64_t storage = process.map_memory(allocation, PROT_READ | PROT_WRITE);
			owned.push_back(storage);
			const uint64_t block = (storage + entry.alignment - 1) & ~uint64_t(entry.alignment - 1);
			process.write_memory(block, entry.bytes);
			put(process, slots + uint64_t(entry.slot) * 8, block, 8);
		}
		put(process, teb + 0x58, slots, 8);
	} catch (...) {
		for (const auto address : owned)
			process.unmap_memory(address);
		throw;
	}
	thread_storage[teb] = std::move(owned);
}

void NativeTLS::release_thread(uint64_t teb)
{
	const auto found = thread_storage.find(teb);
	if (found == thread_storage.end())
		return;
	for (const auto address : found->second)
		process.unmap_memory(address);
	thread_storage.erase(found);
}

const std::vector<uint64_t> &NativeTLS::callbacks(const PEModule &module) const
{
	const auto found = entries.find(&module);
	if (found == entries.end())
		throw std::runtime_error("native loader TLS module is not registered");
	return found->second.callbacks;
}

}
