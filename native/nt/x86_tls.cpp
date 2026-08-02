#include "x86_tls.h"

#include <algorithm>
#include <sys/mman.h>
#include <stdexcept>

namespace raven {

namespace {

uint32_t word(const std::vector<uint8_t> &bytes, size_t offset)
{
	return uint32_t(bytes[offset]) | uint32_t(bytes[offset + 1]) << 8 | uint32_t(bytes[offset + 2]) << 16 | uint32_t(bytes[offset + 3]) << 24;
}

void put_word(NativeProcess &process, uint64_t address, uint32_t value)
{
	const uint8_t bytes[4] = {uint8_t(value), uint8_t(value >> 8), uint8_t(value >> 16), uint8_t(value >> 24)};
	process.write_memory(address, bytes);
}

constexpr size_t tls_directory = 9;
constexpr size_t array_bytes = 4096;

}

void NativeX86Tls::make_block(Thread &thread, const Template &item)
{
	const size_t size = ((item.data.size() + item.zero_fill + 15) & ~size_t(15));
	const auto block = process.map_memory((std::max<size_t>(size, 16) + 4095) & ~size_t(4095), PROT_READ | PROT_WRITE);
	if (!item.data.empty())
		process.write_memory(block, item.data);
	put_word(process, thread.array + item.index * 4ULL, uint32_t(block));
	thread.blocks.push_back(block);
}

void NativeX86Tls::add(PEModule &module)
{
	const auto &directory = module.image.directories[tls_directory];
	if (!directory.address || directory.size < 24 || templates.contains(&module))
		return;
	const auto &image = module.loaded.data();
	const uint64_t base = module.loaded.base();
	if (directory.address + 24 > image.size())
		throw std::runtime_error("native x86 TLS directory lies outside its image");
	const std::vector<uint8_t> raw(image.begin() + directory.address, image.begin() + directory.address + 24);
	const uint32_t start = word(raw, 0), end = word(raw, 4), index_address = word(raw, 8), callbacks_address = word(raw, 12), zero = word(raw, 16);
	if (end < start || start < base || end > base + image.size() || next_index >= array_bytes / 4)
		throw std::runtime_error("native x86 TLS directory is not usable");
	Template item;
	item.data.assign(image.begin() + (start - base), image.begin() + (end - base));
	item.zero_fill = zero;
	item.index = next_index++;
	if (callbacks_address >= base && callbacks_address + 4 <= base + image.size())
		for (size_t at = callbacks_address - base; at + 4 <= image.size(); at += 4) {
			const auto callback = uint32_t(image[at]) | uint32_t(image[at + 1]) << 8 | uint32_t(image[at + 2]) << 16 | uint32_t(image[at + 3]) << 24;
			if (!callback)
				break;
			item.callbacks.push_back(callback);
		}
	put_word(process, index_address, item.index);
	for (auto &[teb, thread] : threads)
		make_block(thread, item);
	templates.emplace(&module, std::move(item));
}

std::vector<uint64_t> NativeX86Tls::callbacks(const PEModule &module) const
{
	const auto found = templates.find(&module);
	return found == templates.end() ? std::vector<uint64_t>{} : found->second.callbacks;
}

void NativeX86Tls::create_thread(uint64_t teb)
{
	Thread thread;
	thread.array = process.map_memory(array_bytes, PROT_READ | PROT_WRITE);
	thread.blocks.push_back(thread.array);
	put_word(process, teb + 0x2c, uint32_t(thread.array));
	for (const auto &[module, item] : templates)
		make_block(thread, item);
	threads[teb] = std::move(thread);
}

void NativeX86Tls::release_thread(uint64_t teb)
{
	const auto found = threads.find(teb);
	if (found == threads.end())
		return;
	for (const auto block : found->second.blocks)
		process.unmap_memory(block);
	threads.erase(found);
}

}
