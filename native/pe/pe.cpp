#include "pe.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

// Layout reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
namespace raven {

static void require_range(size_t offset, size_t size, size_t limit)
{
	if (offset > limit || size > limit - offset)
		throw std::runtime_error("PE range exceeds its backing data");
}

static uint64_t read_le(std::span<const uint8_t> bytes, size_t offset, size_t size)
{
	require_range(offset, size, bytes.size());
	uint64_t value = 0;
	for (size_t i = 0; i < size; ++i)
		value |= uint64_t(bytes[offset + i]) << (i * 8);
	return value;
}

static uint32_t read32(std::span<const uint8_t> bytes, size_t offset)
{
	return static_cast<uint32_t>(read_le(bytes, offset, 4));
}

static bool power_of_two(uint32_t value)
{
	return value != 0 && (value & (value - 1)) == 0;
}

PEImage::PEImage(std::span<const uint8_t> bytes) : bytes(bytes)
{
	if (read_le(bytes, 0, 2) != 0x5a4d)
		throw std::runtime_error("missing DOS signature");
	const size_t pe = read32(bytes, 0x3c);
	require_range(pe, 24, bytes.size());
	if (read32(bytes, pe) != 0x4550)
		throw std::runtime_error("missing PE signature");
	machine = static_cast<uint16_t>(read_le(bytes, pe + 4, 2));
	characteristics = static_cast<uint16_t>(read_le(bytes, pe + 22, 2));
	const size_t count = read_le(bytes, pe + 6, 2);
	const size_t optional_size = read_le(bytes, pe + 20, 2);
	const size_t optional = pe + 24;
	require_range(optional, optional_size, bytes.size());
	if (optional_size < 2)
		throw std::runtime_error("missing PE optional header");
	const uint64_t magic = read_le(bytes, optional, 2);
	if (magic != 0x10b && magic != 0x20b)
		throw std::runtime_error("unsupported PE optional header");
	is_64 = magic == 0x20b;
	if (machine != (is_64 ? 0x8664 : 0x14c))
		throw std::runtime_error("unsupported or inconsistent PE architecture");
	const size_t directory_offset = is_64 ? 112 : 96;
	if (optional_size < directory_offset)
		throw std::runtime_error("truncated PE optional header");
	entry = read32(bytes, optional + 16);
	image_base = read_le(bytes, optional + (is_64 ? 24 : 28), is_64 ? 8 : 4);
	heap_reserve = read_le(bytes, optional + (is_64 ? 88 : 80), is_64 ? 8 : 4);
	heap_commit = read_le(bytes, optional + (is_64 ? 96 : 84), is_64 ? 8 : 4);
	section_alignment = read32(bytes, optional + 32);
	file_alignment = read32(bytes, optional + 36);
	image_size = read32(bytes, optional + 56);
	headers_size = read32(bytes, optional + 60);
	if (!power_of_two(section_alignment) || !power_of_two(file_alignment) ||
		section_alignment < file_alignment ||
		(section_alignment < 4096 && file_alignment != section_alignment) ||
		(section_alignment >= 4096 && (file_alignment < 512 || file_alignment > 65536)))
		throw std::runtime_error("invalid PE alignment");
	if (!image_size || image_size % section_alignment || headers_size > image_size ||
		headers_size % file_alignment || (entry && entry >= image_size))
		throw std::runtime_error("invalid PE image dimensions");
	const uint64_t address_limit = is_64 ? std::numeric_limits<uint64_t>::max() : 0x100000000ULL;
	if (image_base > address_limit || image_size > address_limit - image_base)
		throw std::runtime_error("PE image address overflows its architecture");
	const size_t directory_count = read32(bytes, optional + directory_offset - 4);
	if (directory_count > (optional_size - directory_offset) / 8)
		throw std::runtime_error("PE directories exceed optional header");
	for (size_t i = 0; i < std::min(directory_count, directories.size()); ++i) {
		directories[i] = {read32(bytes, optional + directory_offset + i * 8),
			read32(bytes, optional + directory_offset + i * 8 + 4)};
		// The certificate directory uses file offsets rather than RVAs.
		if (directories[i].size)
			require_range(directories[i].address, directories[i].size,
				i == 4 ? bytes.size() : image_size);
	}
	const size_t table = optional + optional_size;
	if (count == 0 || count > 96)
		throw std::runtime_error("invalid PE section count");
	require_range(table, count * 40, bytes.size());
	if (headers_size < table + count * 40 || headers_size > bytes.size())
		throw std::runtime_error("PE headers do not contain the section table");
	for (size_t i = 0; i < count; ++i) {
		const size_t offset = table + i * 40;
		const auto name = bytes.subspan(offset, 8);
		const auto end = std::find(name.begin(), name.end(), uint8_t(0));
		PESection section{std::string(name.begin(), end), read32(bytes, offset + 12),
			read32(bytes, offset + 8), read32(bytes, offset + 20),
			read32(bytes, offset + 16), read32(bytes, offset + 36)};
		const uint32_t extent = std::max(section.virtual_size, section.file_size);
		require_range(section.address, extent, image_size);
		if (section.address % section_alignment || (extent && section.address < headers_size))
			throw std::runtime_error("invalid PE section address");
		if (section.file_size) {
			require_range(section.file_offset, section.file_size, bytes.size());
			if (section.file_offset < headers_size || section.file_offset % file_alignment)
				throw std::runtime_error("invalid PE section file offset");
		}
		for (const auto &previous : sections) {
			const uint32_t previous_size = std::max(previous.virtual_size, previous.file_size);
			const uint64_t previous_end = uint64_t(previous.address) +
				previous_size;
			if (extent && previous_size && previous_end > section.address &&
				uint64_t(section.address) + extent > previous.address)
				throw std::runtime_error("overlapping PE sections");
		}
		sections.push_back(section);
	}
}

std::span<const uint8_t> PEImage::file_span(uint32_t rva, size_t size) const
{
	require_range(rva, size, image_size);
	if (rva < headers_size) {
		require_range(rva, size, headers_size);
		return bytes.subspan(rva, size);
	}
	for (const auto &section : sections) {
		if (rva < section.address || uint64_t(rva) >= uint64_t(section.address) + section.file_size)
			continue;
		const size_t relative = rva - section.address;
		require_range(relative, size, section.file_size);
		return bytes.subspan(size_t(section.file_offset) + relative, size);
	}
	throw std::runtime_error("PE RVA has no file-backed data");
}

std::string PEImage::string_at(uint32_t rva) const
{
	size_t remaining = rva < headers_size ? headers_size - rva : 0;
	for (const auto &section : sections) {
		if (rva >= section.address && uint64_t(rva) < uint64_t(section.address) + section.file_size)
			remaining = section.file_size - (rva - section.address);
	}
	const auto data = file_span(rva, remaining);
	const auto end = std::find(data.begin(), data.end(), uint8_t(0));
	if (end == data.end())
		throw std::runtime_error("unterminated PE string");
	return std::string(data.begin(), end);
}

std::vector<PEImport> PEImage::imports() const
{
	const auto directory = directories[1];
	if (!directory.address && !directory.size)
		return {};
	if (!directory.address || directory.size < 20)
		throw std::runtime_error("invalid PE import directory");
	const auto descriptors = file_span(directory.address, directory.size);
	std::vector<PEImport> result;
	for (size_t offset = 0; offset + 20 <= descriptors.size(); offset += 20) {
		const auto descriptor = descriptors.subspan(offset, 20);
		if (std::all_of(descriptor.begin(), descriptor.end(), [](uint8_t v) { return v == 0; }))
			return result;
		const auto module = string_at(read32(descriptor, 12));
		const uint32_t iat = read32(descriptor, 16);
		const uint32_t lookup = read32(descriptor, 0) ? read32(descriptor, 0) : iat;
		if (!iat || !lookup || module.empty())
			throw std::runtime_error("invalid PE import descriptor");
		const uint32_t width = is_64 ? 8 : 4;
		for (uint64_t index = 0; ; ++index) {
			const uint64_t slot = uint64_t(lookup) + index * width;
			const uint64_t destination = uint64_t(iat) + index * width;
			if (slot > UINT32_MAX || destination > UINT32_MAX)
				throw std::runtime_error("PE thunk address overflows");
			const uint64_t value = read_le(file_span(static_cast<uint32_t>(slot), width), 0, width);
			if (!value)
				break;
			require_range(static_cast<size_t>(destination), width, image_size);
			const bool ordinal = (value & (uint64_t(1) << (width * 8 - 1))) != 0;
			if (!ordinal && value > UINT32_MAX - 2)
				throw std::runtime_error("PE import name RVA overflows");
			if (!ordinal)
				file_span(static_cast<uint32_t>(value), 2);
			result.push_back({module, ordinal ? std::string{} : string_at(static_cast<uint32_t>(value) + 2),
				static_cast<uint16_t>(ordinal ? value : 0), ordinal, static_cast<uint32_t>(destination)});
		}
	}
	throw std::runtime_error("unterminated PE import directory");
}

std::vector<PEDelayImport> PEImage::delay_imports() const
{
	const auto directory = directories[13];
	if (!directory.address && !directory.size)
		return {};
	if (!directory.address || directory.size < 32)
		throw std::runtime_error("invalid PE delay import directory");
	const auto descriptors = file_span(directory.address, directory.size);
	const uint32_t width = is_64 ? 8 : 4;
	size_t import_count = 0;
	std::vector<PEDelayImport> result;
	for (size_t offset = 0; offset + 32 <= descriptors.size(); offset += 32) {
		const auto descriptor = descriptors.subspan(offset, 32);
		if (std::all_of(descriptor.begin(), descriptor.end(), [](uint8_t v) { return v == 0; }))
			return result;
		if (result.size() >= 10000)
			throw std::runtime_error("PE delay descriptors exceed initial resource limit");
		const uint32_t attributes = read32(descriptor, 0);
		if (attributes & ~uint32_t(1))
			throw std::runtime_error("reserved PE delay import attributes");
		const auto rva = [&](uint64_t value) -> uint32_t {
			if (!value)
				return 0;
			if (!(attributes & 1)) {
				if (value < image_base)
					throw std::runtime_error("PE delay import VA precedes image");
				value -= image_base;
			}
			if (value >= image_size)
				throw std::runtime_error("PE delay import address exceeds image");
			return static_cast<uint32_t>(value);
		};
		const uint32_t module_name = rva(read32(descriptor, 4));
		if (!module_name)
			throw std::runtime_error("missing PE delay import module name");
		PEDelayImport item{string_at(module_name),
			static_cast<uint32_t>(directory.address + offset), rva(read32(descriptor, 8)),
			rva(read32(descriptor, 12)), rva(read32(descriptor, 16)),
			rva(read32(descriptor, 20)), rva(read32(descriptor, 24)), read32(descriptor, 28), {}};
		if (item.module.empty() || !item.module_handle_address || !item.iat_address || !item.lookup_address)
			throw std::runtime_error("invalid PE delay import descriptor");
		// Mutable delay-load storage may be in a zero-filled section.
		const auto mapped = [&](uint64_t address, uint64_t size) {
			require_range(address, size, image_size);
			if (address < headers_size && size <= headers_size - address)
				return;
			for (const auto &section : sections)
				if (address >= section.address && address < uint64_t(section.address) +
					std::max(section.virtual_size, section.file_size) &&
					size <= uint64_t(section.address) + std::max(section.virtual_size, section.file_size) - address)
					return;
			throw std::runtime_error("PE delay import storage is not mapped");
		};
		mapped(item.module_handle_address, width);
		for (uint64_t index = 0; ; ++index) {
			const uint64_t slot = uint64_t(item.lookup_address) + index * width;
			const uint64_t destination = uint64_t(item.iat_address) + index * width;
			if (slot > UINT32_MAX || destination > UINT32_MAX)
				throw std::runtime_error("PE delay thunk address overflows");
			const uint64_t value = read_le(file_span(static_cast<uint32_t>(slot), width), 0, width);
			mapped(destination, width);
			if (item.bound_address)
				file_span(item.bound_address, (index + 1) * width);
			if (item.unload_address)
				file_span(item.unload_address, (index + 1) * width);
			if (!value)
				break;
			if (++import_count > 1000000)
				throw std::runtime_error("PE delay imports exceed initial resource limit");
			const bool ordinal = (value & (uint64_t(1) << (width * 8 - 1))) != 0;
			if (ordinal && (value & ~((uint64_t(1) << (width * 8 - 1)) | UINT64_C(0xffff))))
				throw std::runtime_error("reserved PE delay ordinal bits");
			const uint32_t name = ordinal ? 0 : rva(value);
			if (!ordinal)
				file_span(name, 2);
			const auto symbol = ordinal ? std::string{} : string_at(name + 2);
			if (!ordinal && symbol.empty())
				throw std::runtime_error("empty PE delay import name");
			item.imports.push_back({item.module, symbol, static_cast<uint16_t>(ordinal ? value : 0),
				ordinal, static_cast<uint32_t>(destination)});
		}
		result.push_back(std::move(item));
	}
	throw std::runtime_error("unterminated PE delay import directory");
}

std::vector<PEExport> PEImage::exports() const
{
	const auto directory = directories[0];
	if (!directory.address && !directory.size)
		return {};
	if (!directory.address || directory.size < 40)
		throw std::runtime_error("invalid PE export directory");
	const auto header = file_span(directory.address, 40);
	const uint32_t base = read32(header, 16);
	const uint32_t count = read32(header, 20);
	const uint32_t name_count = read32(header, 24);
	if (count > 1000000 || name_count > 1000000)
		throw std::runtime_error("PE exports exceed initial resource limit");
	if (count && uint64_t(base) + count - 1 > UINT32_MAX)
		throw std::runtime_error("PE export ordinal overflows");
	if ((count && !read32(header, 28)) || (name_count && (!read32(header, 32) || !read32(header, 36))))
		throw std::runtime_error("missing PE export table address");
	const auto addresses = count ? file_span(read32(header, 28), size_t(count) * 4) : std::span<const uint8_t>{};
	const auto names = name_count ? file_span(read32(header, 32), size_t(name_count) * 4) : std::span<const uint8_t>{};
	const auto ordinals = name_count ? file_span(read32(header, 36), size_t(name_count) * 2) : std::span<const uint8_t>{};
	std::vector<PEExport> result;
	result.reserve(count);
	for (uint32_t index = 0; index < count; ++index) {
		const uint32_t address = read32(addresses, size_t(index) * 4);
		PEExport symbol{base + index, address, {}, {}};
		if (address >= directory.address && uint64_t(address) < uint64_t(directory.address) + directory.size) {
			const auto data = file_span(address, uint64_t(directory.address) + directory.size - address);
			const auto end = std::find(data.begin(), data.end(), uint8_t(0));
			if (end == data.end() || end == data.begin())
				throw std::runtime_error("invalid PE export forwarder string");
			symbol.forwarder = std::string(data.begin(), end);
		} else if (address) {
			const bool mapped = address < headers_size || std::any_of(sections.begin(), sections.end(), [&](const auto &section) {
				return address >= section.address && uint64_t(address) < uint64_t(section.address) +
					std::max(section.virtual_size, section.file_size);
			});
			if (!mapped)
				throw std::runtime_error("PE export target is outside mapped image data");
		}
		result.push_back(std::move(symbol));
	}
	std::string previous;
	for (uint32_t index = 0; index < name_count; ++index) {
		const size_t ordinal = read_le(ordinals, size_t(index) * 2, 2);
		if (ordinal >= result.size())
			throw std::runtime_error("PE export name ordinal exceeds address table");
		auto name = string_at(read32(names, size_t(index) * 4));
		if (name.empty() || (index && name <= previous))
			throw std::runtime_error("PE export names are empty, duplicated or unsorted");
		previous = name;
		result[ordinal].names.push_back(std::move(name));
	}
	return result;
}

}
