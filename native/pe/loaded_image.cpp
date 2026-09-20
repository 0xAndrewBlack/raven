#include "loaded_image.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <sys/mman.h>
#include <unistd.h>

namespace raven {

static constexpr size_t page_size = 4096;

LoadedImage::LoadedImage(const PEImage &image, uint64_t base)
	: size(image.image_size), address(base)
{
	const uint64_t limit = image.is_64 ? 0x800000000000ULL : 0x100000000ULL;
	if (!(image.characteristics & 2))
		throw std::runtime_error("PE is not an executable image");
	if (!base || base % 65536 || base >= limit || size > limit - base)
		throw std::runtime_error("invalid guest image base");
	if (sysconf(_SC_PAGESIZE) != static_cast<long>(page_size))
		throw std::runtime_error("shared PE images require 4096-byte host pages");
	if (size > 1024ULL * 1024 * 1024)
		throw std::runtime_error("PE image exceeds initial mapping size limit");
	protections.resize((size + page_size - 1) / page_size, PROT_NONE);
	fd = memfd_create("raven-image", MFD_CLOEXEC);
	if (fd < 0)
		throw std::system_error(errno, std::generic_category(), "create PE backing file");
	try {
		if (ftruncate(fd, static_cast<off_t>(size)) != 0)
			throw std::system_error(errno, std::generic_category(), "size PE backing file");
		// The contents go in through the descriptor: copying them through the mapping took a page fault for every page of a library
		// of hundreds of megabytes, in every process that loads it.
		const auto put = [&](std::span<const uint8_t> source, uint64_t offset) {
			for (size_t done = 0; done < source.size();) {
				const auto written = pwrite(fd, source.data() + done, source.size() - done, static_cast<off_t>(offset + done));
				if (written < 0 && errno == EINTR)
					continue;
				if (written <= 0)
					throw std::system_error(errno, std::generic_category(), "fill PE backing file");
				done += size_t(written);
			}
		};
		put(image.file_span(0, image.headers_size), 0);
		for (const auto &section : image.sections)
			if (section.file_size)
				put(image.file_span(section.address, section.file_size), section.address);
		void *mapping = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (mapping == MAP_FAILED)
			throw std::system_error(errno, std::generic_category(), "map PE backing file");
		storage = static_cast<uint8_t *>(mapping);
		for (size_t page = 0; page * page_size < image.headers_size; ++page)
			protections[page] = PROT_READ;
		for (const auto &section : image.sections) {
			int protection = PROT_NONE;
			if (section.characteristics & 0x40000000)
				protection |= PROT_READ;
			if (section.characteristics & 0x80000000)
				protection |= PROT_WRITE;
			if (section.characteristics & 0x20000000)
				protection |= PROT_EXEC;
			const uint64_t end = uint64_t(section.address) + std::max(section.virtual_size, section.file_size);
			for (size_t page = section.address / page_size; page * page_size < end; ++page)
				protections.at(page) |= protection;
		}
		if (base != image.image_base)
			relocate(image);
	} catch (...) {
		release();
		throw;
	}
}

void LoadedImage::relocate(const PEImage &image)
{
	const auto directory = image.directories[5];
	if ((image.characteristics & 1) || !directory.address || !directory.size)
		throw std::runtime_error("PE image has no relocation table for the requested base");
	const auto table = image.file_span(directory.address, directory.size);
	struct Fixup { uint32_t address; size_t width; };
	std::vector<Fixup> fixups;
	for (size_t offset = 0; offset < table.size();) {
		if (table.size() - offset < 8 || offset % 4)
			throw std::runtime_error("truncated or misaligned PE relocation block");
		uint32_t page = 0;
		uint32_t block_size = 0;
		for (size_t i = 0; i < 4; ++i) {
			page |= uint32_t(table[offset + i]) << (i * 8);
			block_size |= uint32_t(table[offset + 4 + i]) << (i * 8);
		}
		if (page % page_size || block_size < 8 || block_size % 2 || block_size > table.size() - offset)
			throw std::runtime_error("invalid PE relocation block");
		for (size_t item = offset + 8; item < offset + block_size; item += 2) {
			const uint16_t entry = uint16_t(table[item]) | uint16_t(uint16_t(table[item + 1]) << 8);
			const uint16_t type = entry >> 12;
			if (!type)
				continue;
			if (type != (image.is_64 ? 10 : 3))
				throw std::runtime_error("unsupported PE relocation type");
			const size_t width = image.is_64 ? 8 : 4;
			const uint64_t target = uint64_t(page) + (entry & 0xfff);
			if (target > size || width > size - target)
				throw std::runtime_error("PE relocation target exceeds image");
			for (size_t byte = 0; byte < width; ++byte) {
				const uint64_t location = target + byte;
				const bool mapped = location < image.headers_size ||
					std::any_of(image.sections.begin(), image.sections.end(), [&](const auto &section) {
						return location >= section.address && location < uint64_t(section.address) +
							std::max(section.virtual_size, section.file_size);
					});
				if (!mapped)
					throw std::runtime_error("PE relocation target is not mapped");
			}
			fixups.push_back({static_cast<uint32_t>(target), width});
		}
		offset += block_size;
	}
	const uint64_t delta = address - image.image_base;
	for (const auto &fixup : fixups) {
		uint64_t value = 0;
		for (size_t i = 0; i < fixup.width; ++i)
			value |= uint64_t(storage[fixup.address + i]) << (i * 8);
		value += delta;
		for (size_t i = 0; i < fixup.width; ++i)
			storage[fixup.address + i] = static_cast<uint8_t>(value >> (i * 8));
	}
	relocated = fixups.size();
}

LoadedImage::~LoadedImage()
{
	release();
}

void LoadedImage::release()
{
	if (storage)
		munmap(storage, size);
	if (fd >= 0)
		close(fd);
	storage = nullptr;
	fd = -1;
}

std::span<uint8_t> LoadedImage::data()
{
	return {storage, size};
}

std::vector<ImageMapping> LoadedImage::mappings() const
{
	std::vector<ImageMapping> result;
	for (size_t page = 0; page < protections.size(); ++page) {
		const uint64_t offset = page * page_size;
		const uint64_t length = std::min<uint64_t>(page_size, size - offset);
		if (!result.empty() && result.back().protection == protections[page])
			result.back().size += length;
		else
			result.push_back({address + offset, length, offset, protections[page]});
	}
	return result;
}

int LoadedImage::descriptor() const { return fd; }
uint64_t LoadedImage::base() const { return address; }
size_t LoadedImage::relocation_count() const { return relocated; }

}
