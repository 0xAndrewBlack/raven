#include "native_cpu.h"

#include <array>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

static void check(bool condition, const char *message)
{
	if (!condition)
		throw std::runtime_error(message);
}

template<typename F> static void rejected(F operation)
{
	try { operation(); } catch (const std::runtime_error &) { return; }
	throw std::runtime_error("invalid shared mapping was accepted");
}

static size_t descriptors()
{
	return size_t(std::distance(std::filesystem::directory_iterator("/proc/self/fd"), std::filesystem::directory_iterator{}));
}

static void mappings(const std::string &bootstrap, raven::NativeMode mode)
{
	const auto before = descriptors();
	{
		const std::array<raven::LoadedImage *, 0> images{};
		raven::NativeProcess process(images, bootstrap, std::chrono::seconds(2), mode);
		rejected([&] { process.map_descriptor(-1, 4096); });
		const auto code = process.map_memory(4096, PROT_READ | PROT_WRITE);
		const std::vector<uint8_t> x64{0x8b, 0x01, 0x83, 0xc0, 0x01, 0x89, 0x01, 0xc3};
		const std::vector<uint8_t> x86{0x8b, 0x4c, 0x24, 0x04, 0x8b, 0x01, 0x83, 0xc0, 0x01, 0x89, 0x01, 0xc2, 0x04, 0x00};
		process.write_memory(code, mode == raven::NativeMode::x64 ? x64 : x86);
		process.protect_memory(code, 4096, PROT_READ | PROT_EXEC);
		for (uint32_t iteration = 0; iteration < 8; ++iteration) {
			const int file = memfd_create("native-shared-mapping", MFD_CLOEXEC);
			check(file >= 0 && ftruncate(file, 8192) == 0, "cannot create mapping fixture");
			auto *host = static_cast<uint32_t *>(mmap(nullptr, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0));
			check(host != MAP_FAILED, "cannot map fixture in host");
			host[0] = 777;
			host[1024] = 40 + iteration;
			rejected([&] { process.map_descriptor(file, 0); });
			rejected([&] { process.map_descriptor(file, 4095); });
			rejected([&] { process.map_descriptor(file, 4096, 1); });
			rejected([&] { process.map_descriptor(file, 4096, UINT64_MAX); });
			const auto path = "/proc/self/fd/" + std::to_string(file);
			const int readonly = open(path.c_str(), O_RDONLY | O_CLOEXEC);
			check(readonly >= 0, "cannot open readonly fixture descriptor");
			rejected([&] { process.map_descriptor(readonly, 4096); });
			close(readonly);
			const auto address = process.map_descriptor(file, 4096, 4096);
			check(address % 65536 == 0 && (mode != raven::NativeMode::x86 || address < UINT32_MAX), "mapping alignment or x86 address differs");
			close(file);
			const std::array<uint64_t, 1> arguments{address};
			const auto result = process.call(code, arguments, std::chrono::seconds(2));
			check(result.stop == raven::NativeStop::returned && result.value == 41 + iteration && host[1024] == 41 + iteration && host[0] == 777,
				"guest CPU did not share the exact nonzero-offset mapping after descriptor close");
			const std::array<uint8_t, 4> bytes{0x12, 0x34, 0x56, 0x78};
			process.write_memory(address, bytes);
			check(host[1024] == 0x78563412 && process.read_memory(address, 4) == std::vector<uint8_t>(bytes.begin(), bytes.end()),
				"host and guest mapping updates disagree");
			process.protect_memory(address, 4096, PROT_READ);
			rejected([&] { process.write_memory(address, bytes); });
			check(process.read_memory(address, 4) == std::vector<uint8_t>(bytes.begin(), bytes.end()), "readonly shared view lost readable bytes");
			process.protect_memory(address, 4096, PROT_NONE);
			rejected([&] { process.read_memory(address, 4); });
			process.protect_memory(address, 4096, PROT_READ | PROT_WRITE);
			rejected([&] { process.read_memory(address + 4096, 1); });
			process.unmap_memory(address);
			rejected([&] { process.read_memory(address, 4); });
			munmap(host, 8192);
		}
		process.unmap_memory(code);
	}
	check(descriptors() == before, "native descriptor channel leaked a host file");
}

int main(int argc, char **argv)
{
	try {
		if (argc != 2)
			throw std::runtime_error("bootstrap path required");
		mappings(argv[1], raven::NativeMode::x64);
		mappings(argv[1], raven::NativeMode::x86);
		std::cout << "Native x64/x86 descriptor transfer, CPU shared writes, offsets, lifetime, rejection and cleanup passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
