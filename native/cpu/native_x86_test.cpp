#include "native_cpu.h"

#include <algorithm>
#include <cerrno>
#include <functional>
#include <iostream>
#include <signal.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/wait.h>

static void check(bool condition, const char *message)
{
	if (!condition)
		throw std::runtime_error(message);
}

static void put(std::span<uint8_t> bytes, size_t offset, uint64_t value, size_t width = 4)
{
	for (size_t i = 0; i < width; ++i)
		bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
}

constexpr uint32_t image_base = 0x400000;
constexpr uint32_t trap_rva = 0x1100;

// One PE32 executable whose code section holds each probe at a fixed 0x20 byte slot.
static std::vector<uint8_t> fixture()
{
	std::vector<uint8_t> bytes(0x600);
	put(bytes, 0, 0x5a4d, 2);
	put(bytes, 0x3c, 0x80);
	put(bytes, 0x80, 0x4550);
	put(bytes, 0x84, 0x14c, 2);
	put(bytes, 0x86, 2, 2);
	put(bytes, 0x94, 224, 2);
	put(bytes, 0x96, 2, 2);
	put(bytes, 0x98, 0x10b, 2);
	put(bytes, 0xa8, 0x1000);
	put(bytes, 0xb4, image_base);
	put(bytes, 0xb8, 0x1000);
	put(bytes, 0xbc, 0x200);
	put(bytes, 0xd0, 0x5000);
	put(bytes, 0xd4, 0x200);
	put(bytes, 0xf4, 16);
	for (size_t i = 0; i < 2; ++i) {
		const size_t section = 0x178 + i * 40;
		bytes[section] = '.';
		bytes[section + 1] = i == 0 ? 't' : 'd';
		put(bytes, section + 8, 0x400);
		put(bytes, section + 12, i == 0 ? 0x1000 : 0x3000);
		put(bytes, section + 16, 0x200);
		put(bytes, section + 20, 0x200 + i * 0x200);
		put(bytes, section + 36, i == 0 ? 0x60000020 : 0xc0000040);
	}
	const auto place = [&](size_t slot, std::initializer_list<uint8_t> code) {
		std::copy(code.begin(), code.end(), bytes.begin() + 0x200 + slot * 0x20);
	};
	place(0, {0xb8, 0x34, 0x12, 0x00, 0x00, 0xc3});
	place(1, {0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08, 0xc2, 0x08, 0x00});
	place(2, {0x64, 0xa1, 0x18, 0x00, 0x00, 0x00, 0xc3});
	place(3, {0x6a, 0x07, 0x6a, 0x05, 0xb8, 0x00, 0x11, 0x40, 0x00, 0xff, 0xd0, 0xc3});
	place(4, {0x8b, 0x44, 0x24, 0x04, 0xc3});
	bytes[0x200 + (trap_rva - 0x1000)] = 0xcc;
	return bytes;
}

static uint64_t slot(size_t index)
{
	return image_base + 0x1000 + index * 0x20;
}

static void rejected(const std::function<void()> &operation)
{
	try {
		operation();
	} catch (const std::runtime_error &) {
		return;
	}
	throw std::runtime_error("unsupported x86 setup was accepted");
}

static void no_children()
{
	int status = 0;
	errno = 0;
	check(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD, "x86 guest leaked or was not reaped");
}

int main(int argc, char **argv)
{
	try {
		if (argc != 2)
			throw std::runtime_error("bootstrap path required");
		const auto timeout = std::chrono::seconds(2);
		{
			const raven::PEImage image(fixture());
			check(!image.is_64, "fixture is not PE32");
			raven::LoadedImage loaded(image, image.image_base);
			raven::LoadedImage *images[] = {&loaded};
			raven::NativeProcess process(images, argv[1], timeout, raven::NativeMode::x86);
			check(process.mode() == raven::NativeMode::x86, "process lost its x86 mode");

			const auto constant = process.call(slot(0), {}, timeout);
			check(constant.stop == raven::NativeStop::returned && constant.value == 0x1234, "x86 return value differs");

			const uint64_t add[] = {20, 22};
			const auto sum = process.call(slot(1), add, timeout);
			check(sum.stop == raven::NativeStop::returned && sum.value == 42, "x86 stdcall arguments differ");
			const uint64_t wide[] = {0x100000000ULL};
			rejected([&] { process.call(slot(4), wide, timeout); });

			const auto teb = process.map_memory(4096, PROT_READ | PROT_WRITE);
			check(teb < 0x100000000ULL, "x86 allocation left the 32-bit address space");
			const uint8_t self[] = {uint8_t(teb), uint8_t(teb >> 8), uint8_t(teb >> 16), uint8_t(teb >> 24)};
			process.write_memory(teb + 0x18, self);
			process.set_teb(teb);
			const auto linear = process.call(slot(2), {}, timeout);
			check(linear.stop == raven::NativeStop::returned && linear.value == teb, "FS:[0x18] does not reach the TEB self pointer");

			process.add_api_trap(image_base + trap_rva, 8);
			rejected([&] { process.add_api_trap(slot(0), 3); });
			const auto stopped = process.call(slot(3), {}, timeout);
			check(stopped.stop == raven::NativeStop::api && stopped.value == image_base + trap_rva, "x86 API trap was not captured");
			check(process.api_arguments(2) == std::vector<uint64_t>{5, 7}, "x86 API arguments differ");
			const auto before = process.context();
			const auto scratch = process.map_memory(4096, PROT_READ | PROT_WRITE);
			check(scratch < 0x100000000ULL && process.context().registers.cs == before.registers.cs &&
				process.context().registers.rsp == before.registers.rsp, "host memory operation disturbed the paused x86 guest");
			process.unmap_memory(scratch);
			rejected([&] { process.map_memory(4096, PROT_READ, 0x100000000ULL); });
			process.return_api(99);
			const auto finished = process.resume(timeout);
			check(finished.stop == raven::NativeStop::returned && finished.value == 99, "x86 API return or callee cleanup differs");

			rejected([&] { process.enter_nt_service(0, 0); });
			rejected([&] { process.complete_debug_print(0); });
		}
		{
			const raven::PEImage image(fixture());
			raven::LoadedImage loaded(image, image.image_base);
			raven::LoadedImage *images[] = {&loaded};
			raven::NativeProcess process(images, argv[1], timeout);
			rejected([&] { process.set_teb(0x10000); });
		}
		{
			const raven::PEImage image(fixture());
			raven::LoadedImage loaded(image, image.image_base);
			raven::LoadedImage *images[] = {&loaded};
			raven::NativeProcess process(images, argv[1], timeout, raven::NativeMode::x86);
			const auto unset = process.call(slot(2), {}, timeout);
			check(unset.stop == raven::NativeStop::fault && unset.signal == SIGSEGV, "FS access succeeded before a TEB descriptor existed");
		}
		no_children();
		std::cout << "PE32 compatibility-mode calls, stdcall frames, FS TEB, API traps and host memory operations verified\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
