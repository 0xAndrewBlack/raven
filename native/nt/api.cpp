#include "api.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace raven {

namespace {

bool memory_error(const std::runtime_error &failure)
{
	const std::string_view message = failure.what();
	return message.find("readable") != message.npos || message.find("writable") != message.npos;
}

}

ApiCall::ApiCall(NativeProcess &process, NativeEnvironment &environment, std::vector<uint64_t> arguments)
	: process(process), environment(environment), arguments(std::move(arguments)) {}

void ApiCall::fail(uint32_t error, uint64_t value)
{
	environment.set_last_error(error);
	result = value;
}

uint32_t ApiCall::last_error() const
{
	return environment.last_error();
}

void ApiCall::set_last_error(uint32_t error)
{
	environment.set_last_error(error);
}

std::vector<uint8_t> ApiCall::read(uint64_t address, size_t size) const
{
	if (!size)
		return {};
	try {
		return process.read_memory(address, size);
	} catch (const std::runtime_error &failure) {
		if (!memory_error(failure))
			throw;
		throw ApiFault{};
	}
}

void ApiCall::write(uint64_t address, std::span<const uint8_t> bytes) const
{
	if (bytes.empty())
		return;
	try {
		process.write_memory(address, bytes);
	} catch (const std::runtime_error &failure) {
		if (!memory_error(failure))
			throw;
		throw ApiFault{};
	}
}

std::u16string ApiCall::wide(uint64_t address, size_t limit) const
{
	std::u16string text;
	// Read page-bounded chunks so a string ending just before unmapped memory is still readable.
	while (text.size() <= limit) {
		const size_t room = 4096 - (address + text.size() * 2) % 4096;
		const auto bytes = read(address + text.size() * 2, room & 1 ? room - 1 : room);
		for (size_t at = 0; at + 1 < bytes.size(); at += 2) {
			const char16_t character = char16_t(bytes[at] | bytes[at + 1] << 8);
			if (!character)
				return text;
			text.push_back(character);
		}
	}
	throw ApiFault{};
}

std::string ApiCall::narrow(uint64_t address, size_t limit) const
{
	std::string text;
	while (text.size() <= limit) {
		const size_t room = 4096 - (address + text.size()) % 4096;
		const auto bytes = read(address + text.size(), room);
		for (const auto byte : bytes) {
			if (!byte)
				return text;
			text.push_back(char(byte));
		}
	}
	throw ApiFault{};
}

size_t ApiCall::put_wide(uint64_t address, std::u16string_view text, size_t capacity) const
{
	if (capacity > text.size()) {
		std::vector<uint8_t> bytes((text.size() + 1) * 2);
		std::memcpy(bytes.data(), text.data(), text.size() * 2);
		write(address, bytes);
	}
	return text.size();
}

size_t ApiCall::put_narrow(uint64_t address, std::string_view text, size_t capacity) const
{
	if (capacity > text.size()) {
		std::vector<uint8_t> bytes(text.size() + 1);
		std::memcpy(bytes.data(), text.data(), text.size());
		write(address, bytes);
	}
	return text.size();
}

void ApiRegistry::add(std::string_view name, uint32_t arguments, ApiHandler handler)
{
	if (!entries.emplace(std::string(name), Entry{arguments, std::move(handler)}).second)
		throw std::runtime_error("native API registered twice: " + std::string(name));
}

bool ApiRegistry::dispatch(NativeProcess &process, NativeEnvironment &environment, std::string_view name) const
{
	const auto found = entries.find(std::string(name));
	if (found == entries.end())
		return false;
	ApiCall call(process, environment, process.api_arguments(found->second.arguments));
	try {
		found->second.handler(call);
	} catch (const ApiFault &) {
		call.fail(998);
	}
	process.return_api(call.result);
	return true;
}

}
