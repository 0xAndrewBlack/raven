#include "msvcrt_api.h"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <sys/mman.h>

namespace raven {

namespace {

constexpr std::array<std::string_view, 17> names{"_XcptFilter", "__getmainargs", "__p__commode", "__p__fmode",
	"__set_app_type", "__setusermatherr", "_acmdln", "_adjust_fdiv", "_c_exit", "_cexit", "_controlfp",
	"_except_handler3", "_exit", "_initterm", "exit", "rand", "srand"};
constexpr std::array<std::string_view, 2> variables{"_acmdln", "_adjust_fdiv"};

}

NativeCRT::NativeCRT(NativeProcess &process, NativeEnvironment &environment) : process(process), environment(environment)
{
	if (process.mode() != NativeMode::x86)
		throw std::runtime_error("the native CRT provider is x86 only");
}

std::span<const std::string_view> NativeCRT::exports()
{
	static const auto sorted = [] {
		auto copy = names;
		std::sort(copy.begin(), copy.end());
		return copy;
	}();
	return sorted;
}

std::span<const std::string_view> NativeCRT::data_exports()
{
	static const auto sorted = [] {
		auto copy = variables;
		std::sort(copy.begin(), copy.end());
		return copy;
	}();
	return sorted;
}

void NativeCRT::set_call(std::function<NativeResult(uint64_t, std::span<const uint64_t>)> caller)
{
	invoke = std::move(caller);
}

void NativeCRT::write32(uint64_t address, uint32_t value)
{
	const uint8_t bytes[4] = {uint8_t(value), uint8_t(value >> 8), uint8_t(value >> 16), uint8_t(value >> 24)};
	process.write_memory(address, bytes);
}

void NativeCRT::initialize(const std::function<uint64_t(std::string_view)> &address)
{
	globals = process.map_memory(4096, PROT_READ | PROT_WRITE);
	// _acmdln points at the process ANSI command line; _adjust_fdiv reports a correct FDIV unit.
	write32(address("_acmdln"), uint32_t(environment.command_line()));
	write32(address("_adjust_fdiv"), 0);
}

bool NativeCRT::dispatch(std::string_view name)
{
	if (std::find(names.begin(), names.end(), name) == names.end() || std::find(variables.begin(), variables.end(), name) != variables.end())
		return false;
	if (name == "__set_app_type" || name == "__setusermatherr") {
		process.api_arguments(1);
		process.return_api(0);
	} else if (name == "__p__fmode" || name == "__p__commode") {
		process.api_arguments(0);
		process.return_api(globals + (name == "__p__fmode" ? 0 : 4));
	} else if (name == "_controlfp") {
		const auto args = process.api_arguments(2);
		const auto mask = uint32_t(args[1]);
		control_word = (control_word & ~mask) | (uint32_t(args[0]) & mask);
		process.return_api(control_word);
	} else if (name == "_initterm") {
		const auto args = process.api_arguments(2);
		if (args[0] > args[1] || (args[1] - args[0]) / 4 > 4096)
			throw std::runtime_error("native _initterm table is invalid");
		if (!invoke)
			throw std::runtime_error("native CRT callbacks are not connected");
		for (uint64_t cursor = args[0]; cursor < args[1]; cursor += 4) {
			const auto bytes = process.read_memory(cursor, 4);
			const uint64_t target = uint64_t(bytes[0]) | uint64_t(bytes[1]) << 8 | uint64_t(bytes[2]) << 16 | uint64_t(bytes[3]) << 24;
			if (!target)
				continue;
			const auto result = invoke(target, {});
			if (result.stop != NativeStop::returned)
				throw result;
		}
		process.return_api(0);
	} else if (name == "__getmainargs") {
		const auto args = process.api_arguments(5);
		// argv holds one pointer per space-separated token of the ANSI command line, honoring double quotes.
		const auto command = environment.command_line();
		std::string line;
		for (uint64_t at = command;; ++at) {
			const auto byte = process.read_memory(at, 1)[0];
			if (!byte || line.size() > 32768)
				break;
			line.push_back(char(byte));
		}
		std::vector<std::string> tokens;
		for (size_t at = 0; at < line.size();) {
			while (at < line.size() && (line[at] == ' ' || line[at] == '\t'))
				++at;
			if (at >= line.size())
				break;
			std::string token;
			bool quoted = false;
			for (; at < line.size() && (quoted || (line[at] != ' ' && line[at] != '\t')); ++at) {
				if (line[at] == '"')
					quoted = !quoted;
				else
					token.push_back(line[at]);
			}
			tokens.push_back(token);
		}
		size_t size = (tokens.size() + 2) * 4 + 4;
		for (const auto &token : tokens)
			size += token.size() + 1;
		const auto block = process.map_memory((size + 4095) & ~size_t(4095), PROT_READ | PROT_WRITE);
		std::vector<uint8_t> bytes((size + 4095) & ~size_t(4095));
		size_t strings = (tokens.size() + 2) * 4;
		for (size_t index = 0; index < tokens.size(); ++index) {
			const auto pointer = uint32_t(block + strings);
			for (size_t part = 0; part < 4; ++part)
				bytes[index * 4 + part] = uint8_t(pointer >> (part * 8));
			std::copy(tokens[index].begin(), tokens[index].end(), bytes.begin() + ptrdiff_t(strings));
			strings += tokens[index].size() + 1;
		}
		// env is an empty NULL-terminated array placed right after argv's terminator.
		process.write_memory(block, bytes);
		write32(args[0], uint32_t(tokens.size()));
		write32(args[1], uint32_t(block));
		write32(args[2], uint32_t(block + (tokens.size() + 1) * 4));
		arguments_block = block;
		process.return_api(0);
	} else if (name == "_cexit" || name == "_c_exit") {
		process.api_arguments(0);
		process.return_api(0);
	} else if (name == "rand") {
		process.api_arguments(0);
		seed = seed * 214013U + 2531011U;
		process.return_api((seed >> 16) & 0x7fff);
	} else if (name == "srand") {
		seed = uint32_t(process.api_arguments(1)[0]);
		process.return_api(0);
	} else if (name == "_XcptFilter") {
		process.api_arguments(2);
		process.return_api(0);
	} else if (name == "_except_handler3") {
		// ExceptionContinueSearch until structured exception dispatch exists for x86 guests.
		process.api_arguments(4);
		process.return_api(1);
	} else {
		return false;
	}
	return true;
}

}
