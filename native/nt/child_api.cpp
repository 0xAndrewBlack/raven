#include "child_process.h"
#include "file_objects.h"
#include "kernel_context.h"
#include "text.h"

#include <algorithm>
#include <fstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace raven {

namespace {

constexpr uint64_t current_process = UINT64_MAX;
constexpr uint32_t create_suspended = 0x4, startf_use_std_handles = 0x100;

// A pipe is a connected pair of sockets with one direction closed on each end, which lets a reader look at bytes without taking them.
bool make_pipe(int &reader, int &writer)
{
	int pair[2];
	if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair))
		return false;
	::shutdown(pair[0], SHUT_WR);
	::shutdown(pair[1], SHUT_RD);
	reader = pair[0];
	writer = pair[1];
	return true;
}

// The program name a command line starts with: quoted, or up to the first blank.
std::u16string first_word(std::u16string_view line)
{
	size_t start = line.find_first_not_of(u" \t");
	if (start == line.npos)
		return {};
	if (line[start] == u'"') {
		const auto end = line.find(u'"', start + 1);
		return std::u16string(line.substr(start + 1, end == line.npos ? line.npos : end - start - 1));
	}
	const auto end = line.find_first_of(u" \t", start);
	return std::u16string(line.substr(start, end == line.npos ? line.npos : end - start));
}

}

std::shared_ptr<ProcessObject> start_program(KernelContext &context, const std::u16string &application, const std::u16string &line,
	const std::u16string &directory, const int (&standard)[3], uint32_t &error)
{
	auto &paths = context.paths;
	const auto name = application.empty() ? first_word(line) : application;
	if (name.empty()) {
		error = 87;
		return nullptr;
	}
	const auto own_directory = context.launch.image_path.substr(0, std::max<size_t>(context.launch.image_path.find_last_of(u'\\'), 0));
	std::vector<std::u16string> candidates;
	const bool qualified = name.find_first_of(u"\\/:") != name.npos;
	const bool extension = name.find(u'.') != name.npos;
	const auto add = [&](std::u16string path) {
		candidates.push_back(path);
		if (!extension)
			candidates.push_back(path + u".exe");
	};
	if (qualified) {
		add(name);
	} else {
		add(own_directory + u"\\" + name);
		add(paths.current() + u"\\" + name);
		add(u"C:\\Windows\\System32\\" + name);
		add(u"C:\\Windows\\" + name);
	}
	std::optional<NativePaths::Resolved> image;
	for (const auto &candidate : candidates)
		if (const auto resolved = paths.resolve(candidate); resolved && resolved->exists && std::filesystem::is_regular_file(resolved->host)) {
			image = resolved;
			break;
		}
	if (!image) {
		error = 2;
		return nullptr;
	}
	char magic[2] = {};
	std::ifstream file(image->host, std::ios::binary);
	file.read(magic, 2);
	if (magic[0] != 'M' || magic[1] != 'Z') {
		error = 193;
		return nullptr;
	}
	ChildLaunch launch;
	launch.image = image->host;
	launch.command_line = line.empty() ? u"\"" + name + u"\"" : line;
	launch.directory = directory.empty() ? paths.current() : directory;
	std::copy(std::begin(standard), std::end(standard), launch.standard);
	return spawn_child(launch, error);
}

void register_child_process_api(ApiRegistry &registry, KernelContext &context)
{
	auto &objects = context.objects;
	auto &paths = context.paths;
	context.threads.set_external(host_events_pending);
	const auto descriptor_of = [&objects](uint64_t handle) -> int {
		if (const auto file = objects.object_as<FileObject>(handle))
			return file->descriptor;
		return objects.descriptor(handle);
	};

	registry.add("CreatePipe", 4, [&objects](ApiCall &call) {
		int reader, writer;
		if (!call[0] || !call[1] || !make_pipe(reader, writer)) {
			call.fail(call[0] && call[1] ? 8 : 87);
			return;
		}
		const auto read_end = objects.add_object(std::make_shared<FileObject>(reader, 0x80000000U, false, std::filesystem::path(), std::u16string(), 0));
		const auto write_end = objects.add_object(std::make_shared<FileObject>(writer, 0x40000000U, false, std::filesystem::path(), std::u16string(), 0));
		if (read_end.status || write_end.status) {
			if (!read_end.status)
				objects.close(read_end.value);
			if (!write_end.status)
				objects.close(write_end.value);
			call.fail(4);
			return;
		}
		call.store_pointer(call[0], read_end.value);
		call.store_pointer(call[1], write_end.value);
		call.ret(1);
	});
	registry.add("PeekNamedPipe", 6, [descriptor_of, &objects](ApiCall &call) {
		const auto file = objects.object_as<FileObject>(call[0]);
		if (!file || !file->readable() || file->directory) {
			call.fail(6);
			return;
		}
		int available = 0;
		if (::ioctl(file->descriptor, FIONREAD, &available) || available < 0) {
			call.fail(109);
			return;
		}
		uint32_t copied = 0;
		const size_t wanted = call[1] ? std::min<size_t>(call.u32(2), 1 << 20) : 0;
		if (wanted) {
			std::vector<uint8_t> bytes(wanted);
			const auto count = ::recv(file->descriptor, bytes.data(), bytes.size(), MSG_PEEK | MSG_DONTWAIT);
			if (count > 0) {
				call.write(call[1], std::span<const uint8_t>(bytes.data(), size_t(count)));
				copied = uint32_t(count);
			}
		}
		if (call[3])
			call.store<uint32_t>(call[3], copied);
		if (call[4])
			call.store<uint32_t>(call[4], uint32_t(available));
		if (call[5])
			call.store<uint32_t>(call[5], 0);
		(void)descriptor_of;
		call.ret(1);
	});

	registry.add("CreateProcessW", 10, [&, descriptor_of](ApiCall &call) {
		if (call.u32(5) & create_suspended || call[6]) {
			// A suspended start and a private environment block are not carried to the child yet: say so rather than start it differently.
			call.fail(50);
			return;
		}
		if (!call[9]) {
			call.fail(87);
			return;
		}
		const auto application = call[0] ? call.wide(call[0]) : std::u16string();
		const auto line = call[1] ? call.wide(call[1]) : std::u16string();
		auto directory = call[7] ? paths.full(call.wide(call[7])) : std::u16string();
		int standard[3] = {0, 1, 2};
		if (call[8]) {
			// STARTUPINFOW: after the flags come the show command and two reserved fields, then the three standard handles.
			const size_t width = call.pointer_width();
			const size_t flags_at = 4 + 3 * width + 28;
			const size_t handles_at = ((flags_at + 8 + width - 1) / width) * width + width;
			if (call.load<uint32_t>(call[8] + flags_at) & startf_use_std_handles)
				for (size_t index = 0; index < 3; ++index) {
					const auto handle = call.load_pointer(call[8] + handles_at + index * width);
					const auto widened = width == 4 && handle == 0xffffffffULL ? UINT64_MAX : handle;
					if (widened == UINT64_MAX || !widened)
						continue;
					const int descriptor = descriptor_of(widened);
					if (descriptor < 0) {
						call.fail(6);
						return;
					}
					standard[index] = descriptor;
				}
		}
		uint32_t error = 0;
		const auto child = start_program(context, application, line, directory, standard, error);
		if (!child) {
			call.fail(error);
			return;
		}
		const auto process_handle = objects.add_object(child);
		const auto thread_handle = objects.add_object(std::make_shared<ChildThreadObject>(child));
		if (process_handle.status || thread_handle.status) {
			child->terminate(1);
			call.fail(4);
			return;
		}
		const size_t width = call.pointer_width();
		call.store_pointer(call[9], process_handle.value);
		call.store_pointer(call[9] + width, thread_handle.value);
		call.store<uint32_t>(call[9] + 2 * width, uint32_t(child->pid));
		call.store<uint32_t>(call[9] + 2 * width + 4, uint32_t(child->pid));
		call.ret(1);
	});
	registry.add("GetExitCodeProcess", 2, [&objects](ApiCall &call) {
		if (!call[1]) {
			call.fail(87);
			return;
		}
		if (call[0] == current_process) {
			call.store<uint32_t>(call[1], 259);
			call.ret(1);
			return;
		}
		const auto child = objects.object_as<ProcessObject>(call[0]);
		if (!child) {
			call.fail(6);
			return;
		}
		call.store<uint32_t>(call[1], child->exit_code());
		call.ret(1);
	});
	registry.add("TerminateProcess", 2, [&objects](ApiCall &call) {
		if (call[0] == current_process) {
			call.process.abandon_call();
			throw ProcessExit{call.u32(1), 0};
		}
		const auto child = objects.object_as<ProcessObject>(call[0]);
		if (!child) {
			call.fail(6);
			return;
		}
		child->terminate(call.u32(1));
		call.ret(1);
	});
	registry.add("GetProcessId", 1, [&objects](ApiCall &call) {
		if (call[0] == current_process) {
			call.ret(1);
			return;
		}
		const auto child = objects.object_as<ProcessObject>(call[0]);
		if (!child) {
			call.fail(6);
			return;
		}
		call.ret(uint32_t(child->pid));
	});
	// A child has no message queue the parent could watch; it counts as idle from the start.
	registry.add("WaitForInputIdle", 2, [&objects](ApiCall &call) {
		if (!objects.object_as<ProcessObject>(call[0])) {
			call.fail(6, UINT32_MAX);
			return;
		}
		call.ret(0);
	});
}

}
