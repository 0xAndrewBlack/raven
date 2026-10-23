#include "access_token.h"
#include "child_process.h"
#include "elevation.h"
#include "file_objects.h"
#include "kernel_context.h"
#include "text.h"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <cstdio>
#include <fstream>
#include <sys/mman.h>
#include <map>
#include <sstream>
#include <unistd.h>

namespace raven {

namespace {

constexpr uint64_t current_process = UINT64_MAX;

// A list the toolhelp calls walk: entries are built when the snapshot is taken.
class Snapshot : public KernelObject {
public:
	struct Process {
		uint32_t id, parent;
		std::u16string name;
	};
	struct Module {
		uint64_t base;
		uint32_t size;
		std::u16string name, path;
	};
	std::vector<Process> processes;
	std::vector<Module> modules;
	size_t next_process = 0, next_module = 0;
};

// Window stations and desktops are named containers that windows would live in; here every window lives on the one display, so these only
// keep names and which ones the process has selected.
class WindowStation : public KernelObject {
public:
	std::u16string_view type_name() const override { return u"WindowStation"; }
	std::u16string name = u"WinSta0";
};
class Desktop : public KernelObject {
public:
	std::u16string_view type_name() const override { return u"Desktop"; }
	std::u16string name = u"Default";
};

uint64_t filetime_now()
{
	timespec now{};
	clock_gettime(CLOCK_REALTIME, &now);
	return (uint64_t(now.tv_sec) + 11644473600ULL) * 10000000ULL + uint64_t(now.tv_nsec) / 100;
}

}

// CPU time a running child has used so far, in nanoseconds; 0 once the host no longer lists it.
static uint64_t child_cpu_nanoseconds(pid_t pid)
{
	std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
	std::string text;
	std::getline(stat, text);
	const auto close = text.rfind(')');
	if (close == std::string::npos)
		return 0;
	std::istringstream fields(text.substr(close + 2));
	std::string field;
	uint64_t user = 0, system = 0;
	for (int index = 3; fields >> field; ++index) {
		if (index == 14)
			user = std::strtoull(field.c_str(), nullptr, 10);
		else if (index == 15) {
			system = std::strtoull(field.c_str(), nullptr, 10);
			break;
		}
	}
	return (user + system) * (1000000000ULL / uint64_t(sysconf(_SC_CLK_TCK)));
}

// The rights a handle holds as Windows reports them: the generic rights of the request mapped to the specific ones of the object's type.
static uint32_t granted_access(std::u16string_view type, uint32_t requested)
{
	struct Mapping { std::u16string_view type; uint32_t read, write, execute, all; };
	static constexpr Mapping mappings[] = {
		{u"File", 0x120089, 0x120116, 0x1200a0, 0x1f01ff}, {u"Section", 0x20005, 0x20002, 0x20008, 0xf001f},
		{u"Process", 0x20410, 0x20bea, 0x120000, 0x1fffff}, {u"Thread", 0x20048, 0x20037, 0x120000, 0x1fffff},
		{u"Event", 0x20001, 0x20002, 0x120000, 0x1f0003}, {u"Mutant", 0x20001, 0x20000, 0x120000, 0x1f0001},
		{u"Semaphore", 0x20001, 0x20002, 0x120000, 0x1f0003}, {u"Key", 0x20019, 0x20006, 0x20019, 0xf003f},
		{u"Token", 0x20008, 0x200e0, 0x20000, 0xf01ff}, {u"Job", 0x20004, 0x2000b, 0x120000, 0x1f003f},
		{u"IoCompletion", 0x20001, 0x20002, 0x120000, 0x1f0003}};
	const auto found = std::find_if(std::begin(mappings), std::end(mappings), [&](const Mapping &item) { return item.type == type; });
	if (found == std::end(mappings))
		return requested & 0x01ffffffU;
	uint32_t granted = requested & 0x00ffffffU;
	if (requested & (0x10000000U | 0x02000000U))
		granted |= found->all;
	if (requested & 0x80000000U)
		granted |= found->read;
	if (requested & 0x40000000U)
		granted |= found->write;
	if (requested & 0x20000000U)
		granted |= found->execute;
	return granted;
}

void register_process_info_api(ApiRegistry &registry, KernelContext &context)
{
	auto &objects = context.objects;
	auto &modules = context.modules;
	const uint64_t started = filetime_now();
	// A 32-bit program passes the current process handle as the 32-bit -1, which reaches here without its sign.
	const auto is_self = [&objects](uint64_t handle) {
		return handle == current_process || handle == 0xffffffffU || objects.object_as<SelfProcessObject>(handle) != nullptr;
	};

	registry.add("OpenProcess", 3, [&objects](ApiCall &call) {
		const uint32_t id = call.u32(2);
		if (id == uint32_t(::getpid())) {
			const auto made = objects.add_object(std::make_shared<SelfProcessObject>());
			if (made.status) {
				call.fail(4, 0);
				return;
			}
			call.ret(made.value);
			return;
		}
		auto child = find_child(pid_t(id));
		// Any other running instance of the runtime can be named too: the parent that started this process, or a process a sibling started.
		if (!child && runtime_process_alive(pid_t(id)))
			child = std::make_shared<ProcessObject>(pid_t(id), true);
		if (!child) {
			call.fail(87, 0);
			return;
		}
		const auto made = objects.add_object(child);
		if (made.status) {
			call.fail(4, 0);
			return;
		}
		call.ret(made.value);
	});
	// A 32-bit program runs under WOW64 on the 64-bit system; a 64-bit one does not.
	registry.add("IsWow64Process", 2, [is_self](ApiCall &call) {
		if (!call[1]) {
			call.fail(87);
			return;
		}
		call.store<uint32_t>(call[1], call.pointer_width() == 4 && is_self(call[0]) ? 1 : 0);
		call.ret(1);
	});
	registry.add("IsWow64Process2", 3, [](ApiCall &call) {
		if (!call[1]) {
			call.fail(87);
			return;
		}
		call.store<uint16_t>(call[1], call.pointer_width() == 4 ? 0x14c : 0);
		if (call[2])
			call.store<uint16_t>(call[2], 0x8664);
		call.ret(1);
	});
	// The machine runs x64 programs in user and kernel mode and 32-bit x86 ones in the WOW64 container; nothing else.
	registry.add("GetMachineTypeAttributes", 2, [](ApiCall &call) {
		if (!call[1]) {
			call.ret(0x80070057U);
			return;
		}
		const uint16_t machine = uint16_t(call.u32(0));
		call.store<uint32_t>(call[1], machine == 0x8664 ? 3 : machine == 0x14c ? 5 : 0);
		call.ret(0);
	});
	registry.add("GetProcessTimes", 5, [started, is_self, &objects](ApiCall &call) {
		if (const auto child = objects.object_as<ProcessObject>(call[0]); child && call[1] && call[2] && call[3] && call[4]) {
			call.store<uint64_t>(call[1], started);
			call.store<uint64_t>(call[2], 0);
			call.store<uint64_t>(call[3], 0);
			call.store<uint64_t>(call[4], child_cpu_nanoseconds(child->pid) / 100);
			call.ret(1);
			return;
		}
		if (!is_self(call[0]) || !call[1] || !call[2] || !call[3] || !call[4]) {
			call.fail(call[1] && is_self(call[0]) ? 87 : 6);
			return;
		}
		timespec cpu{};
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu);
		call.store<uint64_t>(call[1], started);
		call.store<uint64_t>(call[2], 0);
		call.store<uint64_t>(call[3], 0);
		call.store<uint64_t>(call[4], (uint64_t(cpu.tv_sec) * 1000000000ULL + uint64_t(cpu.tv_nsec)) / 100);
		call.ret(1);
	});
	registry.add("GetThreadTimes", 5, [started](ApiCall &call) {
		if (!call[1] || !call[2] || !call[3] || !call[4]) {
			call.fail(87);
			return;
		}
		timespec cpu{};
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu);
		call.store<uint64_t>(call[1], started);
		call.store<uint64_t>(call[2], 0);
		call.store<uint64_t>(call[3], 0);
		call.store<uint64_t>(call[4], (uint64_t(cpu.tv_sec) * 1000000000ULL + uint64_t(cpu.tv_nsec)) / 100);
		call.ret(1);
	});
	// Cycle counts are taken as CPU time at a nominal 1 GHz, so one nanosecond is one cycle.
	registry.add("QueryThreadCycleTime", 2, [](ApiCall &call) {
		if (!call[1]) {
			call.fail(87);
			return;
		}
		timespec cpu{};
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu);
		call.store<uint64_t>(call[1], uint64_t(cpu.tv_sec) * 1000000000ULL + uint64_t(cpu.tv_nsec));
		call.ret(1);
	});
	registry.add("QueryProcessCycleTime", 2, [is_self, &objects](ApiCall &call) {
		if (const auto child = objects.object_as<ProcessObject>(call[0]); child && call[1]) {
			call.store<uint64_t>(call[1], child_cpu_nanoseconds(child->pid));
			call.ret(1);
			return;
		}
		if (!call[1] || !is_self(call[0])) {
			call.fail(call[1] ? 6 : 87);
			return;
		}
		timespec cpu{};
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu);
		call.store<uint64_t>(call[1], uint64_t(cpu.tv_sec) * 1000000000ULL + uint64_t(cpu.tv_nsec));
		call.ret(1);
	});
	registry.add("GetSystemTimes", 3, [](ApiCall &call) {
		timespec uptime{};
		clock_gettime(CLOCK_BOOTTIME, &uptime);
		const uint64_t total = (uint64_t(uptime.tv_sec) * 1000000000ULL + uint64_t(uptime.tv_nsec)) / 100;
		if (call[0])
			call.store<uint64_t>(call[0], total / 2);
		if (call[1])
			call.store<uint64_t>(call[1], 0);
		if (call[2])
			call.store<uint64_t>(call[2], total / 2);
		call.ret(1);
	});
	registry.add("RtlCaptureStackBackTrace", 4, [](ApiCall &call) {
		if (call[3])
			call.store<uint32_t>(call[3], 0);
		call.ret(0);
	});

	// The window station and desktop: one of each, always visible.
	auto station = std::make_shared<uint64_t>(0);
	registry.add("GetProcessWindowStation", 0, [&objects, station](ApiCall &call) {
		if (!*station) {
			const auto made = objects.add_object(std::make_shared<WindowStation>());
			if (made.status) {
				call.fail(4, 0);
				return;
			}
			*station = made.value;
		}
		call.ret(*station);
	});
	// The names a program creates are kept so that opening one finds it again; the first station and desktop are the default ones.
	auto stations = std::make_shared<std::map<std::u16string, uint64_t>>();
	auto desktops = std::make_shared<std::map<std::u16string, uint64_t>>();
	auto desktop_now = std::make_shared<uint64_t>(0);
	const auto make_named = [&objects](ApiCall &call, auto object, const std::u16string &name, std::shared_ptr<std::map<std::u16string, uint64_t>> table) {
		object->name = name;
		const auto made = objects.add_object(object);
		if (made.status) {
			call.fail(4, 0);
			return;
		}
		(*table)[name] = made.value;
		call.ret(made.value);
	};
	registry.add("CreateWindowStationW", 4, [make_named, stations](ApiCall &call) {
		make_named(call, std::make_shared<WindowStation>(), call[0] ? call.wide(call[0], 256) : u"WinSta0", stations);
	});
	registry.add("CreateDesktopW", 6, [make_named, desktops](ApiCall &call) {
		make_named(call, std::make_shared<Desktop>(), call[0] ? call.wide(call[0], 256) : u"Default", desktops);
	});
	registry.add("OpenWindowStationW", 3, [stations](ApiCall &call) {
		const auto found = stations->find(call[0] ? call.wide(call[0], 256) : u"WinSta0");
		if (found == stations->end()) {
			call.fail(2, 0);
			return;
		}
		call.ret(found->second);
	});
	registry.add("OpenDesktopW", 4, [desktops](ApiCall &call) {
		const auto found = desktops->find(call[0] ? call.wide(call[0], 256) : u"Default");
		if (found == desktops->end()) {
			call.fail(2, 0);
			return;
		}
		call.ret(found->second);
	});
	registry.add("SetProcessWindowStation", 1, [&objects, station](ApiCall &call) {
		if (!objects.object_as<WindowStation>(call[0])) {
			call.fail(6);
			return;
		}
		*station = call[0];
		call.ret(1);
	});
	registry.add("CloseWindowStation", 1, [&objects](ApiCall &call) { call.ret(objects.close(call[0]) == 0); });
	registry.add("CloseDesktop", 1, [&objects](ApiCall &call) { call.ret(objects.close(call[0]) == 0); });
	registry.add("SetThreadDesktop", 1, [&objects, desktop_now](ApiCall &call) {
		if (!objects.object_as<Desktop>(call[0])) {
			call.fail(6);
			return;
		}
		*desktop_now = call[0];
		call.ret(1);
	});
	registry.add("GetThreadDesktop", 1, [&objects, desktop_now, desktops](ApiCall &call) {
		if (!*desktop_now) {
			const auto made = objects.add_object(std::make_shared<Desktop>());
			if (made.status) {
				call.fail(4, 0);
				return;
			}
			*desktop_now = made.value;
			(*desktops)[u"Default"] = made.value;
		}
		call.ret(*desktop_now);
	});
	// The names come back as wide or ANSI text by the form called.
	for (const bool wide : {true, false})
		registry.add(wide ? "GetUserObjectInformationW" : "GetUserObjectInformationA", 5, [&objects, wide](ApiCall &call) {
			const auto named = objects.object_as<WindowStation>(call[0]);
			const auto desktop = objects.object_as<Desktop>(call[0]);
			if (!named && !desktop) {
				call.fail(6);
				return;
			}
			std::vector<uint8_t> data;
			switch (call.u32(1)) {
			case 1: {
				// USEROBJECTFLAGS: the window station is visible (WSF_VISIBLE) except to a process in the services' session.
				data.assign(12, 0);
				data[8] = named && process_noninteractive() ? 0 : 1;
				break;
			}
			case 2: case 3: {
				const std::u16string text = call.u32(1) == 2 ? (named ? named->name : desktop->name) : named ? u"WindowStation" : u"Desktop";
				if (wide) {
					data.resize((text.size() + 1) * 2);
					std::memcpy(data.data(), text.data(), text.size() * 2);
				} else {
					const auto narrow = to_utf8(text);
					data.assign(narrow.begin(), narrow.end());
					data.push_back(0);
				}
				break;
			}
			default:
				call.fail(87);
				return;
			}
			if (call[4])
				call.store<uint32_t>(call[4], uint32_t(data.size()));
			if (!call[2] || call.u32(3) < data.size()) {
				call.fail(122);
				return;
			}
			call.write(call[2], data);
			call.ret(1);
		});

	// The module list of the program: the executable first, then the libraries, as psapi reports them.
	const auto module_list = [&modules, &context]() {
		std::vector<const PEModule *> list;
		list.push_back(&context.entry);
		for (const auto &[name, module] : modules.all())
			if (module.get() != &context.entry && !module->runtime_api)
				list.push_back(module.get());
		return list;
	};
	registry.add("EnumProcessModules", 4, [is_self, module_list](ApiCall &call) {
		if (!is_self(call[0]) || !call[3]) {
			call.fail(call[3] ? 6 : 87);
			return;
		}
		const auto list = module_list();
		const size_t width = call.pointer_width();
		call.store<uint32_t>(call[3], uint32_t(list.size() * width));
		const size_t fit = std::min<size_t>(list.size(), call.u32(2) / width);
		for (size_t index = 0; index < fit; ++index)
			call.store_pointer(call[1] + index * width, list[index]->loaded.base());
		call.ret(1);
	});
	registry.add("EnumProcessModulesEx", 5, [is_self, module_list](ApiCall &call) {
		if (!is_self(call[0]) || !call[3]) {
			call.fail(call[3] ? 6 : 87);
			return;
		}
		const auto list = module_list();
		const size_t width = call.pointer_width();
		call.store<uint32_t>(call[3], uint32_t(list.size() * width));
		const size_t fit = std::min<size_t>(list.size(), call.u32(2) / width);
		for (size_t index = 0; index < fit; ++index)
			call.store_pointer(call[1] + index * width, list[index]->loaded.base());
		call.ret(1);
	});
	const auto module_at = [module_list](uint64_t handle) -> const PEModule * {
		for (const auto *module : module_list())
			if (module->loaded.base() == handle)
				return module;
		return nullptr;
	};
	const auto base_name = [module_at, is_self](ApiCall &call, bool wide) {
		const auto *module = is_self(call[0]) ? module_at(call[1] ? call[1] : 0) : nullptr;
		if (!module && is_self(call[0]) && !call[1])
			module = nullptr;
		if (!module) {
			call.fail(is_self(call[0]) ? 126 : 6);
			return;
		}
		const auto text = from_utf8(module->name);
		const size_t capacity = call.u32(3);
		if (!call[2] || !capacity) {
			call.ret(0);
			return;
		}
		if (wide)
			call.ret(call.put_wide(call[2], text, capacity) > capacity ? capacity : std::min(text.size(), capacity - 1));
		else
			call.ret(call.put_narrow(call[2], to_utf8(text), capacity) > capacity ? capacity : std::min(text.size(), capacity - 1));
	};
	registry.add("GetModuleBaseNameW", 4, [base_name](ApiCall &call) { base_name(call, true); });
	registry.add("GetModuleBaseNameA", 4, [base_name](ApiCall &call) { base_name(call, false); });
	// MODULEINFO: the base, the size of the image and the entry point.
	registry.add("GetModuleInformation", 4, [is_self, module_at](ApiCall &call) {
		const auto *module = is_self(call[0]) ? module_at(call[1]) : nullptr;
		if (!module || !call[2]) {
			call.fail(module ? 87 : 6);
			return;
		}
		const size_t width = call.pointer_width();
		std::vector<uint8_t> info(width == 4 ? 12 : 24);
		const uint64_t base = module->loaded.base(), entry = module->loaded.base() + module->image.entry;
		const uint32_t size = module->image.image_size;
		std::memcpy(info.data(), &base, width);
		std::memcpy(info.data() + width, &size, 4);
		std::memcpy(info.data() + (width == 4 ? 8 : 16), &entry, width);
		call.write(call[2], info);
		call.ret(1);
	});
	// PROCESS_MEMORY_COUNTERS from the host's accounting of this process.
	registry.add("GetProcessMemoryInfo", 3, [is_self](ApiCall &call) {
		if (!is_self(call[0]) || !call[1]) {
			call.fail(call[1] ? 6 : 87);
			return;
		}
		uint64_t pages = 0, resident = 0;
		std::ifstream statm("/proc/self/statm");
		statm >> pages >> resident;
		const size_t width = call.pointer_width(), size = width == 4 ? 40 : 72;
		std::vector<uint8_t> counters(std::min<size_t>(call.u32(2), size));
		if (counters.size() < size) {
			call.fail(24);
			return;
		}
		const uint32_t cb = uint32_t(size);
		std::memcpy(counters.data(), &cb, 4);
		const uint64_t working = resident * 4096, committed = pages * 4096;
		const auto put = [&](size_t index, uint64_t value) { std::memcpy(counters.data() + 8 + (width == 4 ? 0 : 0) + index * width, &value, width); };
		put(0, working);
		put(1, working);
		put(6, committed);
		put(7, committed);
		call.write(call[1], counters);
		call.ret(1);
	});

	// Toolhelp: the process and module lists. The processes are this one and the children it started that still run.
	registry.add("CreateToolhelp32Snapshot", 2, [&objects, &context, module_list](ApiCall &call) {
		const uint32_t flags = call.u32(0);
		auto snapshot = std::make_shared<Snapshot>();
		if (flags & 2) {
			// Every running instance of the runtime is a Windows process here: the programs this one started, its parent, and the
			// processes those started in turn. The name is the program each one runs; its parent is the instance that started it.
			const auto image = context.launch.image_path;
			snapshot->processes.push_back({uint32_t(::getpid()), runtime_process_alive(::getppid()) ? uint32_t(::getppid()) : 0, image.substr(image.find_last_of(u'\\') + 1)});
			std::error_code error;
			for (const auto &entry : std::filesystem::directory_iterator("/proc", error)) {
				const auto name = entry.path().filename().string();
				if (name.empty() || !std::all_of(name.begin(), name.end(), [](char c) { return c >= '0' && c <= '9'; }))
					continue;
				const auto pid = pid_t(std::stol(name));
				if (pid == ::getpid() || !runtime_process_alive(pid))
					continue;
				std::ifstream arguments(entry.path() / "cmdline", std::ios::binary);
				std::string argument, last;
				while (std::getline(arguments, argument, '\0'))
					if (!argument.empty())
						last = argument;
				std::ifstream stat(entry.path() / "stat");
				std::string text;
				std::getline(stat, text);
				pid_t parent = 0;
				if (const auto close = text.rfind(')'); close != std::string::npos)
					std::sscanf(text.c_str() + close + 2, "%*c %d", &parent);
				snapshot->processes.push_back({uint32_t(pid), runtime_process_alive(parent) ? uint32_t(parent) : 0,
					from_utf8(std::filesystem::path(last).filename().string())});
			}
		}
		if (flags & 8)
			for (const auto *module : module_list()) {
				// The program's own path for the executable; the libraries beside it, or the system directory for those the runtime supplies.
				const auto name = from_utf8(module->name);
				const auto path = module == &context.entry ? context.launch.image_path : module->runtime_api ? u"C:\\Windows\\System32\\" + name :
					!module->file.empty() ? context.paths.dos(module->file) : context.paths.library_location(context.launch.image_path, name, context.entry.image.is_64);
				snapshot->modules.push_back({module->loaded.base(), module->image.image_size, name, path});
			}
		const auto made = objects.add_object(snapshot);
		if (made.status) {
			call.fail(4, UINT64_MAX);
			return;
		}
		call.ret(made.value);
	});
	// PROCESSENTRY32: sizes, the process and parent ids, the thread count and the file name; the default heap and module ids are zero.
	const auto process_entry = [](ApiCall &call, const Snapshot::Process &process, bool wide) {
		const size_t width = call.pointer_width();
		const size_t id_at = 8, heap_at = width == 4 ? 12 : 16, threads_at = heap_at + width + 4, parent_at = threads_at + 4, name_at = parent_at + 12;
		const size_t size = name_at + 260 * (wide ? 2 : 1);
		const uint32_t cb = call.load<uint32_t>(call[1]);
		if (cb < size - (width == 4 ? 0 : 0) && cb < name_at + 4) {
			call.fail(24);
			return false;
		}
		std::vector<uint8_t> entry(std::min<size_t>(cb, (size + width - 1) / width * width));
		std::memcpy(entry.data(), &cb, 4);
		std::memcpy(entry.data() + id_at, &process.id, 4);
		const uint32_t threads = 1;
		std::memcpy(entry.data() + threads_at, &threads, 4);
		std::memcpy(entry.data() + parent_at, &process.parent, 4);
		const int32_t priority = 8;
		std::memcpy(entry.data() + parent_at + 4, &priority, 4);
		for (size_t index = 0; index < process.name.size() && index < 259; ++index) {
			if (wide) {
				if (name_at + index * 2 + 2 <= entry.size())
					std::memcpy(entry.data() + name_at + index * 2, &process.name[index], 2);
			} else if (name_at + index < entry.size()) {
				entry[name_at + index] = char(process.name[index]);
			}
		}
		call.write(call[1], entry);
		return true;
	};
	const auto process_step = [&objects, process_entry](ApiCall &call, bool first, bool wide) {
		const auto snapshot = objects.object_as<Snapshot>(call[0]);
		if (!snapshot || !call[1]) {
			call.fail(snapshot ? 87 : 6);
			return;
		}
		if (first)
			snapshot->next_process = 0;
		if (snapshot->next_process >= snapshot->processes.size()) {
			call.fail(18);
			return;
		}
		if (!process_entry(call, snapshot->processes[snapshot->next_process], wide))
			return;
		++snapshot->next_process;
		call.ret(1);
	};
	registry.add("Process32FirstW", 2, [process_step](ApiCall &call) { process_step(call, true, true); });
	registry.add("Process32NextW", 2, [process_step](ApiCall &call) { process_step(call, false, true); });
	registry.add("Process32First", 2, [process_step](ApiCall &call) { process_step(call, true, false); });
	registry.add("Process32Next", 2, [process_step](ApiCall &call) { process_step(call, false, false); });
	// MODULEENTRY32: the base and size, the module handle, then the module name and the full path.
	const auto module_step = [&objects](ApiCall &call, bool first, bool wide) {
		const auto snapshot = objects.object_as<Snapshot>(call[0]);
		if (!snapshot || !call[1]) {
			call.fail(snapshot ? 87 : 6);
			return;
		}
		if (first)
			snapshot->next_module = 0;
		if (snapshot->next_module >= snapshot->modules.size()) {
			call.fail(18);
			return;
		}
		const auto &module = snapshot->modules[snapshot->next_module];
		const size_t width = call.pointer_width();
		const size_t base_at = width == 4 ? 20 : 24, size_at = base_at + width, handle_at = size_at + 4 + (width == 4 ? 0 : 4),
			name_at = handle_at + width, path_at = name_at + 256 * (wide ? 2 : 1), total = path_at + 260 * (wide ? 2 : 1);
		const uint32_t cb = call.load<uint32_t>(call[1]);
		std::vector<uint8_t> entry(std::min<size_t>(cb, total));
		if (entry.size() < path_at) {
			call.fail(24);
			return;
		}
		std::memcpy(entry.data(), &cb, 4);
		const uint32_t process = 1, one = 1;
		std::memcpy(entry.data() + 8, &process, 4);
		std::memcpy(entry.data() + 12, &one, 4);
		std::memcpy(entry.data() + 16, &one, 4);
		std::memcpy(entry.data() + base_at, &module.base, width);
		std::memcpy(entry.data() + size_at, &module.size, 4);
		std::memcpy(entry.data() + handle_at, &module.base, width);
		for (size_t index = 0; index < module.name.size() && index < 255; ++index) {
			if (wide) {
				if (name_at + index * 2 + 2 <= entry.size())
					std::memcpy(entry.data() + name_at + index * 2, &module.name[index], 2);
			} else if (name_at + index < entry.size()) {
				entry[name_at + index] = char(module.name[index]);
			}
		}
		for (size_t index = 0; index < module.path.size() && index < 259; ++index) {
			if (wide) {
				if (path_at + index * 2 + 2 <= entry.size())
					std::memcpy(entry.data() + path_at + index * 2, &module.path[index], 2);
			} else if (path_at + index < entry.size()) {
				entry[path_at + index] = char(module.path[index]);
			}
		}
		call.write(call[1], entry);
		++snapshot->next_module;
		call.ret(1);
	};
	registry.add("Module32FirstW", 2, [module_step](ApiCall &call) { module_step(call, true, true); });
	registry.add("Module32NextW", 2, [module_step](ApiCall &call) { module_step(call, false, true); });
	registry.add("Module32First", 2, [module_step](ApiCall &call) { module_step(call, true, false); });
	registry.add("Module32Next", 2, [module_step](ApiCall &call) { module_step(call, false, false); });
	// The path of a module in this process is the one GetModuleFileName reports; other processes do not expose their modules.
	for (const bool wide : {true, false})
		registry.add(wide ? "GetModuleFileNameExW" : "GetModuleFileNameExA", 4, [&registry, is_self, wide](ApiCall &call) {
			if (!is_self(call[0])) {
				call.fail(5);
				return;
			}
			const auto entry = registry.find(wide ? "GetModuleFileNameW" : "GetModuleFileNameA");
			if (!entry) {
				call.fail(5);
				return;
			}
			ApiCall module_call(call.process, call.environment, {call[1], call[2], call[3]});
			entry->second(module_call);
			call.ret(module_call.result);
		});
	// Every page the guest can address is resident: the host does not page guest memory out behind its back.
	registry.add("QueryWorkingSetEx", 3, [is_self](ApiCall &call) {
		if (!is_self(call[0])) {
			call.fail(5);
			return;
		}
		const size_t width = call.pointer_width(), count = call.u32(2) / (width * 2);
		for (size_t index = 0; index < count; ++index) {
			const uint64_t entry = call[1] + index * width * 2;
			const uint64_t attributes = 1 | (1ULL << 1 << 4) | (1ULL << 15);
			if (width == 4)
				call.store<uint32_t>(entry + 4, uint32_t(attributes));
			else
				call.store<uint64_t>(entry + 8, attributes);
		}
		call.ret(1);
	});
	// Process information classes: memory priority, commit figures, protection, leap seconds and the machine the process runs as.
	registry.add("GetProcessInformation", 4, [is_self](ApiCall &call) {
		if (!is_self(call[0]) && call[0] != UINT32_MAX) {
			call.fail(5);
			return;
		}
		std::vector<uint8_t> info;
		const auto put = [&](size_t at, uint64_t value, size_t size) { std::memcpy(info.data() + at, &value, size); };
		switch (call.u32(1)) {
		case 0:
			info.assign(4, 0);
			put(0, 5, 4);
			break;
		case 2: {
			uint64_t pages = 0, resident = 0;
			std::ifstream statm("/proc/self/statm");
			statm >> pages >> resident;
			info.assign(32, 0);
			put(0, 8ULL << 30, 8);
			put(8, pages * 4096, 8);
			put(16, pages * 4096, 8);
			put(24, pages * 4096, 8);
			break;
		}
		case 4:
			info.assign(12, 0);
			put(0, 1, 4);
			break;
		case 7:
			info.assign(4, 0);
			put(0, 0xfffffffeU, 4);
			break;
		case 8:
			info.assign(8, 0);
			break;
		case 9:
			info.assign(8, 0);
			put(0, call.pointer_width() == 4 ? 0x14c : 0x8664, 2);
			put(4, 3, 4);
			break;
		default:
			call.fail(87);
			return;
		}
		if (!call[2] || call.u32(3) < info.size()) {
			call.fail(call[2] ? 24 : 87);
			return;
		}
		call.write(call[2], info);
		call.ret(1);
	});
	// The file a mapped address of this process comes from, as an NT device path: the image the address lies in.
	for (const bool wide : {true, false})
		registry.add(wide ? "GetMappedFileNameW" : "GetMappedFileNameA", 4, [&registry, &modules, is_self, wide](ApiCall &call) {
			if (!is_self(call[0])) {
				call.fail(5);
				return;
			}
			uint64_t base = 0;
			for (const auto &[name, module] : modules.all())
				if (call[1] >= module->loaded.base() && call[1] - module->loaded.base() < module->image.image_size)
					base = module->loaded.base();
			const auto path_of = registry.find("GetModuleFileNameW");
			if (!base || !path_of) {
				call.fail(487);
				return;
			}
			const uint64_t scratch = call.process.map_memory(4096, PROT_READ | PROT_WRITE);
			ApiCall inner(call.process, call.environment, {base, scratch, 1024});
			path_of->second(inner);
			const auto dos = inner.result ? call.wide(scratch, 1024) : std::u16string();
			call.process.unmap_memory(scratch);
			if (dos.size() < 3 || dos[1] != u':') {
				call.fail(487);
				return;
			}
			// Drive C is the first volume, the drives after it follow in letter order.
			const auto volume = std::to_string(std::max(1, (dos[0] & 0x1f) - 2));
			const auto device = u"\\Device\\HarddiskVolume" + std::u16string(volume.begin(), volume.end()) + dos.substr(2);
			const size_t capacity = call.u32(3);
			if (!capacity) {
				call.fail(122);
				return;
			}
			if (wide)
				call.put_wide(call[2], device.substr(0, capacity - 1), capacity);
			else
				call.put_narrow(call[2], to_utf8(device.substr(0, capacity - 1)), capacity);
			call.ret(std::min(device.size(), capacity - 1));
		});
	// Reading memory works on this process; another process's memory lies in another host process the runtime does not reach.
	registry.add("ReadProcessMemory", 5, [is_self](ApiCall &call) {
		if (call[4])
			call.store_pointer(call[4], 0);
		if (!is_self(call[0])) {
			call.fail(5);
			return;
		}
		try {
			const auto bytes = call.read(call[1], call[3]);
			call.write(call[2], bytes);
		} catch (const ApiFault &) {
			call.fail(299);
			return;
		}
		if (call[4])
			call.store_pointer(call[4], call[3]);
		call.ret(1);
	});
	// What the object manager tells about a handle: the basic record, the name (objects here have none), the type and the handle flags.
	registry.add("NtQueryObject", 5, [&objects](ApiCall &call) {
		const uint64_t handle = call[0];
		const size_t width = call.pointer_width();
		std::optional<std::u16string> type;
		if (handle == UINT64_MAX || (width == 4 && handle == UINT32_MAX))
			type = u"Process";
		else if (handle == UINT64_MAX - 1 || (width == 4 && handle == UINT32_MAX - 1))
			type = u"Thread";
		else
			type = objects.type_name(handle);
		if (!type) {
			call.ret(0xc0000008U);
			return;
		}
		const bool pseudo = handle >= UINT64_MAX - 1 || (width == 4 && handle >= UINT32_MAX - 1);
		std::vector<uint8_t> info;
		const auto put = [&](size_t at, uint64_t value, size_t size) { std::memcpy(info.data() + at, &value, size); };
		// A UNICODE_STRING at the start of the record whose text follows the record.
		const auto counted = [&](size_t record, const std::u16string &text) {
			info.assign(record + (text.size() + 1) * 2, 0);
			put(0, text.size() * 2, 2);
			put(2, (text.size() + 1) * 2, 2);
			put(width, text.empty() ? 0 : call[2] + record, width);
			std::memcpy(info.data() + record, text.data(), text.size() * 2);
		};
		switch (call.u32(1)) {
		case 0:
			info.assign(56, 0);
			put(0, !pseudo && objects.inherit(handle) ? 2 : 0, 4);
			put(4, pseudo ? 0x1fffffU : granted_access(*type, objects.access_of(handle)), 4);
			put(8, 1, 4);
			put(12, 1, 4);
			break;
		case 1:
			counted(width == 4 ? 8 : 16, u"");
			break;
		case 2:
			counted(width == 4 ? 0x60 : 0x68, *type);
			break;
		case 4:
			info.assign(2, 0);
			info[0] = !pseudo && objects.inherit(handle) ? 1 : 0;
			break;
		default:
			call.ret(0xc0000003U);
			return;
		}
		if (call[4])
			call.store<uint32_t>(call[4], uint32_t(info.size()));
		if (call.u32(3) < info.size() || !call[2]) {
			call.ret(0xc0000004U);
			return;
		}
		call.write(call[2], info);
		if (std::getenv("RAVEN_TRACE_API") && info.size() >= 8)
			std::fprintf(stderr, "raven: NtQueryObject %llx class %u type %s access %08x\n", (unsigned long long)handle, call.u32(1),
				to_utf8(*type).c_str(), uint32_t(info[4] | info[5] << 8 | info[6] << 16 | uint32_t(info[7]) << 24));
		call.ret(0);
	});
	// kernel32 publishes the psapi functions a second time under a K32 prefix, which is what newer programs import.
	for (const char *name : {"EnumProcessModules", "EnumProcessModulesEx", "GetModuleBaseNameA", "GetModuleBaseNameW", "GetModuleInformation", "GetProcessMemoryInfo",
		"GetModuleFileNameExW", "GetModuleFileNameExA", "QueryWorkingSetEx", "GetMappedFileNameW", "GetMappedFileNameA"})
		if (const auto entry = registry.find(name))
			registry.add(std::string("K32") + name, entry->first, entry->second);
}

}
