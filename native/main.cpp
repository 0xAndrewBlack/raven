#include "pe/pe.h"
#include "pe/resources.h"
#include "pe/loaded_image.h"
#include "pe/module_set.h"
#ifdef RAVEN_NATIVE_CPU
#include "cpu/native_cpu.h"
#include "nt/providers.h"
#include "nt/paths.h"
#include "nt/launch.h"
#include "nt/text.h"
#ifdef RAVEN_WAYLAND
#include "desktop/wayland.h"
#endif
#endif

#include <filesystem>
#include <charconv>
#include <chrono>
#include <string_view>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <stdexcept>

static std::vector<uint8_t> read_file(const char *path)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file)
		throw std::runtime_error("cannot open PE file");
	const auto size = file.tellg();
	if (size < 0 || size > 1024 * 1024 * 1024)
		throw std::runtime_error("PE file exceeds inspection size limit");
	std::vector<uint8_t> bytes(static_cast<size_t>(size));
	file.seekg(0);
	if (!file.read(reinterpret_cast<char *>(bytes.data()), size))
		throw std::runtime_error("cannot read PE file");
	return bytes;
}

#ifdef RAVEN_NATIVE_CPU
static int native_result(const raven::NativeResult &result,bool process_exit=false,bool inherited_stdio=false)
{
	if (result.stop==raven::NativeStop::exited) {
		const auto code=uint32_t(result.value);
		if (!inherited_stdio) std::cout << "Native process exited with status " << code << '\n';
		return !code ? 0 : (code & 0xff) ? int(code & 0xff) : 1;
	}
	if (result.stop == raven::NativeStop::returned) {
		if (!inherited_stdio) std::cout << "Native entry returned " << result.value << " (process initialization not implemented)\n";
		const auto code=uint32_t(result.value);
		return !process_exit || !code ? 0 : (code & 0xff) ? int(code & 0xff) : 1;
	}
	if (result.stop == raven::NativeStop::syscall)
		std::cerr << "raven: unsupported guest syscall " << result.value;
	else if (result.stop == raven::NativeStop::timeout)
		std::cerr << "raven: native entry timed out";
	else if (result.stop == raven::NativeStop::api)
		std::cerr << "raven: unimplemented native process API";
	else if (result.stop == raven::NativeStop::exception)
		std::cerr << "raven: structured exception 0x" << std::hex << result.value << " (guest handler dispatch not implemented)";
	else
		std::cerr << "raven: native guest fault signal " << result.signal;
	std::cerr << " at 0x" << std::hex << result.instruction;
	if (result.stop == raven::NativeStop::fault && result.fault_address)
		std::cerr << " (address 0x" << result.fault_address << ")";
	std::cerr << '\n';
	return 1;
}
#endif

#include <cstdlib>
#include <exception>
#include <execinfo.h>

// With RAVEN_BACKTRACE set, an exception nothing catches shows where it came from.
static void show_backtrace()
{
	void *frames[48];
	const int count = backtrace(frames, 48);
	backtrace_symbols_fd(frames, count, 2);
	std::abort();
}

int main(int argc, char **argv)
{
	if (std::getenv("RAVEN_BACKTRACE"))
		std::set_terminate(show_backtrace);
	const std::string mode = argc > 1 ? argv[1] : "";
	const bool dump_image = mode == "--dump-image";
	const bool map_image = mode == "--map-image" || dump_image;
	const bool run_entry = mode == "--run-entry";
	const bool run_modules = mode == "--run-modules";
	const bool run_process = mode == "--run-process";
	int first_file=3;
	auto timeout=std::chrono::milliseconds(5000);
	bool wayland=false;
	if (run_process && argc>3 && std::string_view(argv[3]).starts_with("--timeout-ms=")) {
		const std::string_view value=std::string_view(argv[3]).substr(13);
		uint64_t milliseconds=0;
		const auto parsed=std::from_chars(value.data(),value.data()+value.size(),milliseconds);
		if (parsed.ec!=std::errc{} || parsed.ptr!=value.data()+value.size() || milliseconds<1 || milliseconds>86400000) {
			std::cerr << "raven: native timeout must be 1..86400000 milliseconds\n";
			return 2;
		}
		timeout=std::chrono::milliseconds(milliseconds);
		first_file=4;
	}
	if (run_process && argc>first_file && std::string_view(argv[first_file])=="--desktop=wayland") {
		wayland=true; ++first_file;
	}
	bool inherited_stdio=false;
	if (run_process && argc>first_file && std::string_view(argv[first_file])=="--stdio=inherit") {
		inherited_stdio=true; ++first_file;
	}
	// A program started by another one carries the command line and the directory its parent chose.
	std::optional<std::string> command_line_text, directory_text;
	int environment_fd=-1,suspended_fd=-1;
	for (bool more=run_process;more && argc>first_file;) {
		const std::string_view option=argv[first_file];
		if (option.starts_with("--command-line=")) command_line_text=std::string(option.substr(15));
		else if (option.starts_with("--directory=")) directory_text=std::string(option.substr(12));
		else if (option.starts_with("--environment-fd=")) environment_fd=std::atoi(std::string(option.substr(17)).c_str());
		else if (option.starts_with("--suspended-fd=")) suspended_fd=std::atoi(std::string(option.substr(15)).c_str());
		else more=false;
		if (more) ++first_file;
	}
	if (run_process) {
		// What programs it starts inherit: how long they may run and which window system they use.
		std::string options="--timeout-ms="+std::to_string(timeout.count());
		if (wayland) options+=" --desktop=wayland";
		setenv("RAVEN_CHILD_OPTIONS",options.c_str(),1);
	}
	const bool bind_imports = mode == "--bind-imports";
	int last_file=argc;
	if (run_process)
		for (int i=first_file;i<argc;++i)
			if (std::string_view(argv[i])=="--") { last_file=i;break; }
	const bool inspect = mode == "--inspect" || mode == "--inspect-imports" || mode == "--inspect-exports" ||
		mode == "--inspect-delay-imports" || mode == "--inspect-resources";
	const bool valid = (inspect && argc == 3) || (map_image && (argc == 3 || argc == 4)) ||
		(run_entry && argc == 4 && std::string(argv[2]) == "--execution=native") || (bind_imports && argc >= 3) ||
		((run_modules || run_process) && last_file > first_file && std::string(argv[2]) == "--execution=native");
	if (!valid) {
		std::cerr << "Usage: raven --inspect|--inspect-imports|--inspect-exports|--inspect-delay-imports|--inspect-resources program.exe\n"
			<< "       raven --map-image|--dump-image program.exe [base-address]\n"
			<< "       raven --bind-imports program.exe dependency.dll ...\n"
			<< "       raven --run-entry --execution=native fixture.exe\n"
			<< "       raven --run-modules --execution=native fixture.exe dependency.dll ...\n"
			<< "       raven --run-process --execution=native [--timeout-ms=N] [--desktop=wayland] [--stdio=inherit] program.exe [dependency.dll ...] [-- guest-argument ...]\n"
			<< "Complete Windows process initialization is not implemented yet.\n";
		return 2;
	}
	try {
		if (bind_imports || run_modules || run_process) {
			raven::ModuleSet modules;
			raven::PEModule *entry = nullptr;
			for (int i = (run_modules || run_process) ? first_file : 2; i < last_file; ++i) {
				auto bytes = read_file(argv[i]);
				auto &module = modules.add(std::filesystem::path(argv[i]).filename().string(), std::move(bytes));
				if (!entry)
					entry = &module;
			}
			if (run_modules || run_process) {
#ifdef RAVEN_NATIVE_CPU
				const auto bootstrap = std::filesystem::read_symlink("/proc/self/exe").parent_path() / "raven-bootstrap";
				if (run_process) {
					const auto directory = std::filesystem::absolute(argv[first_file]).parent_path();
					const auto source = [&](std::string_view name) -> std::optional<std::vector<uint8_t>> {
						std::optional<std::filesystem::path> selected;
						for (const auto &item : std::filesystem::directory_iterator(directory)) {
							auto filename = item.path().filename().string();
							for (auto &character : filename)
								if (character >= 'A' && character <= 'Z')
									character = static_cast<char>(character + ('a' - 'A'));
							if (filename != name || !item.is_regular_file())
								continue;
							if (selected)
								throw std::runtime_error("ambiguous case-insensitive DLL filename");
							selected = item.path();
						}
						// The runtime's own components are found beside the runtime when the program does not ship them.
						if (!selected && name=="ucrtbase.dll") {
							// A 32-bit program gets the 32-bit build of the component.
							const auto component = std::filesystem::read_symlink("/proc/self/exe").parent_path() / (entry->image.is_64 ? "ucrtbase.dll" : "ucrtbase32.dll");
							if (std::filesystem::exists(component))
								return read_file(component.c_str());
						}
						if (!selected)
							return std::nullopt;
						return read_file(selected->c_str());
					};
					const auto debug=[](std::span<const uint8_t> message) {
						std::cerr << "guest debug: ";
						for (const auto byte : message) {
							if ((byte>=32 && byte<127) || byte=='\n' || byte=='\t') std::cerr << char(byte);
							else std::cerr << "\\x" << std::hex << unsigned(byte) << std::dec;
						}
						std::cerr << '\n';
					};
					// The guest heap component ships beside the runtime when the build provisioned it.
					if (entry->image.is_64 && !modules.all().contains("raven-rtl.dll")) {
						const auto component = std::filesystem::read_symlink("/proc/self/exe").parent_path() / "raven-rtl.dll";
						if (std::filesystem::exists(component))
							modules.add("raven-rtl.dll", read_file(component.c_str()));
					}
					// The components for 32-bit programs are the same libraries built for 32 bits, in a directory beside the runtime.
					const auto component_directory = std::filesystem::read_symlink("/proc/self/exe").parent_path() / (entry->image.is_64 ? "" : "x86");
					// The common controls component stands in for comctl32.dll when the program does not ship its own.
					if (!modules.all().contains("comctl32.dll")) {
						const auto component = component_directory / "comctl32.dll";
						const auto imported = std::any_of(modules.all().begin(), modules.all().end(), [](const auto &item) {
							return std::any_of(item.second->imports.begin(), item.second->imports.end(), [](const auto &symbol) {
								auto name = symbol.module;
								for (auto &character : name)
									if (character >= 'A' && character <= 'Z')
										character = static_cast<char>(character + ('a' - 'A'));
								return name == "comctl32.dll" || name == "comctl32" || name == "user32.dll" || name == "user32";
							});
						});
						if (imported && std::filesystem::exists(component))
							modules.add("comctl32.dll", read_file(component.c_str()));
					}
					// Components that stand in for parts of system libraries are loaded beside the program that imports those libraries.
					const auto load_component = [&](const char *file, std::initializer_list<const char *> libraries) {
						if (modules.all().contains(file))
							return;
						const auto component = component_directory / file;
						const auto imported = std::any_of(modules.all().begin(), modules.all().end(), [&](const auto &item) {
							return std::any_of(item.second->imports.begin(), item.second->imports.end(), [&](const auto &symbol) {
								auto name = symbol.module;
								for (auto &character : name)
									if (character >= 'A' && character <= 'Z')
										character = static_cast<char>(character + ('a' - 'A'));
								return std::any_of(libraries.begin(), libraries.end(), [&](const char *library) {
									const std::string_view wanted(library);
									// A trailing '*' names a family of API set libraries.
									if (wanted.ends_with('*'))
										return name.starts_with(wanted.substr(0, wanted.size() - 1));
									return name == library || name + ".dll" == library;
								});
							});
						});
						if (imported && std::filesystem::exists(component))
							modules.add(file, read_file(component.c_str()));
					};
					// The user32 component supplies the built-in control classes and dialog manager to programs that use user32.
					load_component("raven-user32.dll", {"user32.dll"});
					load_component("raven-shell.dll", {"comdlg32.dll", "ole32.dll", "shell32.dll"});
					if (entry->image.is_64)
						load_component("ucrtbase.dll", {"ucrtbase.dll", "api-ms-win-crt-*"});
					raven::DesktopPresentation presentation;
#ifdef RAVEN_WAYLAND
					raven::WaylandPresentation backend;
					if (wayland) presentation=backend.callbacks();
#else
					if (wayland) throw std::runtime_error("native Wayland presentation was not built");
#endif
					std::optional<raven::NativeLaunch> launch;
					{
						std::vector<std::string_view> arguments;
						for (int i=last_file+1;i<argc;++i) arguments.emplace_back(argv[i]);
						// The guest sees its own executable by a drive-qualified path, like any Windows process.
						const raven::NativePrefix prefix=raven::NativePrefix::from_environment();
						const raven::NativePaths paths(prefix);
						const auto image=paths.dos(std::filesystem::absolute(argv[first_file]));
						launch=raven::NativeLaunch{image,raven::launch_command_line(image,arguments)};
						if (command_line_text) launch->command_line=raven::from_utf8(*command_line_text);
						if (directory_text) launch->directory=raven::from_utf8(*directory_text);
						if (environment_fd>=0) {
							// The parent's environment block arrives in an anonymous file as UTF-16.
							std::string bytes;
							char chunk[4096];
							for (ssize_t count;(count=::read(environment_fd,chunk,sizeof(chunk)))!=0;) {
								if (count<0) { if (errno==EINTR) continue; break; }
								bytes.append(chunk,size_t(count));
							}
							::close(environment_fd);
							std::u16string block(bytes.size()/2,u'\0');
							std::memcpy(block.data(),bytes.data(),block.size()*2);
							launch->environment=std::move(block);
						}
						if (inherited_stdio) launch->standard_fds={0,1,2};
					}
					if (suspended_fd>=0) {
						// Started suspended: nothing runs until the parent resumes the thread.
						char open;
						while (::read(suspended_fd,&open,1)<0 && errno==EINTR) {}
						::close(suspended_fd);
					}
					if (!entry->image.is_64)
						return native_result(raven::run_native_process_x86(modules, *entry, bootstrap.string(), timeout, launch, presentation, source),true,inherited_stdio);
					return native_result(raven::run_native_process(modules, *entry, bootstrap.string(), timeout, source, debug,presentation,launch),true,inherited_stdio);
				}
				return native_result(raven::run_native_modules(modules, *entry, bootstrap.string(), std::chrono::seconds(5)));
#else
				throw std::runtime_error("native execution requires an x86-64 Linux host");
#endif
			}
			const auto count = modules.bind_imports();
			std::cout << "Prepared " << modules.all().size() << " modules and bound " << count
				<< " imports (DLL initialization not implemented)\n";
			for (const auto &[name, module] : modules.all()) {
				for (const auto &symbol : module->imports) {
					uint64_t value = 0;
					for (size_t byte = 0; byte < (module->image.is_64 ? 8U : 4U); ++byte)
						value |= uint64_t(module->loaded.data()[symbol.iat_address + byte]) << (byte * 8);
					std::cout << name << ':' << symbol.module << '!'
						<< (symbol.by_ordinal ? "#" + std::to_string(symbol.ordinal) : symbol.name)
						<< " iat=0x" << std::hex << module->loaded.base() + symbol.iat_address
						<< " target=0x" << value << std::dec << '\n';
				}
			}
			return 0;
		}
		const auto bytes = read_file(argv[run_entry ? 3 : 2]);
		const raven::PEImage image(bytes);
		const auto imports = image.imports();
		if (run_entry) {
#ifdef RAVEN_NATIVE_CPU
			raven::LoadedImage loaded(image, image.image_base);
			const auto bootstrap = std::filesystem::read_symlink("/proc/self/exe").parent_path() / "raven-bootstrap";
			return native_result(raven::run_native_entry(image, loaded, bootstrap.string(), std::chrono::seconds(5)));
#else
			throw std::runtime_error("native execution requires an x86-64 Linux host");
#endif
		}
		if (!dump_image)
			std::cout << (image.is_64 ? "PE64" : "PE32") << " base=0x" << std::hex << image.image_base
				<< " entry=0x" << image.entry << " size=0x" << image.image_size
				<< std::dec << " sections=" << image.sections.size() << " imports=" << imports.size() << '\n';
		if (mode == "--inspect-resources") {
			const auto key = [](const raven::ResourceKey &value) {
				if (const auto *id = std::get_if<uint32_t>(&value)) {
					std::cout << '#' << *id;
					return;
				}
				std::cout << '"';
				for (const auto character : std::get<std::u16string>(value)) {
					if (character >= 32 && character <= 126 && character != '"' && character != '\\')
						std::cout << static_cast<char>(character);
					else
						std::cout << "\\u" << std::hex << std::setw(4) << std::setfill('0')
							<< uint32_t(character) << std::dec << std::setfill(' ');
				}
				std::cout << '"';
			};
			for (const auto &resource : image.resources()) {
				std::cout << "Resource type=";
				key(resource.type);
				std::cout << " name=";
				key(resource.name);
				std::cout << " language=" << resource.language << " info=0x" << std::hex << resource.entry_address
					<< " data=0x" << resource.data_address << std::dec << " size=" << resource.size
					<< " codepage=" << resource.code_page << '\n';
			}
			return 0;
		}
		if (mode == "--inspect-delay-imports") {
			for (const auto &descriptor : image.delay_imports()) {
				std::cout << "Delay module=" << std::quoted(descriptor.module) << " descriptor=0x" << std::hex
					<< descriptor.descriptor_address << " handle=0x" << descriptor.module_handle_address
					<< " iat=0x" << descriptor.iat_address << " lookup=0x" << descriptor.lookup_address
					<< " bound=0x" << descriptor.bound_address << " unload=0x" << descriptor.unload_address
					<< " timestamp=0x" << descriptor.timestamp << std::dec << '\n';
				for (const auto &symbol : descriptor.imports)
					std::cout << descriptor.module << '!' << (symbol.by_ordinal ? "#" +
						std::to_string(symbol.ordinal) : symbol.name) << " iat=0x" << std::hex
						<< symbol.iat_address << std::dec << '\n';
			}
			return 0;
		}
		if (mode == "--inspect-exports") {
			for (const auto &symbol : image.exports()) {
				std::cout << symbol.ordinal << " 0x" << std::hex << symbol.address << std::dec
					<< ' ' << std::quoted(symbol.forwarder);
				for (const auto &name : symbol.names)
					std::cout << ' ' << std::quoted(name);
				std::cout << '\n';
			}
			return 0;
		}
		if (map_image) {
			uint64_t base = image.image_base;
			if (argc == 4) {
				size_t consumed = 0;
				base = std::stoull(argv[3], &consumed, 0);
				if (consumed != std::string(argv[3]).size())
					throw std::runtime_error("invalid image base argument");
			}
			raven::LoadedImage loaded(image, base);
			if (dump_image) {
				std::cout.write(reinterpret_cast<const char *>(loaded.data().data()),
					static_cast<std::streamsize>(loaded.data().size()));
				if (!std::cout)
					throw std::runtime_error("cannot write loaded image");
				return 0;
			}
			std::cout << "Shared image base=0x" << std::hex << loaded.base() << std::dec
				<< " bytes=" << loaded.data().size() << " relocations=" << loaded.relocation_count() << '\n';
			for (const auto &mapping : loaded.mappings())
				std::cout << "Mapping address=0x" << std::hex << mapping.address << " size=0x" << mapping.size
					<< " offset=0x" << mapping.file_offset << std::dec << " protection=" << mapping.protection << '\n';
			return 0;
		}
		std::map<std::string, size_t> modules;
		for (const auto &import : imports)
			++modules[import.module];
		if (std::string(argv[1]) == "--inspect-imports") {
			for (const auto &import : imports)
				std::cout << import.module << '!' << (import.by_ordinal ? "#" + std::to_string(import.ordinal) : import.name) << '\n';
		} else {
			for (const auto &[module, count] : modules)
				std::cout << module << ' ' << count << '\n';
		}
		return 0;
	} catch (const std::exception &error) {
		std::cerr << "raven: " << error.what() << '\n';
		return 1;
	}
}
