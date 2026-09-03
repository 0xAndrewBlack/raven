#include "foreign_surface.h"

#include "shared_pixels.h"
#include "nt/host_names.h"
#include "nt/prefix.h"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <vector>
#include <mutex>
#include <signal.h>
#include <string>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace raven {

namespace {

constexpr size_t header_size = 4096;
constexpr uint32_t surface_magic = 0x52574653;

std::filesystem::path window_directory()
{
	std::filesystem::path base;
	if (const char *runtime = std::getenv("XDG_RUNTIME_DIR"); runtime && *runtime)
		base = runtime;
	else
		base = NativePrefix::from_environment().root();
	auto directory = base / ("raven-windows-" + prefix_tag());
	std::error_code error;
	std::filesystem::create_directories(directory, error);
	return directory;
}

std::string window_name(uint64_t window)
{
	char text[17];
	std::snprintf(text, sizeof(text), "%08llx", static_cast<unsigned long long>(window & 0xffffffffULL));
	return text;
}

}

uint64_t window_handle_base()
{
	// Sixteen bits of window number under a tag from the process id; the tag stays clear of the low handles other objects use.
	return uint64_t((uint32_t(::getpid()) % 0x7ef0) + 0x100) << 16;
}

// Removes what processes that ended without withdrawing their windows left: a window whose owner is gone, and pixels without a window.
static void sweep_windows(const std::filesystem::path &directory)
{
	std::error_code error;
	std::vector<std::filesystem::path> stale;
	for (const auto &entry : std::filesystem::directory_iterator(directory, error)) {
		const auto path = entry.path();
		if (path.extension() == ".window") {
			std::ifstream input(path);
			long owner = 0;
			if ((input >> owner) && owner > 0 && !(::kill(pid_t(owner), 0) != 0 && errno == ESRCH))
				continue;
			stale.push_back(path);
			stale.push_back(std::filesystem::path(path).replace_extension(".pixels"));
		} else if (path.extension() == ".pixels" && !std::filesystem::exists(std::filesystem::path(path).replace_extension(".window"), error)) {
			stale.push_back(path);
		}
	}
	for (const auto &path : stale)
		std::filesystem::remove(path, error);
}

void publish_window(uint64_t window, uint32_t width, uint32_t height)
{
	const auto directory = window_directory();
	static std::once_flag swept;
	std::call_once(swept, [&] { sweep_windows(directory); });
	const auto final_path = directory / (window_name(window) + ".window");
	const auto temporary = directory / (window_name(window) + ".window." + std::to_string(::getpid()));
	{
		std::ofstream output(temporary, std::ios::trunc);
		output << ::getpid() << ' ' << width << ' ' << height << '\n';
	}
	std::error_code error;
	std::filesystem::rename(temporary, final_path, error);
}

void withdraw_window(uint64_t window)
{
	const auto directory = window_directory();
	std::error_code error;
	std::filesystem::remove(directory / (window_name(window) + ".window"), error);
	std::filesystem::remove(directory / (window_name(window) + ".pixels"), error);
}

std::optional<std::pair<uint32_t, uint32_t>> foreign_window_size(uint64_t window)
{
	std::ifstream input(window_directory() / (window_name(window) + ".window"));
	long owner = 0;
	uint32_t width = 0, height = 0;
	if (!(input >> owner >> width >> height) || owner <= 0 || owner == ::getpid())
		return std::nullopt;
	if (::kill(pid_t(owner), 0) != 0 && errno == ESRCH)
		return std::nullopt;
	return std::make_pair(std::max<uint32_t>(width, 1), std::max<uint32_t>(height, 1));
}

std::shared_ptr<ForeignSurface> ForeignSurface::open_for_drawing(uint64_t window, uint32_t width, uint32_t height)
{
	if (!width || !height || width > 16384 || height > 16384)
		return nullptr;
	const auto path = window_directory() / (window_name(window) + ".pixels");
	const int file = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (file < 0)
		return nullptr;
	const size_t bytes = (size_t(width) * height * 4 + 4095) & ~size_t(4095);
	struct stat status{};
	if (::fstat(file, &status) != 0 || (size_t(status.st_size) < header_size + bytes && ::ftruncate(file, off_t(header_size + bytes)) != 0)) {
		::close(file);
		return nullptr;
	}
	void *mapped = ::mmap(nullptr, header_size, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
	if (mapped == MAP_FAILED) {
		::close(file);
		return nullptr;
	}
	auto surface = std::shared_ptr<ForeignSurface>(new ForeignSurface());
	surface->file = file;
	surface->header = static_cast<uint32_t *>(mapped);
	surface->width = width;
	surface->height = height;
	try {
		surface->pixels = std::make_shared<SharedPixels>(file, header_size, bytes);
	} catch (...) {
		return nullptr;
	}
	surface->header[1] = width;
	surface->header[2] = height;
	surface->header[0] = surface_magic;
	return surface;
}

ForeignSurface::~ForeignSurface()
{
	if (header)
		::munmap(header, header_size);
	if (file >= 0)
		::close(file);
}

void ForeignSurface::publish_frame()
{
	if (!header)
		return;
	header[1] = width;
	header[2] = height;
	std::atomic_ref<uint32_t>(header[3]).fetch_add(1, std::memory_order_release);
}

bool take_foreign_frame(uint64_t window, uint32_t &seen, const std::function<void(const uint8_t *, uint32_t, uint32_t)> &use)
{
	const auto path = window_directory() / (window_name(window) + ".pixels");
	const int file = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
	if (file < 0)
		return false;
	struct stat status{};
	bool taken = false;
	if (::fstat(file, &status) == 0 && size_t(status.st_size) > header_size) {
		void *mapped = ::mmap(nullptr, size_t(status.st_size), PROT_READ, MAP_SHARED, file, 0);
		if (mapped != MAP_FAILED) {
			const auto *header = static_cast<const uint32_t *>(mapped);
			const uint32_t sequence = std::atomic_ref<const uint32_t>(header[3]).load(std::memory_order_acquire);
			const uint32_t width = header[1], height = header[2];
			if (header[0] == surface_magic && sequence && sequence != seen && width && height &&
				header_size + size_t(width) * height * 4 <= size_t(status.st_size)) {
				use(static_cast<const uint8_t *>(mapped) + header_size, width, height);
				seen = sequence;
				taken = true;
			}
			::munmap(mapped, size_t(status.st_size));
		}
	}
	::close(file);
	return taken;
}

}
