#include "child_process.h"
#include "pipe.h"
#include "section.h"
#include "security_attributes.h"
#include "kernel_context.h"
#include "file_objects.h"
#include "text.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <unistd.h>

namespace raven {

FileObject::~FileObject()
{
	if (descriptor >= 0)
		::close(descriptor);
	if (flags & 0x04000000U)
		::unlink(path.c_str());
}

namespace {

constexpr uint64_t invalid_handle = UINT64_MAX;
constexpr uint32_t attribute_readonly = 0x1, attribute_hidden = 0x2, attribute_directory = 0x10, attribute_archive = 0x20,
	attribute_normal = 0x80, attribute_reparse = 0x400;

uint64_t filetime(const timespec &time)
{
	return (uint64_t(time.tv_sec) * 10000000ULL) + uint64_t(time.tv_nsec) / 100 + filetime_epoch_offset;
}

timespec timespec_from(uint64_t ticks)
{
	const uint64_t since_unix = ticks - filetime_epoch_offset;
	return {time_t(since_unix / 10000000ULL), long(since_unix % 10000000ULL * 100)};
}

uint32_t attributes_of(const struct stat &metadata, const std::filesystem::path &path)
{
	uint32_t attributes = S_ISDIR(metadata.st_mode) ? attribute_directory : attribute_archive;
	if (S_ISLNK(metadata.st_mode))
		attributes |= attribute_reparse;
	if (!(metadata.st_mode & 0222))
		attributes |= attribute_readonly;
	const auto name = path.filename().string();
	if (name.size() > 1 && name[0] == '.' && name != "..")
		attributes |= attribute_hidden;
	return attributes;
}

uint32_t error_of(int error, bool missing_parent = false)
{
	switch (error) {
	case ENOENT: return missing_parent ? 3 : 2;
	case ENOTDIR: return 3;
	case EACCES: case EPERM: case EROFS: case EISDIR: return 5;
	case EEXIST: return 80;
	case ENOTEMPTY: return 145;
	case ENOSPC: case EDQUOT: return 112;
	case EMFILE: case ENFILE: return 4;
	case ENAMETOOLONG: return 206;
	case EXDEV: return 17;
	case EBUSY: case ETXTBSY: return 32;
	case EINVAL: return 87;
	case EBADF: return 6;
	default: return 31;
	}
}

// Windows wildcard matching: * and ? against a file name, case-insensitively; "*.*" matches every name.
bool wildcard(std::u16string_view pattern, std::u16string_view name)
{
	if (pattern == u"*.*" || pattern == u"*")
		return true;
	size_t p = 0, n = 0, star = std::u16string_view::npos, mark = 0;
	while (n < name.size()) {
		if (p < pattern.size() && (pattern[p] == u'?' || pattern[p] == u'>' || equal_fold(pattern.substr(p, 1), name.substr(n, 1)))) {
			++p;
			++n;
		} else if (p < pattern.size() && (pattern[p] == u'*' || pattern[p] == u'<')) {
			star = p++;
			mark = n;
		} else if (star != std::u16string_view::npos) {
			p = star + 1;
			n = ++mark;
		} else {
			return false;
		}
	}
	while (p < pattern.size() && (pattern[p] == u'*' || pattern[p] == u'<' || pattern[p] == u'.'))
		++p;
	return p == pattern.size();
}

FindObject::Entry entry_of(const std::filesystem::path &path, const std::u16string &name)
{
	FindObject::Entry entry{name, attribute_normal, 0, 0, 0, 0};
	struct stat metadata{};
	if (::lstat(path.c_str(), &metadata)) {
		metadata = {};
		return entry;
	}
	struct stat target{};
	const bool link = S_ISLNK(metadata.st_mode);
	if (link && !::stat(path.c_str(), &target))
		metadata = target;
	entry.attributes = attributes_of(metadata, path);
	entry.creation = filetime(metadata.st_ctim);
	entry.access = filetime(metadata.st_atim);
	entry.write = filetime(metadata.st_mtim);
	entry.size = S_ISDIR(metadata.st_mode) ? 0 : uint64_t(metadata.st_size);
	return entry;
}

void put32(std::vector<uint8_t> &bytes, size_t at, uint32_t value)
{
	std::memcpy(bytes.data() + at, &value, 4);
}

void put64(std::vector<uint8_t> &bytes, size_t at, uint64_t value)
{
	std::memcpy(bytes.data() + at, &value, 8);
}

// WIN32_FIND_DATAW is 592 bytes: attributes, three times, size, two reserved words, a 260-character name and a short name.
std::vector<uint8_t> find_data(const FindObject::Entry &entry)
{
	std::vector<uint8_t> bytes(592);
	put32(bytes, 0, entry.attributes);
	put64(bytes, 4, entry.creation);
	put64(bytes, 12, entry.access);
	put64(bytes, 20, entry.write);
	put32(bytes, 28, uint32_t(entry.size >> 32));
	put32(bytes, 32, uint32_t(entry.size));
	const auto name = entry.name.substr(0, 259);
	std::memcpy(bytes.data() + 44, name.data(), name.size() * 2);
	return bytes;
}

std::vector<uint8_t> attribute_data(const FindObject::Entry &entry)
{
	std::vector<uint8_t> bytes(36);
	put32(bytes, 0, entry.attributes);
	put64(bytes, 4, entry.creation);
	put64(bytes, 12, entry.access);
	put64(bytes, 20, entry.write);
	put32(bytes, 28, uint32_t(entry.size >> 32));
	put32(bytes, 32, uint32_t(entry.size));
	return bytes;
}

}

void register_file_api(ApiRegistry &registry, KernelContext &context)
{
	auto &paths = context.paths;
	auto &objects = context.objects;
	const auto file_of = [&](uint64_t handle) { return objects.object_as<FileObject>(handle); };
	// Host errors become Windows last errors; a missing parent directory reads as path-not-found.
	const auto resolve = [&](ApiCall &call, std::u16string_view name) -> std::optional<NativePaths::Resolved> {
		const auto resolved = paths.resolve(name);
		if (!resolved)
			call.set_last_error(name.empty() ? 2 : 123);
		return resolved;
	};
	const auto missing = [&](const NativePaths::Resolved &resolved) { return resolved.parent_exists ? 2U : 3U; };

	registry.add("CreateFileW", 7, [&, resolve, missing, file_of](ApiCall &call) {
		const auto name = call.wide(call[0]);
		const uint32_t access = call.u32(1), disposition = call.u32(4), flags = call.u32(5);
		if (open_pipe_client(context, call, name, access, flags))
			return;
		call.ret(invalid_handle);
		if (disposition < 1 || disposition > 5) {
			call.set_last_error(87);
			return;
		}
		if (NativePaths::device(name)) {
			const int descriptor = ::open("/dev/null", O_RDWR | O_CLOEXEC);
			const auto made = objects.add_object(std::make_shared<FileObject>(descriptor, access, false, "/dev/null", u"NUL", 0));
			{ if (!made.status && inheritable_handle(call, optional_argument(call, 3))) objects.set_inherit(made.value, true); call.ret(made.status ? invalid_handle : made.value); }
			return;
		}
		const auto resolved = resolve(call, name);
		if (!resolved)
			return;
		const bool want_write = access & (0x40000000U | 0x10000000U | 0x2U | 0x4U | 0x10000U);
		const bool want_read = access & (0x80000000U | 0x10000000U | 0x1U);
		struct stat metadata{};
		const bool exists = resolved->exists && !::stat(resolved->host.c_str(), &metadata);
		if (exists && S_ISDIR(metadata.st_mode)) {
			if (!(flags & 0x02000000U) || disposition == 1 || disposition == 2 || disposition == 5) {
				call.set_last_error(disposition == 1 ? 80 : 5);
				return;
			}
			const int descriptor = ::open(resolved->host.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
			if (descriptor < 0) {
				call.set_last_error(error_of(errno));
				return;
			}
			const auto made = objects.add_object(std::make_shared<FileObject>(descriptor, access, true, resolved->host, paths.full(name), flags));
			{ if (!made.status && inheritable_handle(call, optional_argument(call, 3))) objects.set_inherit(made.value, true); call.ret(made.status ? invalid_handle : made.value); }
			return;
		}
		int mode = want_read && want_write ? O_RDWR : want_write ? O_WRONLY : O_RDONLY;
		// FILE_APPEND_DATA without a right to write at a position means every write goes to the end of the file.
		if ((access & 0x4U) && !(access & (0x40000000U | 0x10000000U | 0x2U)))
			mode |= O_APPEND;
		if (disposition == 1) {
			if (exists) {
				call.set_last_error(80);
				return;
			}
			mode |= O_CREAT | O_EXCL;
		} else if (disposition == 2) {
			mode |= O_CREAT;
			if (want_write)
				mode |= O_TRUNC;
		} else if (disposition == 4) {
			mode |= O_CREAT;
		} else if (disposition == 5) {
			if (!want_write) {
				call.set_last_error(87);
				return;
			}
			if (!exists) {
				call.set_last_error(missing(*resolved));
				return;
			}
			mode |= O_TRUNC;
		} else if (!exists) {
			call.set_last_error(missing(*resolved));
			return;
		}
		if (!exists && !resolved->parent_exists) {
			call.set_last_error(3);
			return;
		}
		const int descriptor = ::open(resolved->host.c_str(), mode | O_CLOEXEC, 0666);
		if (descriptor < 0) {
			call.set_last_error(error_of(errno, !resolved->parent_exists));
			return;
		}
		// CREATE_ALWAYS and OPEN_ALWAYS report an existing file through a successful call with ERROR_ALREADY_EXISTS.
		call.set_last_error(exists && (disposition == 2 || disposition == 4) ? 183 : 0);
		if (disposition == 2 && exists && !want_write)
			::ftruncate(descriptor, 0);
		const auto made = objects.add_object(std::make_shared<FileObject>(descriptor, access, false, resolved->host, paths.full(name), flags));
		{ if (!made.status && inheritable_handle(call, optional_argument(call, 3))) objects.set_inherit(made.value, true); call.ret(made.status ? invalid_handle : made.value); }
	});
	registry.add("ReadFile", 5, [&, resolve, missing, file_of](ApiCall &call) {
		if (transfer_pipe(context, call, true))
			return;
		// The standard handles inherited from the host read straight from their descriptors.
		if (!file_of(call[0])) {
			std::vector<uint8_t> buffer(std::min<uint32_t>(call.u32(2), 1 << 20));
			const auto result = objects.read_file(call[0], buffer);
			if (!result.status && !call[4]) {
				call.write(call[1], std::span<const uint8_t>(buffer.data(), size_t(result.value)));
				if (call[3]) call.store<uint32_t>(call[3], uint32_t(result.value));
				call.ret(1);
				return;
			}
		}
		const auto file = file_of(call[0]);
		if (!file || file->directory || !file->readable()) {
			call.fail(file && file->directory ? 5 : file ? 5 : 6);
			return;
		}
		if (call[3]) call.store<uint32_t>(call[3], 0);
		else if (!call[4]) {
			call.fail(87);
			return;
		}
		std::vector<uint8_t> buffer(call.u32(2));
		ssize_t count;
		if (call[4]) {
			// An OVERLAPPED offset applies to synchronous handles too, and moves their file pointer after the transfer.
			const auto offset = call.load<uint64_t>(call[4] + 16);
			count = ::pread(file->descriptor, buffer.data(), buffer.size(), off_t(offset));
			if (count >= 0 && !(file->flags & 0x40000000U))
				::lseek(file->descriptor, off_t(offset + uint64_t(count)), SEEK_SET);
		} else {
			do count = ::read(file->descriptor, buffer.data(), buffer.size()); while (count < 0 && errno == EINTR);
		}
		if (count < 0) {
			call.fail(error_of(errno));
			return;
		}
		call.write(call[1], std::span<const uint8_t>(buffer.data(), size_t(count)));
		if (call[3]) call.store<uint32_t>(call[3], uint32_t(count));
		if (call[4]) {
			call.store<uint64_t>(call[4], 0);
			call.store<uint64_t>(call[4] + 8, uint64_t(count));
		}
		call.ret(1);
	});
	registry.add("WriteFile", 5, [&, resolve, missing, file_of](ApiCall &call) {
		if (transfer_pipe(context, call, false))
			return;
		const auto file = file_of(call[0]);
		if (!file || file->directory || !file->writable()) {
			call.fail(file ? 5 : 6);
			return;
		}
		if (call[3]) call.store<uint32_t>(call[3], 0);
		else if (!call[4]) {
			call.fail(87);
			return;
		}
		const auto bytes = call.read(call[1], call.u32(2));
		ssize_t count;
		if (call[4]) {
			const auto offset = call.load<uint64_t>(call[4] + 16);
			count = offset == UINT64_MAX ? ::write(file->descriptor, bytes.data(), bytes.size())
				: ::pwrite(file->descriptor, bytes.data(), bytes.size(), off_t(offset));
			if (count >= 0 && offset != UINT64_MAX && !(file->flags & 0x40000000U))
				::lseek(file->descriptor, off_t(offset + uint64_t(count)), SEEK_SET);
		} else {
			do count = ::write(file->descriptor, bytes.data(), bytes.size()); while (count < 0 && errno == EINTR);
		}
		if (count < 0) {
			call.fail(error_of(errno));
			return;
		}
		if (call[3]) call.store<uint32_t>(call[3], uint32_t(count));
		if (call[4]) {
			call.store<uint64_t>(call[4], 0);
			call.store<uint64_t>(call[4] + 8, uint64_t(count));
		}
		call.ret(1);
	});
	registry.add("SetFilePointerEx", 4, [&, resolve, missing, file_of](ApiCall &call) {
		const auto file = file_of(call[0]);
		if (!file) {
			call.fail(6);
			return;
		}
		const auto method = call.u32(3);
		if (method > 2) {
			call.fail(87);
			return;
		}
		const off_t position = ::lseek(file->descriptor, off_t(int64_t(call[1])), method == 0 ? SEEK_SET : method == 1 ? SEEK_CUR : SEEK_END);
		if (position < 0) {
			call.fail(errno == EINVAL ? 131 : error_of(errno));
			return;
		}
		if (call[2]) call.store<int64_t>(call[2], position);
		call.ret(1);
	});
	// The older form splits the distance in two words; the answer is the low word of the position, and 0xffffffff with a last error on failure.
	registry.add("SetFilePointer", 4, [&, resolve, missing, file_of](ApiCall &call) {
		const auto file = file_of(call[0]);
		if (!file) {
			call.fail(6, 0xffffffffU);
			return;
		}
		const auto method = call.u32(3);
		if (method > 2) {
			call.fail(87, 0xffffffffU);
			return;
		}
		const int64_t distance = call[2] ? int64_t(uint64_t(uint32_t(call.load<int32_t>(call[2]))) << 32 | call.u32(1)) : int64_t(call.i32(1));
		const off_t position = ::lseek(file->descriptor, off_t(distance), method == 0 ? SEEK_SET : method == 1 ? SEEK_CUR : SEEK_END);
		if (position < 0) {
			call.fail(errno == EINVAL ? 131 : error_of(errno), 0xffffffffU);
			return;
		}
		if (call[2]) call.store<int32_t>(call[2], int32_t(uint64_t(position) >> 32));
		call.set_last_error(0);
		call.ret(uint32_t(position));
	});
	// Byte-range locks map to open-file-description locks, so they conflict between handles the way Windows locks do.
	const auto lock_range = [file_of](ApiCall &call, int kind, uint64_t offset, uint64_t length, bool wait) {
		const auto file = file_of(call[0]);
		if (!file) {
			call.fail(6);
			return;
		}
		struct flock request{};
		request.l_type = kind;
		request.l_whence = SEEK_SET;
		request.l_start = off_t(offset);
		request.l_len = off_t(length);
		if (::fcntl(file->descriptor, wait ? F_OFD_SETLKW : F_OFD_SETLK, &request) < 0) {
			call.fail(errno == EAGAIN || errno == EACCES ? 33 : errno == EINTR ? 995 : error_of(errno));
			return;
		}
		call.ret(1);
	};
	registry.add("LockFileEx", 6, [lock_range](ApiCall &call) {
		const uint64_t offset = call[5] ? call.load<uint32_t>(call[5] + 16) | (uint64_t(call.load<uint32_t>(call[5] + 20)) << 32) : 0;
		lock_range(call, (call.u32(1) & 2) ? F_WRLCK : F_RDLCK, offset, call.u32(3) | (uint64_t(call.u32(4)) << 32), !(call.u32(1) & 1));
	});
	registry.add("UnlockFileEx", 5, [lock_range](ApiCall &call) {
		const uint64_t offset = call[4] ? call.load<uint32_t>(call[4] + 16) | (uint64_t(call.load<uint32_t>(call[4] + 20)) << 32) : 0;
		lock_range(call, F_UNLCK, offset, call.u32(2) | (uint64_t(call.u32(3)) << 32), false);
	});
	registry.add("LockFile", 5, [lock_range](ApiCall &call) {
		lock_range(call, F_WRLCK, call.u32(1) | (uint64_t(call.u32(2)) << 32), call.u32(3) | (uint64_t(call.u32(4)) << 32), false);
	});
	registry.add("UnlockFile", 5, [lock_range](ApiCall &call) {
		lock_range(call, F_UNLCK, call.u32(1) | (uint64_t(call.u32(2)) << 32), call.u32(3) | (uint64_t(call.u32(4)) << 32), false);
	});
	registry.add("GetFileSizeEx", 2, [&, resolve, missing, file_of](ApiCall &call) {
		const auto file = file_of(call[0]);
		struct stat metadata{};
		if (!file || ::fstat(file->descriptor, &metadata)) {
			call.fail(6);
			return;
		}
		call.store<int64_t>(call[1], metadata.st_size);
		call.ret(1);
	});
	registry.add("GetFileSize", 2, [&, resolve, missing, file_of](ApiCall &call) {
		const auto file = file_of(call[0]);
		struct stat metadata{};
		if (!file || ::fstat(file->descriptor, &metadata)) {
			call.fail(6, 0xffffffffU);
			return;
		}
		if (call[1]) call.store<uint32_t>(call[1], uint32_t(uint64_t(metadata.st_size) >> 32));
		call.set_last_error(0);
		call.ret(uint32_t(metadata.st_size));
	});
	registry.add("GetFileType", 1, [&, resolve, missing, file_of](ApiCall &call) {
		const auto file = file_of(call[0]);
		if (!file) {
			call.fail(6);
			return;
		}
		call.ret(objects.object_as<PipeObject>(call[0]) ? 3 : ::isatty(file->descriptor) ? 2 : 1);
	});
	registry.add("SetEndOfFile", 1, [&, resolve, missing, file_of](ApiCall &call) {
		const auto file = file_of(call[0]);
		if (!file || !file->writable()) {
			call.fail(file ? 5 : 6);
			return;
		}
		const off_t position = ::lseek(file->descriptor, 0, SEEK_CUR);
		if (position < 0 || ::ftruncate(file->descriptor, position)) {
			call.fail(error_of(errno));
			return;
		}
		call.ret(1);
	});
	registry.add("FlushFileBuffers", 1, [&, resolve, missing, file_of](ApiCall &call) {
		const auto file = file_of(call[0]);
		if (!file || !file->writable()) {
			call.fail(file ? 5 : 6);
			return;
		}
		::fsync(file->descriptor);
		call.ret(1);
	});
	registry.add("GetFileTime", 4, [&, resolve, missing, file_of](ApiCall &call) {
		const auto file = file_of(call[0]);
		struct stat metadata{};
		if (!file || ::fstat(file->descriptor, &metadata)) {
			call.fail(6);
			return;
		}
		if (call[1]) call.store<uint64_t>(call[1], filetime(metadata.st_ctim));
		if (call[2]) call.store<uint64_t>(call[2], filetime(metadata.st_atim));
		if (call[3]) call.store<uint64_t>(call[3], filetime(metadata.st_mtim));
		call.ret(1);
	});
	registry.add("SetFileTime", 4, [&, resolve, missing, file_of](ApiCall &call) {
		const auto file = file_of(call[0]);
		if (!file || !file->writable()) {
			call.fail(file ? 5 : 6);
			return;
		}
		timespec times[2]{{0, UTIME_OMIT}, {0, UTIME_OMIT}};
		if (call[2]) if (const auto value = call.load<uint64_t>(call[2])) times[0] = timespec_from(value);
		if (call[3]) if (const auto value = call.load<uint64_t>(call[3])) times[1] = timespec_from(value);
		if (::futimens(file->descriptor, times)) {
			call.fail(error_of(errno));
			return;
		}
		call.ret(1);
	});
	registry.add("GetFileInformationByHandle", 2, [&, resolve, missing, file_of](ApiCall &call) {
		const auto file = file_of(call[0]);
		struct stat metadata{};
		if (!file || ::fstat(file->descriptor, &metadata)) {
			call.fail(6);
			return;
		}
		std::vector<uint8_t> bytes(52);
		put32(bytes, 0, attributes_of(metadata, file->path));
		put64(bytes, 4, filetime(metadata.st_ctim));
		put64(bytes, 12, filetime(metadata.st_atim));
		put64(bytes, 20, filetime(metadata.st_mtim));
		put32(bytes, 28, uint32_t(metadata.st_dev));
		put32(bytes, 32, uint32_t(uint64_t(metadata.st_size) >> 32));
		put32(bytes, 36, uint32_t(metadata.st_size));
		put32(bytes, 40, uint32_t(metadata.st_nlink));
		put32(bytes, 44, uint32_t(uint64_t(metadata.st_ino) >> 32));
		put32(bytes, 48, uint32_t(metadata.st_ino));
		call.write(call[1], bytes);
		call.ret(1);
	});
	registry.add("GetFinalPathNameByHandleW", 4, [&, resolve, missing, file_of](ApiCall &call) {
		const auto file = file_of(call[0]);
		if (!file) {
			call.fail(6);
			return;
		}
		const auto text = u"\\\\?\\" + file->dos_path;
		const size_t capacity = call.u32(2);
		const size_t length = call.put_wide(call[1], text, capacity);
		call.ret(capacity > length ? length : length + 1);
	});
	registry.add("GetFileAttributesW", 1, [&, resolve, missing, file_of](ApiCall &call) {
		call.ret(UINT32_MAX);
		const auto name = call.wide(call[0]);
		const auto resolved = resolve(call, name);
		struct stat metadata{};
		if (!resolved)
			return;
		if (NativePaths::device(name)) {
			call.ret(attribute_archive);
			return;
		}
		if (!resolved->exists || ::stat(resolved->host.c_str(), &metadata)) {
			call.set_last_error(missing(*resolved));
			return;
		}
		call.set_last_error(0);
		call.ret(attributes_of(metadata, resolved->host));
	});
	registry.add("GetFileAttributesExW", 3, [&, resolve, missing, file_of](ApiCall &call) {
		const auto name = call.wide(call[0]);
		if (call.u32(1) != 0) {
			call.fail(87);
			return;
		}
		const auto resolved = resolve(call, name);
		if (!resolved)
			return;
		if (!resolved->exists) {
			call.set_last_error(missing(*resolved));
			return;
		}
		call.write(call[2], attribute_data(entry_of(resolved->host, u"")));
		call.ret(1);
	});
	registry.add("SetFileAttributesW", 2, [&, resolve, missing, file_of](ApiCall &call) {
		const auto resolved = resolve(call, call.wide(call[0]));
		if (!resolved)
			return;
		struct stat metadata{};
		if (!resolved->exists || ::stat(resolved->host.c_str(), &metadata)) {
			call.set_last_error(missing(*resolved));
			return;
		}
		mode_t mode = metadata.st_mode & 07777;
		mode = call.u32(1) & attribute_readonly ? mode & ~0222 : mode | 0200;
		if (::chmod(resolved->host.c_str(), mode)) {
			call.fail(error_of(errno));
			return;
		}
		call.ret(1);
	});
	registry.add("CreateDirectoryW", 2, [&, resolve, missing, file_of](ApiCall &call) {
		const auto resolved = resolve(call, call.wide(call[0]));
		if (!resolved)
			return;
		if (resolved->exists) {
			call.set_last_error(183);
			return;
		}
		if (::mkdir(resolved->host.c_str(), 0777)) {
			call.fail(error_of(errno, !resolved->parent_exists));
			return;
		}
		call.ret(1);
	});
	registry.add("RemoveDirectoryW", 1, [&, resolve, missing, file_of](ApiCall &call) {
		const auto resolved = resolve(call, call.wide(call[0]));
		if (!resolved)
			return;
		if (::rmdir(resolved->host.c_str())) {
			call.fail(error_of(errno, !resolved->parent_exists));
			return;
		}
		call.ret(1);
	});
	registry.add("DeleteFileW", 1, [&, resolve, missing, file_of](ApiCall &call) {
		const auto resolved = resolve(call, call.wide(call[0]));
		if (!resolved)
			return;
		if (::unlink(resolved->host.c_str())) {
			call.fail(errno == EISDIR ? 5 : error_of(errno, !resolved->parent_exists));
			return;
		}
		call.ret(1);
	});
	const auto copy_file = [&, missing](ApiCall &call, const NativePaths::Resolved &from, const NativePaths::Resolved &to, bool fail_if_exists) {
		if (!from.exists) {
			call.set_last_error(missing(from));
			return;
		}
		if (to.exists && fail_if_exists) {
			call.set_last_error(80);
			return;
		}
		const int source = ::open(from.host.c_str(), O_RDONLY | O_CLOEXEC);
		if (source < 0) {
			call.fail(error_of(errno));
			return;
		}
		struct stat metadata{};
		::fstat(source, &metadata);
		const int target = ::open(to.host.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, metadata.st_mode & 0777);
		if (target < 0) {
			const int error = errno;
			::close(source);
			call.fail(error_of(error, !to.parent_exists));
			return;
		}
		std::vector<char> buffer(1 << 16);
		bool good = true;
		for (;;) {
			const ssize_t count = ::read(source, buffer.data(), buffer.size());
			if (count <= 0) {
				good = count == 0;
				break;
			}
			if (::write(target, buffer.data(), size_t(count)) != count) {
				good = false;
				break;
			}
		}
		const int error = errno;
		::close(source);
		::close(target);
		if (!good) {
			call.fail(error_of(error));
			return;
		}
		call.ret(1);
	};
	registry.add("CopyFileW", 3, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		const auto from = resolve(call, call.wide(call[0]));
		const auto to = from ? resolve(call, call.wide(call[1])) : std::nullopt;
		if (from && to)
			copy_file(call, *from, *to, call.u32(2));
	});
	registry.add("CopyFileExW", 6, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		const auto from = resolve(call, call.wide(call[0]));
		const auto to = from ? resolve(call, call.wide(call[1])) : std::nullopt;
		if (from && to)
			copy_file(call, *from, *to, call.u32(5) & 1);
	});
	registry.add("MoveFileExW", 3, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		const auto from = resolve(call, call.wide(call[0]));
		if (!from)
			return;
		const auto flags = call.u32(2);
		if (!call[1]) {
			call.fail(87);
			return;
		}
		const auto to = resolve(call, call.wide(call[1]));
		if (!to)
			return;
		if (!from->exists) {
			call.set_last_error(missing(*from));
			return;
		}
		if (to->exists && !(flags & 1)) {
			call.set_last_error(183);
			return;
		}
		if (::rename(from->host.c_str(), to->host.c_str())) {
			if (errno == EXDEV && (flags & 2)) {
				copy_file(call, *from, *to, false);
				if (call.result)
					::unlink(from->host.c_str());
				return;
			}
			call.fail(error_of(errno, !to->parent_exists));
			return;
		}
		call.ret(1);
	});
	registry.add("MoveFileW", 2, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		const auto from = resolve(call, call.wide(call[0]));
		const auto to = from ? resolve(call, call.wide(call[1])) : std::nullopt;
		if (!from || !to)
			return;
		if (!from->exists) {
			call.set_last_error(missing(*from));
			return;
		}
		if (to->exists) {
			call.set_last_error(183);
			return;
		}
		if (::rename(from->host.c_str(), to->host.c_str())) {
			call.fail(error_of(errno, !to->parent_exists));
			return;
		}
		call.ret(1);
	});
	registry.add("ReplaceFileW", 6, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		const auto replaced = resolve(call, call.wide(call[0]));
		const auto replacement = resolve(call, call.wide(call[1]));
		if (!replaced || !replacement)
			return;
		if (!replaced->exists) {
			call.set_last_error(1176);
			return;
		}
		if (!replacement->exists) {
			call.set_last_error(1177);
			return;
		}
		if (call[2]) {
			const auto backup = resolve(call, call.wide(call[2]));
			if (!backup)
				return;
			copy_file(call, *replaced, *backup, false);
			if (!call.result) {
				call.set_last_error(1175);
				return;
			}
			call.result = 0;
		}
		if (::rename(replacement->host.c_str(), replaced->host.c_str())) {
			call.fail(1175);
			return;
		}
		call.ret(1);
	});
	registry.add("GetCurrentDirectoryW", 2, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		const auto &text = paths.current();
		const size_t capacity = call.u32(0);
		const size_t length = text.size() > 3 ? text.size() : 3;
		call.put_wide(call[1], text.size() == 2 ? text + u"\\" : text, capacity);
		call.ret(capacity > length ? length : length + 1);
	});
	registry.add("SetCurrentDirectoryW", 1, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		if (!paths.set_current(call.wide(call[0]))) {
			call.fail(2);
			return;
		}
		call.ret(1);
	});
	registry.add("GetFullPathNameW", 4, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		const auto name = call.wide(call[0]);
		if (name.empty()) {
			call.fail(87);
			return;
		}
		const auto text = paths.full(name);
		if (text.empty()) {
			call.fail(123);
			return;
		}
		const size_t capacity = call.u32(1);
		if (capacity <= text.size()) {
			call.ret(text.size() + 1);
			return;
		}
		call.put_wide(call[2], text, capacity);
		if (call[3]) {
			const auto slash = text.find_last_of(u'\\');
			call.store<uint64_t>(call[3], slash == text.npos || slash + 1 == text.size() ? 0 : call[2] + (slash + 1) * 2);
		}
		call.ret(text.size());
	});
	registry.add("GetLongPathNameW", 3, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		const auto name = call.wide(call[0]);
		const auto resolved = resolve(call, name);
		if (!resolved)
			return;
		if (!resolved->exists) {
			call.set_last_error(missing(*resolved));
			return;
		}
		const auto text = paths.dos(resolved->host);
		const size_t capacity = call.u32(2);
		call.put_wide(call[1], text, capacity);
		call.ret(capacity > text.size() ? text.size() : text.size() + 1);
	});
	registry.add("GetTempPathW", 2, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		auto text = paths.temporary();
		const size_t capacity = call.u32(0);
		call.put_wide(call[1], text, capacity);
		call.ret(capacity > text.size() ? text.size() : text.size() + 1);
	});
	// The classic form reports clusters of eight 512-byte sectors, each count clamped to what a 32-bit field holds.
	registry.add("GetDiskFreeSpaceW", 5, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		const auto resolved = call[0] ? resolve(call, call.wide(call[0])) : paths.resolve(paths.current());
		if (!resolved)
			return;
		struct statvfs info{};
		auto path = resolved->host;
		while (!std::filesystem::exists(path) && path.has_parent_path() && path != path.parent_path())
			path = path.parent_path();
		if (::statvfs(path.c_str(), &info)) {
			call.fail(error_of(errno));
			return;
		}
		constexpr uint64_t cluster = 8 * 512;
		const auto clamp = [](uint64_t value) { return uint32_t(std::min<uint64_t>(value, UINT32_MAX)); };
		if (call[1]) call.store<uint32_t>(call[1], 8);
		if (call[2]) call.store<uint32_t>(call[2], 512);
		if (call[3]) call.store<uint32_t>(call[3], clamp(uint64_t(info.f_bavail) * info.f_frsize / cluster));
		if (call[4]) call.store<uint32_t>(call[4], clamp(uint64_t(info.f_blocks) * info.f_frsize / cluster));
		call.ret(1);
	});
	// GetTempFileName: a zero unique value picks a free name and creates the file; any other value only forms the name.
	registry.add("GetTempFileNameW", 4, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		const auto directory = call.wide(call[0]);
		auto prefix = call.wide(call[1]);
		if (prefix.size() > 3)
			prefix.resize(3);
		const uint32_t requested = call.u32(2) & 0xffff;
		const auto name_for = [&](uint32_t unique) {
			static constexpr char digits[] = "0123456789abcdef";
			std::u16string name = directory;
			if (name.empty() || (name.back() != u'\\' && name.back() != u'/'))
				name.push_back(u'\\');
			name += prefix;
			bool started = false;
			for (int shift = 12; shift >= 0; shift -= 4) {
				const auto digit = (unique >> shift) & 15;
				if (digit || started || shift == 0) {
					name.push_back(char16_t(digits[digit]));
					started = true;
				}
			}
			return name + u".tmp";
		};
		uint32_t unique = requested;
		std::u16string name;
		if (requested) {
			name = name_for(unique);
		} else {
			static uint32_t counter = 0;
			for (unsigned tries = 0; tries < 0x10000; ++tries) {
				unique = ((::getpid() * 7919U) + (++counter) * 31U + tries) & 0xffff;
				if (!unique)
					continue;
				name = name_for(unique);
				const auto resolved = paths.resolve(name);
				if (!resolved) {
					call.fail(123);
					return;
				}
				if (!resolved->parent_exists) {
					call.fail(3);
					return;
				}
				const int descriptor = ::open(resolved->host.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
				if (descriptor >= 0) {
					::close(descriptor);
					break;
				}
				if (errno != EEXIST) {
					call.fail(error_of(errno));
					return;
				}
				name.clear();
			}
			if (name.empty()) {
				call.fail(80);
				return;
			}
		}
		if (name.size() >= 260) {
			call.fail(111);
			return;
		}
		call.put_wide(call[3], name, 260);
		call.ret(unique);
	});
	// There are no 8.3 aliases in the prefix, so the short form of an existing path is its own long form.
	registry.add("GetShortPathNameW", 3, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		const auto text = call.wide(call[0]);
		const auto resolved = resolve(call, text);
		if (!resolved)
			return;
		if (!resolved->exists) {
			call.fail(missing(*resolved));
			return;
		}
		const auto full = paths.full(text);
		const size_t capacity = call.u32(2);
		call.put_wide(call[1], full, capacity);
		call.ret(capacity > full.size() ? full.size() : full.size() + 1);
	});
	// SearchPath: the program's directory, the current directory, the system directories, then the path named by the caller.
	registry.add("SearchPathW", 6, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		auto file = call.wide(call[1]);
		if (file.empty()) {
			call.fail(87);
			return;
		}
		if (call[2] && file.find(u'.') == std::u16string::npos)
			file += call.wide(call[2]);
		std::vector<std::u16string> directories;
		if (call[0]) {
			directories.push_back(call.wide(call[0]));
		} else {
			const auto &image = context.launch.image_path;
			const auto slash = image.find_last_of(u'\\');
			if (slash != std::u16string::npos)
				directories.push_back(image.substr(0, slash));
			directories.push_back(paths.current());
			directories.push_back(u"C:\\Windows\\System32");
			directories.push_back(u"C:\\Windows");
		}
		for (const auto &directory : directories) {
			std::u16string candidate = directory;
			if (candidate.empty() || candidate.back() != u'\\')
				candidate.push_back(u'\\');
			candidate += file;
			const auto resolved = paths.resolve(candidate);
			if (!resolved || !resolved->exists || !std::filesystem::is_regular_file(resolved->host))
				continue;
			const auto full = paths.full(candidate);
			const size_t capacity = call.u32(3);
			if (capacity > full.size()) {
				call.put_wide(call[4], full, capacity);
				if (call[5]) {
					const auto slash = full.find_last_of(u'\\');
					call.store_pointer(call[5], call[4] + (slash == std::u16string::npos ? 0 : slash + 1) * 2);
				}
			}
			call.ret(capacity > full.size() ? full.size() : full.size() + 1);
			return;
		}
		call.fail(2);
	});
	registry.add("GetDiskFreeSpaceExW", 4, [&, resolve, missing, file_of, copy_file](ApiCall &call) {
		const auto resolved = call[0] ? resolve(call, call.wide(call[0])) : paths.resolve(paths.current());
		if (!resolved)
			return;
		struct statvfs info{};
		auto path = resolved->host;
		while (!std::filesystem::exists(path) && path.has_parent_path() && path != path.parent_path())
			path = path.parent_path();
		if (::statvfs(path.c_str(), &info)) {
			call.fail(error_of(errno));
			return;
		}
		if (call[1]) call.store<uint64_t>(call[1], uint64_t(info.f_bavail) * info.f_frsize);
		if (call[2]) call.store<uint64_t>(call[2], uint64_t(info.f_blocks) * info.f_frsize);
		if (call[3]) call.store<uint64_t>(call[3], uint64_t(info.f_bfree) * info.f_frsize);
		call.ret(1);
	});
	const auto find_first = [&](ApiCall &call, uint64_t name_argument, uint64_t data_argument) {
		call.ret(invalid_handle);
		const auto pattern_text = call.wide(call[name_argument]);
		const auto path = paths.full(pattern_text);
		if (path.empty()) {
			call.set_last_error(123);
			return;
		}
		const auto slash = path.find_last_of(u'\\');
		const auto directory = path.substr(0, slash == 2 ? 3 : slash);
		const auto pattern = path.substr(slash + 1);
		const auto resolved = paths.resolve(directory);
		if (!resolved || !resolved->exists) {
			call.set_last_error(3);
			return;
		}
		auto found = std::make_shared<FindObject>();
		const bool wild = pattern.find_first_of(u"*?<>") != pattern.npos;
		std::vector<std::u16string> names;
		if (wild) {
			DIR *handle = ::opendir(resolved->host.c_str());
			if (!handle) {
				call.set_last_error(error_of(errno));
				return;
			}
			while (const auto *item = ::readdir(handle)) {
				const auto name = from_utf8(item->d_name);
				if (directory.size() <= 3 && (name == u"." || name == u".."))
					continue;
				if (wildcard(pattern, name))
					names.push_back(name);
			}
			::closedir(handle);
		} else {
			const auto target = paths.resolve(path);
			if (target && target->exists)
				names.push_back(from_utf8(target->host.filename().string()));
		}
		std::sort(names.begin(), names.end(), [](const auto &a, const auto &b) { return compare_fold(a, b) < 0; });
		for (const auto &name : names)
			found->entries.push_back(entry_of(resolved->host / to_utf8(name), name));
		if (found->entries.empty()) {
			call.set_last_error(wild ? 2 : (paths.resolve(path) && paths.resolve(path)->parent_exists ? 2 : 3));
			return;
		}
		call.write(call[data_argument], find_data(found->entries[0]));
		found->next = 1;
		const auto made = objects.add_object(found);
		{ if (!made.status && inheritable_handle(call, optional_argument(call, 3))) objects.set_inherit(made.value, true); call.ret(made.status ? invalid_handle : made.value); }
		call.set_last_error(0);
	};
	registry.add("FindFirstFileW", 2, [find_first](ApiCall &call) { find_first(call, 0, 1); });
	registry.add("FindFirstFileExW", 6, [find_first](ApiCall &call) {
		if (call.u32(1) > 1 || call.u32(3) > 2) {
			call.fail(87, invalid_handle);
			return;
		}
		find_first(call, 0, 2);
	});
	registry.add("FindNextFileW", 2, [&, resolve, missing, file_of, copy_file, find_first](ApiCall &call) {
		const auto found = objects.object_as<FindObject>(call[0]);
		if (!found) {
			call.fail(6);
			return;
		}
		if (found->next >= found->entries.size()) {
			call.fail(18);
			return;
		}
		call.write(call[1], find_data(found->entries[found->next++]));
		call.ret(1);
	});
	registry.add("FindClose", 1, [&, resolve, missing, file_of, copy_file, find_first](ApiCall &call) {
		if (!objects.object_as<FindObject>(call[0])) {
			call.fail(6);
			return;
		}
		objects.close(call[0]);
		call.ret(1);
	});
	registry.add("GetDriveTypeW", 1, [&, resolve, missing, file_of, copy_file, find_first](ApiCall &call) {
		// DRIVE_FIXED for mapped drives, DRIVE_NO_ROOT_DIR for letters without a mapping.
		const auto root = call[0] ? paths.resolve(call.wide(call[0])) : paths.resolve(paths.current());
		call.ret(root && root->exists ? 3 : 1);
	});
	registry.add("DuplicateHandle", 7, [&, resolve, missing, file_of, find_first, copy_file](ApiCall &call) {
		constexpr uint64_t current = UINT64_MAX;
		constexpr uint32_t same_access = 0x2, close_source = 0x1;
		const bool from_self = call[0] == current || objects.object_as<SelfProcessObject>(call[0]);
		const bool to_self = call[2] == current || objects.object_as<SelfProcessObject>(call[2]);
		if (!from_self || !to_self) {
			// A handle can reach another process only through the channel to it, which carries no handles yet.
			call.fail(50);
			return;
		}
		if (!call[3] && !(call.u32(6) & close_source)) {
			call.fail(87);
			return;
		}
		// The current-thread pseudo handle duplicates into a real handle to the calling thread; the current-process one into the process itself.
		std::optional<uint32_t> narrowed;
		const bool section = objects.object_as<SectionObject>(call[1]) != nullptr;
		if (section && !(call.u32(6) & same_access)) {
			// A copy cannot carry rights the original lacks; asking for them is refused.
			const uint32_t held = objects.access_of(call[1]);
			uint32_t wanted = call.u32(4);
			if (wanted & (0x10000000U | 0x02000000U))
				wanted = held;
			if (wanted & ~held) {
				call.fail(5);
				return;
			}
			narrowed = wanted;
		}
		const auto made = call[1] == UINT64_MAX - 1 && call[0] == UINT64_MAX ?
			objects.add_object(std::make_shared<ThreadObject>(context.threads.find(context.threads.current_id()))) :
			call[1] == UINT64_MAX ? objects.add_object(std::make_shared<SelfProcessObject>()) : objects.duplicate(call[1], narrowed);
		if (made.status) {
			call.fail(6);
			return;
		}
		if (call.u32(5))
			objects.set_inherit(made.value, true);
		if (call[3])
			call.store_pointer(call[3], made.value);
		// DUPLICATE_CLOSE_SOURCE closes the original whatever else happens.
		if ((call.u32(6) & close_source) && call[1] != UINT64_MAX && call[1] != UINT64_MAX - 1)
			objects.close(call[1]);
		call.ret(1);
	});
}

}
