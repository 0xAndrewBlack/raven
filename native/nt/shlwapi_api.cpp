#include "kernel_context.h"
#include "text.h"

#include <algorithm>
#include <cstring>
#include <sys/stat.h>

namespace raven {

namespace {

constexpr size_t max_path = 260;

bool separator(char16_t character)
{
	return character == u'\\' || character == u'/';
}

// Index of the file name inside a path: after the last separator or drive colon.
size_t file_name_start(std::u16string_view path)
{
	size_t start = 0;
	for (size_t at = 0; at < path.size(); ++at)
		if (separator(path[at]) || (path[at] == u':' && at == 1))
			start = at + 1;
	return start;
}

size_t extension_start(std::u16string_view path)
{
	const size_t name = file_name_start(path);
	size_t dot = std::u16string_view::npos;
	for (size_t at = name; at < path.size(); ++at)
		if (path[at] == u'.')
			dot = at;
	return dot == std::u16string_view::npos ? path.size() : dot;
}

// Length of the root part: "X:\", "\\server\share\" or a single leading separator.
size_t root_length(std::u16string_view path)
{
	if (path.size() >= 3 && path[1] == u':' && separator(path[2]))
		return 3;
	if (path.size() >= 2 && separator(path[0]) && separator(path[1])) {
		size_t at = 2, parts = 0;
		while (at < path.size() && parts < 2) {
			while (at < path.size() && !separator(path[at]))
				++at;
			++parts;
			if (at < path.size() && parts < 2)
				++at;
		}
		if (at < path.size())
			++at;
		return at;
	}
	if (!path.empty() && separator(path[0]))
		return 1;
	return 0;
}

bool is_unc_root(std::u16string_view path)
{
	return path.size() >= 2 && separator(path[0]) && separator(path[1]);
}

std::u16string canonical(std::u16string_view path)
{
	const size_t root = root_length(path);
	std::u16string result(path.substr(0, root));
	for (auto &character : result)
		if (character == u'/')
			character = u'\\';
	std::vector<std::u16string> parts;
	size_t at = root;
	const bool trailing = !path.empty() && separator(path.back()) && path.size() > root;
	while (at <= path.size()) {
		size_t end = at;
		while (end < path.size() && !separator(path[end]))
			++end;
		const auto part = path.substr(at, end - at);
		if (part == u"..") {
			if (!parts.empty())
				parts.pop_back();
		} else if (!part.empty() && part != u".") {
			parts.emplace_back(part);
		}
		if (end >= path.size())
			break;
		at = end + 1;
	}
	for (size_t index = 0; index < parts.size(); ++index) {
		if (!result.empty() && result.back() != u'\\')
			result.push_back(u'\\');
		result += parts[index];
	}
	if (trailing && !parts.empty())
		result.push_back(u'\\');
	if (result.empty())
		result = u"\\";
	return result;
}

std::u16string join(std::u16string_view directory, std::u16string_view file)
{
	if (directory.empty())
		return std::u16string(file);
	if (file.empty())
		return std::u16string(directory);
	std::u16string result(directory);
	if (!separator(result.back()))
		result.push_back(u'\\');
	result += separator(file.front()) ? file.substr(1) : file;
	return result;
}

bool absolute(std::u16string_view path)
{
	return root_length(path) > 0;
}

bool match_one(std::u16string_view spec, std::u16string_view name)
{
	size_t p = 0, n = 0, star = std::u16string_view::npos, mark = 0;
	while (n < name.size()) {
		if (p < spec.size() && (spec[p] == u'?' || equal_fold(spec.substr(p, 1), name.substr(n, 1)))) {
			++p;
			++n;
		} else if (p < spec.size() && spec[p] == u'*') {
			star = p++;
			mark = n;
		} else if (star != std::u16string_view::npos) {
			p = star + 1;
			n = ++mark;
		} else {
			return false;
		}
	}
	while (p < spec.size() && spec[p] == u'*')
		++p;
	return p == spec.size();
}

// HLS in the 0..240 range of shlwapi, from 8-bit RGB.
void rgb_to_hls(uint32_t rgb, uint16_t &hue, uint16_t &luminance, uint16_t &saturation)
{
	const int r = rgb & 255, g = (rgb >> 8) & 255, b = (rgb >> 16) & 255;
	const int maximum = std::max({r, g, b}), minimum = std::min({r, g, b});
	const int sum = maximum + minimum, difference = maximum - minimum;
	luminance = uint16_t(((sum * 240) + 255) / 510);
	if (!difference) {
		saturation = 0;
		hue = 160;
		return;
	}
	saturation = uint16_t(luminance <= 120 ? (difference * 240 + sum / 2) / sum : (difference * 240 + (510 - sum) / 2) / (510 - sum));
	const int rc = ((maximum - r) * 40 + difference / 2) / difference, gc = ((maximum - g) * 40 + difference / 2) / difference,
		bc = ((maximum - b) * 40 + difference / 2) / difference;
	int result = r == maximum ? bc - gc : g == maximum ? 80 + rc - bc : 160 + gc - rc;
	if (result < 0)
		result += 240;
	if (result > 240)
		result -= 240;
	hue = uint16_t(result);
}

int hue_component(int n1, int n2, int hue)
{
	if (hue < 0) hue += 240;
	if (hue > 240) hue -= 240;
	if (hue < 40) return n1 + ((n2 - n1) * hue + 20) / 40;
	if (hue < 120) return n2;
	if (hue < 160) return n1 + ((n2 - n1) * (160 - hue) + 20) / 40;
	return n1;
}

uint32_t hls_to_rgb(int hue, int luminance, int saturation)
{
	int r, g, b;
	if (!saturation) {
		r = g = b = luminance * 255 / 240;
	} else {
		const int m2 = luminance <= 120 ? (luminance * (240 + saturation) + 120) / 240 : luminance + saturation - (luminance * saturation + 120) / 240;
		const int m1 = 2 * luminance - m2;
		const auto scale = [](int value) { return std::clamp((value * 255 + 120) / 240, 0, 255); };
		r = scale(hue_component(m1, m2, hue + 80));
		g = scale(hue_component(m1, m2, hue));
		b = scale(hue_component(m1, m2, hue - 80));
	}
	return uint32_t(r) | uint32_t(g) << 8 | uint32_t(b) << 16;
}

std::u16string compact(std::u16string_view path, size_t capacity)
{
	if (path.size() < capacity)
		return std::u16string(path);
	if (capacity < 4)
		return std::u16string(path.substr(0, capacity ? capacity - 1 : 0));
	const size_t name = file_name_start(path);
	const auto file = path.substr(name);
	const std::u16string_view ellipsis = u"...";
	if (file.size() + ellipsis.size() + 1 >= capacity) {
		std::u16string result(file.substr(0, capacity - 1 - ellipsis.size()));
		return result + std::u16string(ellipsis);
	}
	const size_t room = capacity - 1 - ellipsis.size() - file.size();
	std::u16string result(path.substr(0, std::min(room, name)));
	return result + std::u16string(ellipsis) + std::u16string(file);
}

}

void register_shlwapi_api(ApiRegistry &registry, KernelContext &context)
{
	auto &paths = context.paths;
	// Path functions edit a MAX_PATH buffer in place; this reads it, applies the edit and writes it back.
	const auto edit = [](ApiCall &call, const std::function<bool(std::u16string &)> &change) {
		auto text = call.wide(call[0], max_path * 4);
		const bool changed = change(text);
		call.put_wide(call[0], text, max_path * 4);
		call.ret(changed);
	};
	// Completion lists are drawn by the shell; an edit control without one still works, so enabling it succeeds without a list.
	registry.add("SHAutoComplete", 2, [](ApiCall &call) { call.ret(0); });
	registry.add("PathRemoveFileSpecW", 1, [edit](ApiCall &call) {
		edit(call, [](std::u16string &path) {
			const size_t root = root_length(path);
			if (path.empty() || (path.size() == root && root))
				return false;
			const auto last = path.find_last_of(u"\\/");
			if (last == path.npos) {
				if (path.size() > 2 && path[1] == u':') {
					path.resize(2);
					return true;
				}
				path.clear();
				return true;
			}
			if (is_unc_root(path) && last < root) {
				if (last + 1 == path.size() && path.size() > root - 1 && root == path.size())
					return false;
			}
			if (last + 1 == path.size()) {
				path.pop_back();
				return true;
			}
			if (last < root && root)
				path.resize(root);
			else
				path.resize(last);
			return true;
		});
	});
	registry.add("PathStripPathW", 1, [edit](ApiCall &call) {
		edit(call, [](std::u16string &path) {
			path.erase(0, file_name_start(path));
			return true;
		});
	});
	registry.add("PathRemoveExtensionW", 1, [edit](ApiCall &call) {
		edit(call, [](std::u16string &path) {
			path.resize(extension_start(path));
			return true;
		});
	});
	registry.add("PathAddExtensionW", 2, [](ApiCall &call) {
		auto path = call.wide(call[0], max_path * 4);
		const auto extension = call[1] ? call.wide(call[1]) : u".exe";
		if (extension_start(path) != path.size()) {
			call.ret(0);
			return;
		}
		if (path.size() + extension.size() >= max_path) {
			call.ret(0);
			return;
		}
		path += extension;
		call.put_wide(call[0], path, max_path);
		call.ret(1);
	});
	registry.add("PathAppendW", 2, [](ApiCall &call) {
		auto path = call.wide(call[0], max_path * 4);
		const auto more = call.wide(call[1]);
		auto joined = canonical(join(path, more));
		if (joined.size() >= max_path) {
			call.ret(0);
			return;
		}
		call.put_wide(call[0], joined, max_path);
		call.ret(1);
	});
	registry.add("PathCombineW", 3, [](ApiCall &call) {
		const auto directory = call[1] ? call.wide(call[1]) : std::u16string();
		const auto file = call[2] ? call.wide(call[2]) : std::u16string();
		const auto combined = absolute(file) && !(separator(file[0]) && !is_unc_root(file)) ? file : join(directory, file);
		const auto result = canonical(combined);
		if (result.size() >= max_path) {
			call.ret(0);
			return;
		}
		call.put_wide(call[0], result, max_path);
		call.ret(call[0]);
	});
	registry.add("PathCanonicalizeW", 2, [](ApiCall &call) {
		const auto result = canonical(call.wide(call[1]));
		if (result.size() >= max_path) {
			call.fail(206);
			return;
		}
		call.put_wide(call[0], result, max_path);
		call.ret(1);
	});
	registry.add("PathIsRelativeW", 1, [](ApiCall &call) {
		const auto path = call.wide(call[0]);
		call.ret(path.empty() || !(root_length(path) > 0));
	});
	registry.add("PathIsRootW", 1, [](ApiCall &call) {
		const auto path = call.wide(call[0]);
		call.ret(!path.empty() && root_length(path) == path.size());
	});
	registry.add("PathIsUNCW", 1, [](ApiCall &call) { call.ret(is_unc_root(call.wide(call[0]))); });
	registry.add("PathIsNetworkPathW", 1, [](ApiCall &call) { call.ret(is_unc_root(call.wide(call[0]))); });
	registry.add("PathIsFileSpecW", 1, [](ApiCall &call) { call.ret(call.wide(call[0]).find_first_of(u"\\/:") == std::u16string::npos); });
	registry.add("PathGetDriveNumberW", 1, [](ApiCall &call) {
		const auto path = call.wide(call[0]);
		if (path.size() >= 2 && path[1] == u':' && ((path[0] >= u'a' && path[0] <= u'z') || (path[0] >= u'A' && path[0] <= u'Z')))
			call.ret(uint32_t(upper_case(path[0]) - u'A'));
		else
			call.ret(uint32_t(-1));
	});
	registry.add("PathFindFileNameW", 1, [](ApiCall &call) {
		const auto path = call.wide(call[0]);
		call.ret(call[0] + file_name_start(path) * 2);
	});
	registry.add("PathFindExtensionW", 1, [](ApiCall &call) {
		const auto path = call.wide(call[0]);
		call.ret(call[0] + extension_start(path) * 2);
	});
	registry.add("PathSkipRootW", 1, [](ApiCall &call) {
		const auto path = call.wide(call[0]);
		const size_t root = root_length(path);
		call.ret(root ? call[0] + root * 2 : 0);
	});
	// The PathCch forms report through an HRESULT: E_INVALIDARG for a missing argument or root, and the strsafe overflow code when the
	// result does not fit the buffer.
	registry.add("PathCchSkipRoot", 2, [](ApiCall &call) {
		const size_t root = call[0] && call[1] ? root_length(call.wide(call[0])) : 0;
		if (!root) {
			call.ret(0x80070057U);
			return;
		}
		call.store_pointer(call[1], call[0] + root * 2);
		call.ret(0);
	});
	registry.add("PathCchCombineEx", 5, [](ApiCall &call) {
		if (!call[0] || !call[1] || call[1] > 32768 || (!call[2] && !call[3])) {
			call.ret(0x80070057U);
			return;
		}
		const auto directory = call[2] ? call.wide(call[2]) : std::u16string();
		const auto file = call[3] ? call.wide(call[3]) : std::u16string();
		const auto combined = absolute(file) && !(separator(file[0]) && !is_unc_root(file)) ? file : join(directory, file);
		const auto result = canonical(combined);
		if (result.size() >= call[1]) {
			call.store<uint16_t>(call[0], 0);
			call.ret(0x8007007aU);
			return;
		}
		call.put_wide(call[0], result, call[1]);
		call.ret(0);
	});
	registry.add("PathAddBackslashW", 1, [](ApiCall &call) {
		auto path = call.wide(call[0], max_path * 4);
		if (path.empty() || separator(path.back())) {
			call.ret(call[0] + path.size() * 2);
			return;
		}
		if (path.size() + 1 >= max_path) {
			call.ret(0);
			return;
		}
		path.push_back(u'\\');
		call.put_wide(call[0], path, max_path);
		call.ret(call[0] + path.size() * 2);
	});
	registry.add("PathRemoveBackslashW", 1, [](ApiCall &call) {
		auto path = call.wide(call[0], max_path * 4);
		if (path.size() > root_length(path) && !path.empty() && separator(path.back())) {
			path.pop_back();
			call.put_wide(call[0], path, max_path);
		}
		call.ret(call[0] + path.size() * 2);
	});
	registry.add("PathQuoteSpacesW", 1, [](ApiCall &call) {
		auto path = call.wide(call[0], max_path * 4);
		if (path.find(u' ') != path.npos && path.size() + 2 < max_path) {
			path = u"\"" + path + u"\"";
			call.put_wide(call[0], path, max_path);
		}
	});
	registry.add("PathUnquoteSpacesW", 1, [](ApiCall &call) {
		auto path = call.wide(call[0], max_path * 4);
		if (path.size() >= 2 && path.front() == u'"' && path.back() == u'"') {
			path = path.substr(1, path.size() - 2);
			call.put_wide(call[0], path, max_path);
		}
	});
	registry.add("PathMatchSpecW", 2, [](ApiCall &call) {
		const auto file = call.wide(call[0]);
		const auto spec = call.wide(call[1]);
		bool matched = false;
		size_t at = 0;
		while (at <= spec.size() && !matched) {
			const size_t end = std::min(spec.find(u';', at), spec.size());
			auto part = std::u16string_view(spec).substr(at, end - at);
			while (!part.empty() && part.front() == u' ')
				part.remove_prefix(1);
			matched = !part.empty() && match_one(part, file);
			at = end + 1;
		}
		call.ret(matched);
	});
	registry.add("PathCompactPathExW", 4, [](ApiCall &call) {
		const auto path = call.wide(call[1]);
		const size_t capacity = call.u32(2);
		if (!capacity) {
			call.ret(0);
			return;
		}
		const auto result = compact(path, capacity);
		call.put_wide(call[0], result, capacity);
		call.ret(1);
	});
	registry.add("PathFileExistsW", 1, [&](ApiCall &call) {
		const auto resolved = paths.resolve(call.wide(call[0]));
		call.ret(resolved && resolved->exists);
	});
	registry.add("PathIsDirectoryW", 1, [&](ApiCall &call) {
		const auto resolved = paths.resolve(call.wide(call[0]));
		struct stat metadata{};
		call.ret(resolved && resolved->exists && !::stat(resolved->host.c_str(), &metadata) && S_ISDIR(metadata.st_mode) ? 0x10 : 0);
	});
	registry.add("PathIsDirectoryEmptyW", 1, [&](ApiCall &call) {
		const auto resolved = paths.resolve(call.wide(call[0]));
		std::error_code error;
		call.ret(resolved && std::filesystem::is_directory(resolved->host, error) && std::filesystem::is_empty(resolved->host, error));
	});

	registry.add("StrCmpW", 2, [](ApiCall &call) {
		const auto a = call.wide(call[0]), b = call.wide(call[1]);
		call.ret(uint32_t(a < b ? -1 : a > b ? 1 : 0));
	});
	registry.add("StrCmpIW", 2, [](ApiCall &call) { call.ret(uint32_t(compare_fold(call.wide(call[0]), call.wide(call[1])))); });
	registry.add("StrCmpNW", 3, [](ApiCall &call) {
		const size_t count = call.u32(2);
		const auto a = call.wide(call[0]).substr(0, count), b = call.wide(call[1]).substr(0, count);
		call.ret(uint32_t(a < b ? -1 : a > b ? 1 : 0));
	});
	registry.add("StrCmpNIW", 3, [](ApiCall &call) {
		const size_t count = call.u32(2);
		call.ret(uint32_t(compare_fold(call.wide(call[0]).substr(0, count), call.wide(call[1]).substr(0, count))));
	});
	registry.add("StrStrW", 2, [](ApiCall &call) {
		const auto text = call.wide(call[0]), needle = call.wide(call[1]);
		const auto found = text.find(needle);
		call.ret(found == text.npos ? 0 : call[0] + found * 2);
	});
	registry.add("StrStrIW", 2, [](ApiCall &call) {
		const auto text = call.wide(call[0]), needle = call.wide(call[1]);
		for (size_t at = 0; at + needle.size() <= text.size(); ++at)
			if (equal_fold(std::u16string_view(text).substr(at, needle.size()), needle)) {
				call.ret(call[0] + at * 2);
				return;
			}
		call.ret(0);
	});
	registry.add("StrChrW", 2, [](ApiCall &call) {
		const auto text = call.wide(call[0]);
		const auto found = text.find(char16_t(call[1]));
		call.ret(found == text.npos ? 0 : call[0] + found * 2);
	});
	registry.add("StrRChrW", 3, [](ApiCall &call) {
		const auto text = call.wide(call[0]);
		const auto end = call[1] ? std::min<size_t>((call[1] - call[0]) / 2, text.size()) : text.size();
		const auto found = text.substr(0, end).rfind(char16_t(call[2]));
		call.ret(found == text.npos ? 0 : call[0] + found * 2);
	});
	registry.add("StrToIntW", 1, [](ApiCall &call) {
		const auto text = call.wide(call[0]);
		size_t at = 0;
		bool negative = false;
		if (at < text.size() && text[at] == u'-') {
			negative = true;
			++at;
		}
		int64_t value = 0;
		for (; at < text.size() && text[at] >= u'0' && text[at] <= u'9'; ++at)
			value = std::min<int64_t>(value * 10 + (text[at] - u'0'), 0x7fffffffLL + 1);
		call.ret(uint32_t(int32_t(negative ? -value : value)));
	});
	registry.add("StrTrimW", 2, [](ApiCall &call) {
		auto text = call.wide(call[0]);
		const auto trim = call.wide(call[1]);
		const auto first = text.find_first_not_of(trim);
		const bool changed = first != 0 || (!text.empty() && trim.find(text.back()) != trim.npos);
		if (first == text.npos) text.clear();
		else text = text.substr(first, text.find_last_not_of(trim) - first + 1);
		call.put_wide(call[0], text, text.size() + 1);
		call.ret(changed);
	});
	registry.add("StrCpyNW", 3, [](ApiCall &call) {
		const int32_t capacity = call.i32(2);
		const auto text = call.wide(call[1]);
		if (capacity > 0)
			call.put_wide(call[0], text.substr(0, size_t(capacity) - 1), size_t(capacity));
		call.ret(call[0]);
	});
	registry.add("StrNCatW", 3, [](ApiCall &call) {
		auto text = call.wide(call[0]);
		const int32_t capacity = call.i32(2);
		const auto more = call.wide(call[1]);
		if (capacity > int32_t(text.size() + 1)) {
			text += more.substr(0, size_t(capacity) - text.size() - 1);
			call.put_wide(call[0], text, text.size() + 1);
		}
		call.ret(call[0]);
	});
	registry.add("StrDupW", 1, [&](ApiCall &call) {
		const auto text = call.wide(call[0]);
		const auto copy = context.allocator.allocate((text.size() + 1) * 2, false);
		if (!copy) {
			call.ret(0);
			return;
		}
		call.put_wide(copy, text, text.size() + 1);
		call.ret(copy);
	});
	registry.add("StrFormatByteSizeW", 3, [](ApiCall &call) {
		const uint64_t value = call[0];
		static constexpr const char *units[] = {" bytes", " KB", " MB", " GB", " TB", " PB", " EB"};
		std::string text;
		if (value < 1024) {
			text = std::to_string(value) + units[0];
		} else {
			double scaled = double(value);
			size_t unit = 0;
			while (scaled >= 1024 && unit < 6) {
				scaled /= 1024;
				++unit;
			}
			// Windows shows three significant digits.
			char buffer[32];
			const int decimals = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
			std::snprintf(buffer, sizeof buffer, "%.*f", decimals, scaled);
			text = std::string(buffer) + units[unit];
		}
		call.put_wide(call[1], widen_ascii(text), call.u32(2));
		call.ret(call[1]);
	});

	registry.add("ColorRGBToHLS", 4, [](ApiCall &call) {
		uint16_t hue, luminance, saturation;
		rgb_to_hls(call.u32(0), hue, luminance, saturation);
		if (call[1]) call.store<uint16_t>(call[1], hue);
		if (call[2]) call.store<uint16_t>(call[2], luminance);
		if (call[3]) call.store<uint16_t>(call[3], saturation);
	});
	registry.add("ColorHLSToRGB", 3, [](ApiCall &call) {
		call.ret(hls_to_rgb(int(call[0] & 0xffff), int(call[1] & 0xffff), int(call[2] & 0xffff)));
	});
	registry.add("ColorAdjustLuma", 3, [](ApiCall &call) {
		const uint32_t color = call.u32(0);
		const int32_t amount = call.i32(1);
		if (!amount) {
			call.ret(color);
			return;
		}
		uint16_t hue, luminance, saturation;
		rgb_to_hls(color, hue, luminance, saturation);
		int value = luminance;
		if (call.u32(2))
			value = value * (1000 + amount) / 1000;
		else
			value += amount * 240 / 1000;
		call.ret(hls_to_rgb(hue, std::clamp(value, 0, 240), saturation));
	});
	registry.add("AssocQueryStringW", 6, [](ApiCall &call) { call.ret(0x80070483U); });
}

}
