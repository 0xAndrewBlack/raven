#include "kernel_context.h"
#include "text.h"

#include <algorithm>
#include <cstring>
#include <map>

namespace raven {

namespace {

constexpr uint64_t current_process = UINT64_MAX;

// Whether the guest range can be read, and optionally written back unchanged.
bool accessible(ApiCall &call, uint64_t address, size_t size, bool writable)
{
	if (!size)
		return true;
	try {
		const auto bytes = call.read(address, size);
		if (writable)
			call.write(address, bytes);
		return true;
	} catch (const ApiFault &) {
		return false;
	}
}

std::u16string atom_text(ApiCall &call, uint64_t name)
{
	return call.wide(name, 256);
}

int compare_text(const std::string &left, const std::string &right, uint32_t flags)
{
	const bool ignore_case = flags & 1;
	const size_t length = std::min(left.size(), right.size());
	for (size_t i = 0; i < length; ++i) {
		auto a = static_cast<unsigned char>(left[i]), b = static_cast<unsigned char>(right[i]);
		if (ignore_case) {
			a = static_cast<unsigned char>(std::tolower(a));
			b = static_cast<unsigned char>(std::tolower(b));
		}
		if (a != b)
			return a < b ? 1 : 3;
	}
	return left.size() == right.size() ? 2 : left.size() < right.size() ? 1 : 3;
}

}

void register_process_api(ApiRegistry &registry, KernelContext &context)
{
	registry.add("DisableThreadLibraryCalls", 1, [](ApiCall &call) { call.ret(1); });
	registry.add("FreeLibraryWhenCallbackReturns", 2, [](ApiCall &call) { call.ret(0); });
	registry.add("GetProcessVersion", 1, [](ApiCall &call) { call.ret(0x0006000a); });
	registry.add("FreeResource", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("CancelIo", 1, [](ApiCall &call) { call.ret(1); });
	registry.add("ReadDirectoryChangesW", 8, [](ApiCall &call) { call.fail(50, 0); });
	registry.add("FindFirstStreamW", 4, [](ApiCall &call) { call.fail(38, UINT64_MAX); });
	registry.add("TerminateProcess", 2, [](ApiCall &call) {
		if (call[0] != current_process) {
			call.fail(5, 0);
			return;
		}
		call.process.abandon_call();
		throw ProcessExit{call.u32(1), 0};
	});
	const auto windows_directory = [](ApiCall &call, bool wide) {
		static const std::string path = "C:\\Windows";
		const size_t capacity = call.u32(1);
		if (wide) {
			const auto text = from_utf8(path);
			if (capacity <= text.size()) {
				call.ret(text.size() + 1);
				return;
			}
			call.put_wide(call[0], text, capacity);
			call.ret(text.size());
		} else {
			if (capacity <= path.size()) {
				call.ret(path.size() + 1);
				return;
			}
			call.put_narrow(call[0], path, capacity);
			call.ret(path.size());
		}
	};
	registry.add("GetWindowsDirectoryW", 2, [=](ApiCall &call) { windows_directory(call, true); });
	registry.add("GetSystemWindowsDirectoryW", 2, [=](ApiCall &call) { windows_directory(call, true); });
	registry.add("GetWindowsDirectoryA", 2, [=](ApiCall &call) { windows_directory(call, false); });
	registry.add("GetSystemWindowsDirectoryA", 2, [=](ApiCall &call) { windows_directory(call, false); });
	registry.add("lstrcatW", 2, [](ApiCall &call) {
		auto first = call.wide(call[0], 65536);
		const auto second = call.wide(call[1], 65536);
		first += second;
		call.put_wide(call[0], first, first.size() + 1);
		call.ret(call[0]);
	});

	// One atom table serves the local and global names; atoms count from 0xc000 and integer atoms pass through.
	struct Atoms {
		std::map<std::u16string, std::pair<uint16_t, uint32_t>> names;
		uint16_t next = 0xc000;
	};
	const auto atoms = std::make_shared<Atoms>();
	const auto key = [](std::u16string text) {
		for (auto &c : text)
			if (c >= 'A' && c <= 'Z')
				c = char16_t(c + 32);
		return text;
	};
	const auto add_atom = [atoms, key](ApiCall &call) {
		if (call[0] < 0x10000) {
			call.ret(call[0]);
			return;
		}
		const auto text = atom_text(call, call[0]);
		if (text.empty() || text.size() > 255) {
			call.fail(87, 0);
			return;
		}
		auto found = atoms->names.find(key(text));
		if (found == atoms->names.end()) {
			if (atoms->next == 0xffff) {
				call.fail(8, 0);
				return;
			}
			found = atoms->names.emplace(key(text), std::pair<uint16_t, uint32_t>{atoms->next++, 0}).first;
		}
		++found->second.second;
		call.ret(found->second.first);
	};
	const auto find_atom = [atoms, key](ApiCall &call) {
		if (call[0] < 0x10000) {
			call.ret(call[0]);
			return;
		}
		const auto found = atoms->names.find(key(atom_text(call, call[0])));
		if (found == atoms->names.end())
			call.fail(2, 0);
		else
			call.ret(found->second.first);
	};
	const auto delete_atom = [atoms](ApiCall &call) {
		for (auto found = atoms->names.begin(); found != atoms->names.end(); ++found)
			if (found->second.first == call.u32(0)) {
				if (--found->second.second == 0)
					atoms->names.erase(found);
				call.ret(0);
				return;
			}
		call.fail(6, call.u32(0));
	};
	const auto atom_name = [atoms](ApiCall &call) {
		for (const auto &[text, entry] : atoms->names)
			if (entry.first == call.u32(0)) {
				const size_t capacity = call.u32(2);
				if (!capacity) {
					call.fail(122, 0);
					return;
				}
				const auto copied = call.put_wide(call[1], text, capacity);
				call.ret(std::min(copied, capacity - 1));
				return;
			}
		call.fail(6, 0);
	};
	for (const auto *name : {"GlobalAddAtomW", "AddAtomW"})
		registry.add(name, 1, add_atom);
	for (const auto *name : {"GlobalFindAtomW", "FindAtomW"})
		registry.add(name, 1, find_atom);
	for (const auto *name : {"GlobalDeleteAtom", "DeleteAtom"})
		registry.add(name, 1, delete_atom);
	for (const auto *name : {"GlobalGetAtomNameW", "GetAtomNameW"})
		registry.add(name, 3, atom_name);

	// Activation contexts only select side-by-side manifests; every program runs against one fixed set of libraries.
	registry.add("CreateActCtxW", 1, [](ApiCall &call) { call.ret(0x7e000001); });
	registry.add("ActivateActCtx", 2, [](ApiCall &call) {
		if (call[1])
			call.store<uint64_t>(call[1], 1);
		call.ret(1);
	});
	registry.add("DeactivateActCtx", 2, [](ApiCall &call) { call.ret(1); });
	registry.add("ReleaseActCtx", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("GetCurrentActCtx", 1, [](ApiCall &call) {
		call.store<uint64_t>(call[0], 0);
		call.ret(1);
	});
	registry.add("IsBadReadPtr", 2, [](ApiCall &call) { call.ret(!accessible(call, call[0], call[1], false)); });
	registry.add("IsBadWritePtr", 2, [](ApiCall &call) { call.ret(!accessible(call, call[0], call[1], true)); });
	registry.add("IsBadCodePtr", 1, [](ApiCall &call) { call.ret(!accessible(call, call[0], 1, false)); });
	registry.add("IsBadStringPtrW", 2, [](ApiCall &call) {
		try {
			call.wide(call[0], std::min<size_t>(call[1] ? call[1] : 1, 1 << 20));
			call.ret(0);
		} catch (const ApiFault &) {
			call.ret(1);
		}
	});
	registry.add("IsBadStringPtrA", 2, [](ApiCall &call) {
		try {
			call.narrow(call[0], std::min<size_t>(call[1] ? call[1] : 1, 1 << 20));
			call.ret(0);
		} catch (const ApiFault &) {
			call.ret(1);
		}
	});
	registry.add("IsDBCSLeadByte", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("IsDBCSLeadByteEx", 2, [](ApiCall &call) { call.ret(0); });
	registry.add("CompareStringA", 6, [](ApiCall &call) {
		const int32_t left_count = call.i32(3), right_count = call.i32(5);
		auto left = call.narrow(call[2], left_count < 0 ? 65536 : size_t(left_count));
		auto right = call.narrow(call[4], right_count < 0 ? 65536 : size_t(right_count));
		if (left_count >= 0)
			left = call.narrow(call[2], 65536).substr(0, size_t(left_count));
		if (right_count >= 0)
			right = call.narrow(call[4], 65536).substr(0, size_t(right_count));
		call.ret(uint64_t(compare_text(left, right, call.u32(1))));
	});
	registry.add("GetStringTypeExA", 5, [](ApiCall &call) {
		// C1 classification of each byte: upper 1, lower 2, digit 4, space 8, punctuation 0x10, control 0x20, blank 0x40, hex 0x80.
		const int32_t count = call.i32(3) < 0 ? int32_t(call.narrow(call[2]).size()) : call.i32(3);
		for (int32_t i = 0; i < count; ++i) {
			const auto c = call.load<uint8_t>(call[2] + uint64_t(i));
			uint16_t type = 0;
			if (c >= 'A' && c <= 'Z') type |= 1 | 0x100;
			if (c >= 'a' && c <= 'z') type |= 2 | 0x100;
			if (c >= '0' && c <= '9') type |= 4 | 0x80;
			if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) type |= 0x80;
			if (c == ' ' || (c >= 9 && c <= 13)) type |= 8;
			if (c == ' ' || c == 9) type |= 0x40;
			if (c < 32 || c == 127) type |= 0x20;
			if (c > 32 && c < 127 && !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) type |= 0x10;
			call.store<uint16_t>(call[4] + uint64_t(i) * 2, type);
		}
		call.ret(1);
	});
	registry.add("SetStdHandle", 2, [](ApiCall &call) { call.ret(1); });
}

}
