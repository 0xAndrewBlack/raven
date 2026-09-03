#include "access_token.h"
#include "kernel_context.h"

#include <map>

#include <algorithm>
#include <cstring>
#include <string>

namespace raven {

namespace {

constexpr uint16_t owner_defaulted = 0x1, group_defaulted = 0x2, dacl_present = 0x4, dacl_defaulted = 0x8, sacl_present = 0x10, sacl_defaulted = 0x20;
constexpr size_t acl_header = 8;

// Where the fields of an absolute security descriptor sit: the four pointers follow the revision and the control word,
// so they start at 4 for a 32-bit program and at 8 for a 64-bit one.
struct Layout {
	size_t size, owner, group, sacl, dacl;
};

Layout layout_of(const ApiCall &call)
{
	const size_t width = call.pointer_width();
	const size_t first = width == 4 ? 4 : 8;
	return {first + 4 * width, first, first + width, first + 2 * width, first + 3 * width};
}

uint32_t sid_length(ApiCall &call, uint64_t sid)
{
	return 8 + 4 * uint32_t(call.read(sid + 1, 1)[0]);
}

bool valid_sid(ApiCall &call, uint64_t sid)
{
	if (!sid)
		return false;
	try {
		const auto header = call.read(sid, 2);
		return header[0] == 1 && header[1] >= 1 && header[1] <= 15;
	} catch (const ApiFault &) {
		return false;
	}
}

}

void register_security_api(ApiRegistry &registry, KernelContext &context)
{
	auto &objects = context.objects;
	registry.add("InitializeSecurityDescriptor", 2, [](ApiCall &call) {
		if (!call[0]) {
			call.fail(87);
			return;
		}
		if (call.u32(1) != 1) {
			call.fail(1305);
			return;
		}
		std::vector<uint8_t> descriptor(layout_of(call).size);
		descriptor[0] = 1;
		call.write(call[0], descriptor);
		call.ret(1);
	});
	const auto control = [](ApiCall &call, uint16_t set, uint16_t clear) {
		auto value = call.load<uint16_t>(call[0] + 2);
		value = uint16_t((value & ~clear) | set);
		call.store<uint16_t>(call[0] + 2, value);
	};
	registry.add("SetSecurityDescriptorOwner", 3, [control](ApiCall &call) {
		if (!call[0] || call.read(call[0], 1)[0] != 1) {
			call.fail(1338);
			return;
		}
		call.store_pointer(call[0] + layout_of(call).owner, call[1]);
		control(call, call.u32(2) ? owner_defaulted : 0, owner_defaulted);
		call.ret(1);
	});
	registry.add("SetSecurityDescriptorGroup", 3, [control](ApiCall &call) {
		if (!call[0] || call.read(call[0], 1)[0] != 1) {
			call.fail(1338);
			return;
		}
		call.store_pointer(call[0] + layout_of(call).group, call[1]);
		control(call, call.u32(2) ? group_defaulted : 0, group_defaulted);
		call.ret(1);
	});
	registry.add("SetSecurityDescriptorDacl", 4, [control](ApiCall &call) {
		if (!call[0] || call.read(call[0], 1)[0] != 1) {
			call.fail(1338);
			return;
		}
		const bool present = call.u32(1) != 0;
		call.store_pointer(call[0] + layout_of(call).dacl, present ? call[2] : 0);
		control(call, uint16_t((present ? dacl_present : 0) | (call.u32(3) ? dacl_defaulted : 0)), dacl_present | dacl_defaulted);
		call.ret(1);
	});
	registry.add("SetSecurityDescriptorSacl", 4, [control](ApiCall &call) {
		if (!call[0] || call.read(call[0], 1)[0] != 1) {
			call.fail(1338);
			return;
		}
		const bool present = call.u32(1) != 0;
		call.store_pointer(call[0] + layout_of(call).sacl, present ? call[2] : 0);
		control(call, uint16_t((present ? sacl_present : 0) | (call.u32(3) ? sacl_defaulted : 0)), sacl_present | sacl_defaulted);
		call.ret(1);
	});
	registry.add("IsValidSecurityDescriptor", 1, [](ApiCall &call) {
		if (!call[0]) {
			call.fail(87);
			return;
		}
		call.ret(call.read(call[0], 1)[0] == 1);
	});
	registry.add("GetLengthSid", 1, [](ApiCall &call) { call.ret(sid_length(call, call[0])); });
	registry.add("IsValidSid", 1, [](ApiCall &call) { call.ret(valid_sid(call, call[0])); });
	registry.add("EqualSid", 2, [](ApiCall &call) {
		if (!valid_sid(call, call[0]) || !valid_sid(call, call[1])) {
			call.fail(1337);
			return;
		}
		const auto length = sid_length(call, call[0]);
		call.ret(length == sid_length(call, call[1]) && call.read(call[0], length) == call.read(call[1], length));
	});
	registry.add("CopySid", 3, [](ApiCall &call) {
		if (!valid_sid(call, call[2])) {
			call.fail(1337);
			return;
		}
		const auto length = sid_length(call, call[2]);
		if (call.u32(0) < length) {
			call.fail(122);
			return;
		}
		call.write(call[1], call.read(call[2], length));
		call.ret(1);
	});
	// An access control list is a header followed by its entries: the size of the whole, and how many entries it holds.
	registry.add("InitializeAcl", 3, [](ApiCall &call) {
		const uint32_t length = call.u32(1);
		if (call.u32(2) < 2 || call.u32(2) > 4) {
			call.fail(87);
			return;
		}
		if (length < acl_header || length > 0xffff) {
			call.fail(122);
			return;
		}
		std::vector<uint8_t> header(acl_header);
		header[0] = uint8_t(call.u32(2));
		const uint16_t size = uint16_t(length);
		std::memcpy(header.data() + 2, &size, 2);
		call.write(call[0], header);
		call.ret(1);
	});
	const auto add_ace = [](ApiCall &call, uint8_t type) {
		if (!valid_sid(call, call[3])) {
			call.fail(1337);
			return;
		}
		const auto header = call.read(call[0], acl_header);
		uint16_t size, count;
		std::memcpy(&size, header.data() + 2, 2);
		std::memcpy(&count, header.data() + 4, 2);
		uint32_t used = acl_header;
		for (uint16_t index = 0; index < count; ++index) {
			const auto entry = call.read(call[0] + used, 4);
			uint16_t entry_size;
			std::memcpy(&entry_size, entry.data() + 2, 2);
			used += entry_size;
		}
		const auto length = sid_length(call, call[3]);
		const uint32_t entry_size = 8 + length;
		if (used + entry_size > size) {
			call.fail(122);
			return;
		}
		std::vector<uint8_t> entry(entry_size);
		entry[0] = type;
		const uint16_t entry_size16 = uint16_t(entry_size);
		const uint32_t mask = call.u32(2);
		std::memcpy(entry.data() + 2, &entry_size16, 2);
		std::memcpy(entry.data() + 4, &mask, 4);
		const auto sid = call.read(call[3], length);
		std::memcpy(entry.data() + 8, sid.data(), length);
		call.write(call[0] + used, entry);
		call.store<uint16_t>(call[0] + 4, uint16_t(count + 1));
		call.ret(1);
	};
	// Token information: the account is one fixed user in the Users group at medium integrity, not elevated, in session 1.
	registry.add("GetTokenInformation", 5, [&objects](ApiCall &call) {
		if (!objects.object_as<AccessToken>(call[0])) {
			call.fail(6);
			return;
		}
		const size_t width = call.pointer_width();
		const size_t record = width == 4 ? 8 : 16;
		std::vector<uint8_t> data;
		// A structure that holds a SID: the pointer sits in the structure and points at the SID placed after it.
		const auto with_sid = [&](const std::vector<uint8_t> &sid, uint32_t attributes, bool pair) {
			const size_t head = pair ? record : width;
			data.assign(head + sid.size(), 0);
			const uint64_t at = call[2] + head;
			std::memcpy(data.data(), &at, width);
			if (pair)
				std::memcpy(data.data() + width, &attributes, 4);
			std::memcpy(data.data() + head, sid.data(), sid.size());
		};
		switch (call.u32(1)) {
		case 1: with_sid(user_sid(), 0, true); break;
		case 4: with_sid(user_sid(), 0, false); break;
		case 5: with_sid(make_sid(5, {21, 1000, 1000, 1000, 513}), 0, false); break;
		case 2: {
			// TOKEN_GROUPS: a count, then SID_AND_ATTRIBUTES entries; one group, the Users of the machine.
			const auto sid = make_sid(5, {32, 545});
			const size_t first = width == 4 ? 4 : 8;
			data.assign(first + record + sid.size(), 0);
			const uint32_t count = 1, attributes = 7;
			std::memcpy(data.data(), &count, 4);
			const uint64_t at = call[2] + first + record;
			std::memcpy(data.data() + first, &at, width);
			std::memcpy(data.data() + first + width, &attributes, 4);
			std::memcpy(data.data() + first + record, sid.data(), sid.size());
			break;
		}
		case 8: data = {1, 0, 0, 0}; break;
		case 9: data = {0, 0, 0, 0}; break;
		case 12: data = {1, 0, 0, 0}; break;
		case 18: data = {1, 0, 0, 0}; break;
		case 20: data = {0, 0, 0, 0}; break;
		case 29: data = {0, 0, 0, 0}; break;
		case 25: with_sid(make_sid(16, {8192}), 0x60, true); break;
		case 10: data.assign(56, 0); break;
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
	// A generic right becomes the specific rights the mapping names for it.
	registry.add("MapGenericMask", 2, [](ApiCall &call) {
		if (!call[0] || !call[1]) {
			call.fail(87);
			return;
		}
		auto mask = call.load<uint32_t>(call[0]);
		const auto mapping = call.read(call[1], 16);
		uint32_t specific[4];
		std::memcpy(specific, mapping.data(), 16);
		if (mask & 0x80000000U) mask |= specific[0];
		if (mask & 0x40000000U) mask |= specific[1];
		if (mask & 0x20000000U) mask |= specific[2];
		if (mask & 0x10000000U) mask |= specific[3];
		mask &= ~0xf0000000U;
		call.store<uint32_t>(call[0], mask);
	});
	// Descriptors are not kept: every object answers with the same one, so setting one changes nothing that could be read back.
	registry.add("SetSecurityInfo", 7, [&objects](ApiCall &call) { call.ret(0); });
	registry.add("SetNamedSecurityInfoW", 7, [](ApiCall &call) { call.ret(0); });
	// The access a descriptor grants to the token's account: the entries of its list in order, allow entries adding rights and deny entries
	// refusing them, for the account, its group, the users of the machine and everyone.
	registry.add("AccessCheck", 8, [&objects](ApiCall &call) {
		if (!objects.object_as<AccessToken>(call[1]) || !call[0] || !call[6] || !call[7]) {
			call.fail(call[0] && call[6] && call[7] ? 6 : 87);
			return;
		}
		uint32_t wanted = call.u32(2);
		const auto mapping = call.read(call[3], 16);
		uint32_t specific[4];
		std::memcpy(specific, mapping.data(), 16);
		if (wanted & 0x80000000U) wanted |= specific[0];
		if (wanted & 0x40000000U) wanted |= specific[1];
		if (wanted & 0x20000000U) wanted |= specific[2];
		if (wanted & 0x10000000U) wanted |= specific[3];
		wanted &= ~0xf0000000U;
		const uint64_t descriptor = call[0];
		const uint16_t control = call.load<uint16_t>(descriptor + 2);
		uint64_t acl = 0;
		if (control & dacl_present) {
			if (control & 0x8000) {
				const auto offset = call.load<uint32_t>(descriptor + 16);
				acl = offset ? descriptor + offset : 0;
			} else {
				acl = call.load_pointer(descriptor + layout_of(call).dacl);
			}
		}
		// A descriptor without a list gives everyone everything.
		uint32_t granted = 0, denied = 0;
		if (!(control & dacl_present) || !acl) {
			granted = wanted ? wanted : 0x1f01ffU;
		} else {
			const auto header = call.read(acl, acl_header);
			uint16_t count;
			std::memcpy(&count, header.data() + 4, 2);
			uint64_t at = acl + acl_header;
			const std::vector<std::vector<uint8_t>> mine{user_sid(), make_sid(5, {21, 1000, 1000, 1000, 513}), make_sid(5, {32, 545}), make_sid(1, {0}),
				make_sid(5, {11}), make_sid(5, {4}), make_sid(5, {1})};
			for (uint16_t index = 0; index < count; ++index) {
				const auto entry = call.read(at, 8);
				uint16_t size;
				std::memcpy(&size, entry.data() + 2, 2);
				uint32_t mask;
				std::memcpy(&mask, entry.data() + 4, 4);
				if (size < 12 || !valid_sid(call, at + 8)) {
					at += size ? size : 8;
					continue;
				}
				const auto sid = call.read(at + 8, sid_length(call, at + 8));
				const bool applies = std::any_of(mine.begin(), mine.end(), [&](const auto &candidate) { return candidate == sid; });
				if (applies && entry[0] == 0)
					granted |= mask & ~denied;
				else if (applies && entry[0] == 1)
					denied |= mask & ~granted;
				at += size;
			}
		}
		// MAXIMUM_ALLOWED asks for everything the descriptor grants.
		const bool maximum = wanted & 0x02000000U;
		const bool allowed = maximum ? granted != 0 : wanted && (granted & wanted) == wanted;
		call.store<uint32_t>(call[6], maximum ? granted : allowed ? wanted : 0);
		call.store<uint32_t>(call[7], allowed);
		if (!allowed)
			call.set_last_error(5);
		call.ret(1);
	});
	// A token can be copied and restricted; the copies are accounts of the same kind (the program has one identity and no enforcement
	// of restrictions), so they answer the same queries as the original.
	registry.add("DuplicateTokenEx", 6, [&objects](ApiCall &call) {
		if (!objects.object_as<AccessToken>(call[0]) || !call[5]) {
			call.fail(call[5] ? 6 : 87);
			return;
		}
		const auto made = objects.add_object(std::make_shared<AccessToken>());
		if (made.status) {
			call.fail(8);
			return;
		}
		call.store_pointer(call[5], made.value);
		call.ret(1);
	});
	registry.add("DuplicateToken", 3, [&objects](ApiCall &call) {
		if (!objects.object_as<AccessToken>(call[0]) || !call[2]) {
			call.fail(call[2] ? 6 : 87);
			return;
		}
		const auto made = objects.add_object(std::make_shared<AccessToken>());
		if (made.status) {
			call.fail(8);
			return;
		}
		call.store_pointer(call[2], made.value);
		call.ret(1);
	});
	registry.add("CreateRestrictedToken", 9, [&objects](ApiCall &call) {
		if (!objects.object_as<AccessToken>(call[0]) || !call[8]) {
			call.fail(call[8] ? 6 : 87);
			return;
		}
		const auto made = objects.add_object(std::make_shared<AccessToken>());
		if (made.status) {
			call.fail(8);
			return;
		}
		call.store_pointer(call[8], made.value);
		call.ret(1);
	});
	registry.add("SetTokenInformation", 4, [&objects](ApiCall &call) {
		if (!objects.object_as<AccessToken>(call[0])) {
			call.fail(6);
			return;
		}
		call.ret(1);
	});
	// The SIDs that exist on every system, by their well known names.
	registry.add("CreateWellKnownSid", 4, [](ApiCall &call) {
		std::vector<uint8_t> sid;
		switch (call.u32(0)) {
		case 0: sid = make_sid(0, {0}); break;
		case 1: sid = make_sid(1, {0}); break;
		case 11: case 17: sid = make_sid(5, {11}); break;
		case 12: case 36: sid = make_sid(5, {12}); break;
		case 22: sid = make_sid(5, {18}); break;
		case 23: sid = make_sid(5, {19}); break;
		case 24: sid = make_sid(5, {20}); break;
		case 26: sid = make_sid(5, {32, 544}); break;
		case 27: sid = make_sid(5, {32, 545}); break;
		case 66: sid = make_sid(16, {4096}); break;
		case 67: sid = make_sid(16, {8192}); break;
		case 68: sid = make_sid(16, {12288}); break;
		case 69: sid = make_sid(16, {16384}); break;
		default:
			call.fail(87);
			return;
		}
		if (!call[3]) {
			call.fail(87);
			return;
		}
		const uint32_t capacity = call.load<uint32_t>(call[3]);
		call.store<uint32_t>(call[3], uint32_t(sid.size()));
		if (!call[2] || capacity < sid.size()) {
			call.fail(122);
			return;
		}
		call.write(call[2], sid);
		call.ret(1);
	});
	// Every object reports the same descriptor: owned by the account, readable and usable by everyone. It comes as one self-relative block
	// that the program frees with LocalFree, and the owner, group and ACL pointers point inside it.
	const auto security_info = [&context](ApiCall &call) {
		const uint32_t wanted = call.u32(2);
		const auto owner = user_sid(), group = make_sid(5, {21, 1000, 1000, 1000, 513}), everyone = make_sid(1, {0});
		// ACL: the 8 byte header and one access allowed entry (header, mask, SID).
		const uint16_t ace_size = uint16_t(8 + everyone.size()), acl_size = uint16_t(8 + ace_size);
		std::vector<uint8_t> block(20);
		const auto place = [&](const std::vector<uint8_t> &bytes) {
			const uint32_t at = uint32_t(block.size());
			block.insert(block.end(), bytes.begin(), bytes.end());
			while (block.size() % 4)
				block.push_back(0);
			return at;
		};
		std::vector<uint8_t> acl(acl_size);
		acl[0] = 2;
		std::memcpy(acl.data() + 2, &acl_size, 2);
		const uint16_t one = 1;
		std::memcpy(acl.data() + 4, &one, 2);
		const uint32_t mask = 0x1f01ffU;
		std::memcpy(acl.data() + 10, &ace_size, 2);
		std::memcpy(acl.data() + 12, &mask, 4);
		std::memcpy(acl.data() + 16, everyone.data(), everyone.size());
		const uint32_t owner_at = place(owner), group_at = place(group), dacl_at = place(acl);
		const uint16_t control = 0x8000 | 0x4;
		block[0] = 1;
		std::memcpy(block.data() + 2, &control, 2);
		std::memcpy(block.data() + 4, &owner_at, 4);
		std::memcpy(block.data() + 8, &group_at, 4);
		std::memcpy(block.data() + 16, &dacl_at, 4);
		const auto memory = context.allocator.allocate(block.size(), true);
		if (!memory) {
			call.ret(8);
			return;
		}
		call.write(memory, block);
		if (call[3] && (wanted & 1))
			call.store_pointer(call[3], memory + owner_at);
		if (call[4] && (wanted & 2))
			call.store_pointer(call[4], memory + group_at);
		if (call[5] && (wanted & 4))
			call.store_pointer(call[5], memory + dacl_at);
		if (call[6] && (wanted & 8))
			call.store_pointer(call[6], 0);
		if (call[7])
			call.store_pointer(call[7], memory);
		else
			context.allocator.release(memory);
		call.ret(0);
	};
	registry.add("GetSecurityInfo", 8, security_info);
	// A file or directory that is not there has no descriptor to give.
	registry.add("GetNamedSecurityInfoW", 8, [&context, security_info](ApiCall &call) {
		if (call.u32(1) == 1) {
			const auto name = call.wide(call[0], 32768);
			const auto resolved = context.paths.resolve(name);
			if (!resolved || !resolved->exists) {
				call.ret(resolved && !resolved->parent_exists ? 3 : 2);
				return;
			}
		}
		security_info(call);
	});
	// Reading a descriptor: the control bits say whether its parts are offsets from its start (self-relative) or pointers.
	const auto part = [](ApiCall &call, uint64_t descriptor, size_t index) -> uint64_t {
		const uint16_t control = call.load<uint16_t>(descriptor + 2);
		if (control & 0x8000) {
			const uint32_t offset = call.load<uint32_t>(descriptor + 4 + index * 4);
			return offset ? descriptor + offset : 0;
		}
		const size_t width = call.pointer_width(), first = width == 4 ? 4 : 8;
		return call.load_pointer(descriptor + first + index * width);
	};
	registry.add("GetSecurityDescriptorControl", 3, [](ApiCall &call) {
		if (!call[0]) {
			call.fail(87);
			return;
		}
		if (call[1])
			call.store<uint16_t>(call[1], call.load<uint16_t>(call[0] + 2));
		if (call[2])
			call.store<uint32_t>(call[2], call.read(call[0], 1)[0]);
		call.ret(1);
	});
	const auto owner_or_group = [part](ApiCall &call, size_t index, uint16_t defaulted) {
		if (!call[0] || !call[1] || !call[2]) {
			call.fail(87);
			return;
		}
		call.store_pointer(call[1], part(call, call[0], index));
		call.store<uint32_t>(call[2], (call.load<uint16_t>(call[0] + 2) & defaulted) != 0);
		call.ret(1);
	};
	registry.add("GetSecurityDescriptorOwner", 3, [owner_or_group](ApiCall &call) { owner_or_group(call, 0, owner_defaulted); });
	registry.add("GetSecurityDescriptorGroup", 3, [owner_or_group](ApiCall &call) { owner_or_group(call, 1, group_defaulted); });
	const auto acl_part = [part](ApiCall &call, size_t index, uint16_t present, uint16_t defaulted) {
		if (!call[0] || !call[1] || !call[2] || !call[3]) {
			call.fail(87);
			return;
		}
		const uint16_t control = call.load<uint16_t>(call[0] + 2);
		const bool has = (control & present) != 0;
		call.store<uint32_t>(call[1], has);
		call.store_pointer(call[2], has ? part(call, call[0], index) : 0);
		call.store<uint32_t>(call[3], (control & defaulted) != 0);
		call.ret(1);
	};
	registry.add("GetSecurityDescriptorSacl", 4, [acl_part](ApiCall &call) { acl_part(call, 2, sacl_present, sacl_defaulted); });
	registry.add("GetSecurityDescriptorDacl", 4, [acl_part](ApiCall &call) { acl_part(call, 3, dacl_present, dacl_defaulted); });
	registry.add("GetSecurityDescriptorLength", 1, [part](ApiCall &call) {
		// A self-relative descriptor ends where its last part ends; an absolute one is only its header.
		const auto control = call.load<uint16_t>(call[0] + 2);
		if (!(control & 0x8000)) {
			call.ret(layout_of(call).size);
			return;
		}
		uint64_t end = 20;
		for (size_t index = 0; index < 4; ++index) {
			const auto at = part(call, call[0], index);
			if (!at)
				continue;
			const uint64_t offset = at - call[0];
			uint64_t size = 0;
			if (index < 2)
				size = 8 + 4 * uint64_t(call.read(at + 1, 1)[0]);
			else
				size = call.load<uint16_t>(at + 2);
			end = std::max(end, offset + size);
		}
		call.ret(end);
	});
	registry.add("IsValidAcl", 1, [](ApiCall &call) {
		if (!call[0]) {
			call.ret(0);
			return;
		}
		const auto header = call.read(call[0], 8);
		call.ret(header[0] >= 2 && header[0] <= 4);
	});
	registry.add("GetAclInformation", 4, [](ApiCall &call) {
		if (!call[0] || !call[1]) {
			call.fail(87);
			return;
		}
		const auto header = call.read(call[0], 8);
		uint16_t size, count;
		std::memcpy(&size, header.data() + 2, 2);
		std::memcpy(&count, header.data() + 4, 2);
		if (call.u32(3) == 1 && call.u32(2) >= 4) {
			call.store<uint32_t>(call[1], header[0]);
		} else if (call.u32(3) == 2 && call.u32(2) >= 12) {
			uint32_t used = 8;
			for (uint16_t index = 0; index < count; ++index) {
				uint16_t entry;
				std::memcpy(&entry, call.read(call[0] + used + 2, 2).data(), 2);
				used += entry;
			}
			call.store<uint32_t>(call[1], count);
			call.store<uint32_t>(call[1] + 4, used);
			call.store<uint32_t>(call[1] + 8, size > used ? size - used : 0);
		} else {
			call.fail(24);
			return;
		}
		call.ret(1);
	});
	registry.add("GetAce", 3, [](ApiCall &call) {
		if (!call[0] || !call[2]) {
			call.fail(87);
			return;
		}
		const auto header = call.read(call[0], 8);
		uint16_t count;
		std::memcpy(&count, header.data() + 4, 2);
		if (call.u32(1) >= count) {
			call.fail(87);
			return;
		}
		uint32_t at = 8;
		for (uint32_t index = 0; index < call.u32(1); ++index) {
			uint16_t entry;
			std::memcpy(&entry, call.read(call[0] + at + 2, 2).data(), 2);
			at += entry;
		}
		call.store_pointer(call[2], call[0] + at);
		call.ret(1);
	});
	registry.add("GetSidSubAuthorityCount", 1, [](ApiCall &call) { call.ret(call[0] + 1); });
	registry.add("GetSidIdentifierAuthority", 1, [](ApiCall &call) { call.ret(call[0] + 2); });
	registry.add("GetSidSubAuthority", 2, [](ApiCall &call) { call.ret(call[0] + 8 + 4 * uint64_t(call.u32(1))); });
	registry.add("GetSidLengthRequired", 1, [](ApiCall &call) { call.ret(8 + 4 * uint32_t(uint8_t(call.u32(0)))); });
	// S-R-I-S-S...: the string form of a SID, in memory the program frees with LocalFree.
	registry.add("ConvertSidToStringSidW", 2, [&context](ApiCall &call) {
		if (!valid_sid(call, call[0]) || !call[1]) {
			call.fail(87);
			return;
		}
		const auto sid = call.read(call[0], sid_length(call, call[0]));
		uint64_t authority = 0;
		for (int index = 2; index < 8; ++index)
			authority = authority << 8 | sid[size_t(index)];
		std::string text = "S-1-" + std::to_string(authority);
		for (size_t index = 0; index < sid[1]; ++index) {
			uint32_t value;
			std::memcpy(&value, sid.data() + 8 + index * 4, 4);
			text += "-" + std::to_string(value);
		}
		const auto memory = context.allocator.allocate((text.size() + 1) * 2, true);
		if (!memory) {
			call.fail(8);
			return;
		}
		std::vector<uint8_t> wide((text.size() + 1) * 2);
		for (size_t index = 0; index < text.size(); ++index)
			wide[index * 2] = uint8_t(text[index]);
		call.write(memory, wide);
		call.store_pointer(call[1], memory);
		call.ret(1);
	});
	registry.add("ConvertStringSidToSidW", 2, [&context](ApiCall &call) {
		auto text = call.wide(call[0], 256);
		// The two-letter names of the security descriptor language stand for well-known SIDs.
		static const std::map<std::u16string, std::u16string> aliases{
			{u"AN", u"S-1-5-7"}, {u"AO", u"S-1-5-32-548"}, {u"AU", u"S-1-5-11"}, {u"BA", u"S-1-5-32-544"}, {u"BG", u"S-1-5-32-546"},
			{u"BO", u"S-1-5-32-551"}, {u"BU", u"S-1-5-32-545"}, {u"CG", u"S-1-3-1"}, {u"CO", u"S-1-3-0"}, {u"CY", u"S-1-5-32-569"},
			{u"ED", u"S-1-5-9"}, {u"HI", u"S-1-16-12288"}, {u"IU", u"S-1-5-4"}, {u"LS", u"S-1-5-19"}, {u"LW", u"S-1-16-4096"},
			{u"ME", u"S-1-16-8192"}, {u"MP", u"S-1-16-8448"}, {u"NO", u"S-1-5-32-556"}, {u"NS", u"S-1-5-20"}, {u"NU", u"S-1-5-2"},
			{u"PO", u"S-1-5-32-550"}, {u"PS", u"S-1-5-10"}, {u"PU", u"S-1-5-32-547"}, {u"RC", u"S-1-5-12"}, {u"RD", u"S-1-5-32-555"},
			{u"RE", u"S-1-5-32-552"}, {u"RU", u"S-1-5-32-554"}, {u"SI", u"S-1-16-16384"}, {u"SO", u"S-1-5-32-549"}, {u"SS", u"S-1-18-2"},
			{u"SU", u"S-1-5-6"}, {u"SY", u"S-1-5-18"}, {u"WD", u"S-1-1-0"}, {u"WR", u"S-1-5-33"}, {u"OW", u"S-1-3-4"},
			{u"UD", u"S-1-5-84-0-0-0-0-0"}};
		if (const auto alias = aliases.find(text); alias != aliases.end())
			text = alias->second;
		unsigned long long numbers[16];
		size_t count = 0;
		if (text.size() < 5 || text[0] != u'S' || text[1] != u'-' || text[2] != u'1' || text[3] != u'-') {
			call.fail(1337);
			return;
		}
		for (size_t at = 4; at < text.size() && count < 16;) {
			unsigned long long value = 0;
			size_t digits = 0;
			while (at < text.size() && text[at] >= u'0' && text[at] <= u'9') {
				value = value * 10 + (text[at] - u'0');
				++at;
				++digits;
			}
			if (!digits || (at < text.size() && text[at] != u'-')) {
				call.fail(1337);
				return;
			}
			numbers[count++] = value;
			if (at < text.size())
				++at;
		}
		if (count < 2 || count > 9) {
			call.fail(1337);
			return;
		}
		std::vector<uint8_t> sid{1, uint8_t(count - 1), 0, 0, 0, 0, 0, 0};
		for (int index = 0; index < 6; ++index)
			sid[size_t(2 + index)] = uint8_t(numbers[0] >> (8 * (5 - index)));
		for (size_t index = 1; index < count; ++index)
			for (int shift = 0; shift < 32; shift += 8)
				sid.push_back(uint8_t(numbers[index] >> shift));
		const auto memory = context.allocator.allocate(sid.size(), true);
		if (!memory || !call[1]) {
			call.fail(memory ? 87 : 8);
			return;
		}
		call.write(memory, sid);
		call.store_pointer(call[1], memory);
		call.ret(1);
	});
	// Building an ACL from explicit entries: each entry grants or denies a mask to a trustee named by its SID.
	registry.add("BuildTrusteeWithSidW", 2, [](ApiCall &call) {
		if (!call[0])
			return;
		const size_t width = call.pointer_width();
		std::vector<uint8_t> trustee(width == 4 ? 20 : 32);
		const uint64_t sid = call[1];
		std::memcpy(trustee.data() + (width == 4 ? 16 : 24), &sid, width);
		call.write(call[0], trustee);
	});
	registry.add("SetEntriesInAclW", 4, [&context](ApiCall &call) {
		const uint32_t count = call.u32(0);
		if (!call[3] || (count && !call[1])) {
			call.ret(87);
			return;
		}
		const size_t width = call.pointer_width(), trustee_size = width == 4 ? 20 : 32, entry_size = 12 + (width == 4 ? 0 : 4) + trustee_size;
		const size_t trustee_at = 12 + (width == 4 ? 0 : 4);
		std::vector<uint8_t> acl(8);
		acl[0] = 2;
		uint16_t entries = 0;
		// An existing list keeps its entries first.
		if (call[2]) {
			const auto header = call.read(call[2], 8);
			uint16_t old_count;
			std::memcpy(&old_count, header.data() + 4, 2);
			uint32_t used = 8;
			for (uint16_t index = 0; index < old_count; ++index) {
				uint16_t size;
				std::memcpy(&size, call.read(call[2] + used + 2, 2).data(), 2);
				used += size;
			}
			const auto old = call.read(call[2] + 8, used - 8);
			acl.insert(acl.end(), old.begin(), old.end());
			entries = old_count;
		}
		for (uint32_t index = 0; index < count; ++index) {
			const uint64_t at = call[1] + uint64_t(index) * entry_size;
			const uint32_t permissions = call.load<uint32_t>(at), mode = call.load<uint32_t>(at + 4);
			const uint64_t name = call.load_pointer(at + trustee_at + (width == 4 ? 16 : 24));
			const uint32_t form = call.load<uint32_t>(at + trustee_at + (width == 4 ? 8 : 12));
			std::vector<uint8_t> sid;
			if (form == 0 && valid_sid(call, name))
				sid = call.read(name, sid_length(call, name));
			else if (form == 1 && call.wide(name, 64) == u"Everyone")
				sid = make_sid(1, {0});
			else {
				call.ret(1332);
				return;
			}
			if (mode != 1 && mode != 2 && mode != 3) {
				call.ret(87);
				return;
			}
			const uint16_t size = uint16_t(8 + sid.size());
			std::vector<uint8_t> entry(size);
			entry[0] = mode == 3 ? 1 : 0;
			entry[1] = uint8_t(call.load<uint32_t>(at + 8));
			std::memcpy(entry.data() + 2, &size, 2);
			std::memcpy(entry.data() + 4, &permissions, 4);
			std::memcpy(entry.data() + 8, sid.data(), sid.size());
			acl.insert(acl.end(), entry.begin(), entry.end());
			++entries;
		}
		const uint16_t total = uint16_t(acl.size());
		std::memcpy(acl.data() + 2, &total, 2);
		std::memcpy(acl.data() + 4, &entries, 2);
		const auto memory = context.allocator.allocate(acl.size(), true);
		if (!memory) {
			call.ret(8);
			return;
		}
		call.write(memory, acl);
		call.store_pointer(call[3], memory);
		call.ret(0);
	});
	registry.add("AddAccessAllowedAce", 4, [add_ace](ApiCall &call) { add_ace(call, 0); });
	registry.add("AddAccessDeniedAce", 4, [add_ace](ApiCall &call) { add_ace(call, 1); });
}

}
