#include "kernel_context.h"

#include <cstring>

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

void register_security_api(ApiRegistry &registry, KernelContext &)
{
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
	registry.add("AddAccessAllowedAce", 4, [add_ace](ApiCall &call) { add_ace(call, 0); });
	registry.add("AddAccessDeniedAce", 4, [add_ace](ApiCall &call) { add_ace(call, 1); });
}

}
