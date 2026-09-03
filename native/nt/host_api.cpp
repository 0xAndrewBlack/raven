#include "kernel_context.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <ctime>
#include <fstream>
#include <ifaddrs.h>
#include <map>
#include <optional>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace raven {

namespace {

constexpr uint32_t error_buffer_overflow = 111, error_no_data = 232, error_invalid_parameter = 87, wsaservice_not_found = 10108, wsa_invalid_handle = 6, wsa_not_enough_memory = 8, error_io_pending = 997, error_not_supported = 50, error_more_data = 234, error_no_more_items = 259;
constexpr uint32_t skip_unicast = 1, skip_anycast = 2, skip_multicast = 4, skip_dns_server = 8;
constexpr uint32_t windows_inet6 = 23;
constexpr uint32_t if_type_ethernet = 6, if_type_loopback = 24, if_type_wireless = 71;

// A set of device interfaces that SetupDi hands out; the host exposes no devices to the guest, so the set stays empty.
class DeviceInfoSet : public KernelObject {};

// An event log query: the log holds no records, so the query only ever reports that nothing more is there.
class EventQuery : public KernelObject {};

struct Address {
	std::vector<uint8_t> socket_address;
	uint8_t prefix = 0;
};

struct Adapter {
	std::string name;
	uint32_t index = 0, mtu = 1500, type = if_type_ethernet, status = 2;
	uint8_t hardware[8]{};
	uint32_t hardware_length = 0;
	std::vector<Address> unicast;
};

// A SOCKADDR_IN or SOCKADDR_IN6 in Windows layout, without a port.
std::vector<uint8_t> windows_address(const sockaddr *host)
{
	std::vector<uint8_t> bytes;
	if (host->sa_family == AF_INET) {
		bytes.assign(16, 0);
		const uint16_t family = AF_INET;
		std::memcpy(bytes.data(), &family, 2);
		std::memcpy(bytes.data() + 4, &reinterpret_cast<const sockaddr_in *>(host)->sin_addr, 4);
	} else {
		const auto *source = reinterpret_cast<const sockaddr_in6 *>(host);
		bytes.assign(28, 0);
		const uint16_t family = uint16_t(windows_inet6);
		std::memcpy(bytes.data(), &family, 2);
		std::memcpy(bytes.data() + 8, &source->sin6_addr, 16);
		std::memcpy(bytes.data() + 24, &source->sin6_scope_id, 4);
	}
	return bytes;
}

uint8_t prefix_length(const sockaddr *mask)
{
	if (!mask)
		return 0;
	const uint8_t *bytes = mask->sa_family == AF_INET ? reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(mask)->sin_addr)
		: reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in6 *>(mask)->sin6_addr);
	const size_t size = mask->sa_family == AF_INET ? 4 : 16;
	uint8_t bits = 0;
	for (size_t index = 0; index < size; ++index)
		bits = uint8_t(bits + __builtin_popcount(bytes[index]));
	return bits;
}

std::vector<Adapter> host_adapters(uint32_t family)
{
	std::vector<Adapter> adapters;
	ifaddrs *list = nullptr;
	if (::getifaddrs(&list))
		return adapters;
	std::map<std::string, size_t> found;
	for (const auto *entry = list; entry; entry = entry->ifa_next) {
		if (!entry->ifa_name)
			continue;
		auto position = found.find(entry->ifa_name);
		if (position == found.end()) {
			Adapter adapter;
			adapter.name = entry->ifa_name;
			adapter.index = ::if_nametoindex(entry->ifa_name);
			adapter.status = (entry->ifa_flags & IFF_UP) && (entry->ifa_flags & IFF_RUNNING) ? 1 : 2;
			adapter.type = (entry->ifa_flags & IFF_LOOPBACK) ? if_type_loopback :
				::access(("/sys/class/net/" + adapter.name + "/wireless").c_str(), F_OK) == 0 ? if_type_wireless : if_type_ethernet;
			if (const int probe = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); probe >= 0) {
				ifreq request{};
				std::strncpy(request.ifr_name, entry->ifa_name, IFNAMSIZ - 1);
				if (::ioctl(probe, SIOCGIFMTU, &request) == 0)
					adapter.mtu = uint32_t(request.ifr_mtu);
				if (adapter.type != if_type_loopback && ::ioctl(probe, SIOCGIFHWADDR, &request) == 0) {
					std::memcpy(adapter.hardware, request.ifr_hwaddr.sa_data, 6);
					adapter.hardware_length = 6;
				}
				::close(probe);
			}
			position = found.emplace(adapter.name, adapters.size()).first;
			adapters.push_back(std::move(adapter));
		}
		if (!entry->ifa_addr || (entry->ifa_addr->sa_family != AF_INET && entry->ifa_addr->sa_family != AF_INET6))
			continue;
		if (family && family != uint32_t(entry->ifa_addr->sa_family == AF_INET ? AF_INET : windows_inet6))
			continue;
		adapters[position->second].unicast.push_back({windows_address(entry->ifa_addr), prefix_length(entry->ifa_netmask)});
	}
	::freeifaddrs(list);
	// A family filter keeps only the adapters that have an address of that family.
	if (family)
		adapters.erase(std::remove_if(adapters.begin(), adapters.end(), [](const Adapter &adapter) { return adapter.unicast.empty(); }), adapters.end());
	return adapters;
}

}

// The adapter list is built from the host interfaces. The records follow the IP_ADAPTER_ADDRESSES layout of the caller's pointer width.
void register_host_api(ApiRegistry &registry, KernelContext &context)
{
	auto &objects = context.objects;
	registry.add("GetAdaptersAddresses", 5, [](ApiCall &call) {
		const uint32_t family = call.u32(0), flags = call.u32(1);
		if (!call[4] || (family != 0 && family != AF_INET && family != windows_inet6)) {
			call.ret(error_invalid_parameter);
			return;
		}
		const size_t width = call.pointer_width();
		const auto adapters = host_adapters(family);
		if (adapters.empty()) {
			call.ret(error_no_data);
			return;
		}
		// Offsets in IP_ADAPTER_ADDRESSES_LH: the pointer fields follow the 64-bit alignment of the speeds and the 8-byte LUID.
		const auto align = [](size_t value, size_t boundary) { return (value + boundary - 1) & ~(boundary - 1); };
		size_t cursor = 8;
		const size_t next_at = cursor; cursor += width;
		const size_t name_at = cursor; cursor += width;
		const size_t unicast_at = cursor; cursor += width;
		cursor += 2 * width;
		const size_t dns_at = cursor; cursor += width;
		const size_t suffix_at = cursor; cursor += width;
		const size_t description_at = cursor; cursor += width;
		const size_t friendly_at = cursor; cursor += width;
		const size_t physical_at = cursor; cursor += 8;
		const size_t physical_length_at = cursor; cursor += 4;
		const size_t flags_at = cursor; cursor += 4;
		const size_t mtu_at = cursor; cursor += 4;
		const size_t type_at = cursor; cursor += 4;
		const size_t status_at = cursor; cursor += 4;
		const size_t index6_at = cursor; cursor += 4 + 64;
		cursor = align(cursor, width);
		cursor += width;
		cursor = align(cursor, 8);
		const size_t transmit_at = cursor; cursor += 16;
		cursor = align(cursor, width);
		cursor += 2 * width;
		const size_t metric4_at = cursor; cursor += 8;
		cursor = align(cursor, 8);
		cursor += 8;
		cursor = align(cursor, width);
		cursor += 2 * width;
		cursor += 4;
		cursor = align(cursor, 4);
		const size_t guid_at = cursor; cursor += 16;
		cursor += 8;
		cursor = align(cursor, width);
		cursor += 2 * width;
		cursor += 130;
		cursor = align(cursor, 4);
		cursor += 8;
		cursor = align(cursor, width);
		cursor += width;
		const size_t record = align(cursor, 8);
		// IP_ADAPTER_UNICAST_ADDRESS_LH: length, flags, next, the socket address, three origins, three lifetimes and the prefix length.
		size_t unicast_cursor = 8 + width;
		const size_t sockaddr_pointer_at = unicast_cursor; unicast_cursor += width;
		const size_t sockaddr_length_at = unicast_cursor; unicast_cursor += 4;
		unicast_cursor = align(unicast_cursor, width);
		const size_t origin_at = unicast_cursor; unicast_cursor += 24;
		const size_t prefix_at = unicast_cursor;
		const size_t unicast_record = align(prefix_at + 1, width);
		size_t needed = 0;
		for (const auto &adapter : adapters) {
			needed += record;
			if (!(flags & skip_unicast))
				for (const auto &address : adapter.unicast)
					needed += unicast_record + align(address.socket_address.size(), 8);
			needed += 2 * (adapter.name.size() + 1) + 2 * (adapter.name.size() + 1) + 64;
			needed = align(needed, 8);
		}
		const uint32_t capacity = call.load<uint32_t>(call[4]);
		if (!call[3] || capacity < needed) {
			call.store<uint32_t>(call[4], uint32_t(needed));
			call.ret(error_buffer_overflow);
			return;
		}
		std::vector<uint8_t> block(needed, 0);
		const uint64_t base = call[3];
		const auto put32 = [&](size_t at, uint32_t value) { std::memcpy(block.data() + at, &value, 4); };
		const auto put_pointer = [&](size_t at, uint64_t value) { std::memcpy(block.data() + at, &value, width); };
		size_t position = 0, previous = 0;
		for (size_t number = 0; number < adapters.size(); ++number) {
			const auto &adapter = adapters[number];
			const size_t self = position;
			position += record;
			put32(self, uint32_t(record));
			put32(self + 4, adapter.index);
			if (number)
				put_pointer(previous + next_at, base + self);
			previous = self;
			// The adapter name is a GUID string made from the interface index, stable for the interface.
			char guid[64];
			std::snprintf(guid, sizeof(guid), "{00000000-0000-0000-0000-%012x}", adapter.index);
			std::memcpy(block.data() + position, guid, std::strlen(guid) + 1);
			put_pointer(self + name_at, base + position);
			position += 48;
			for (const size_t at : {description_at, friendly_at}) {
				for (size_t character = 0; character < adapter.name.size(); ++character)
					block[position + 2 * character] = uint8_t(adapter.name[character]);
				put_pointer(self + at, base + position);
				position += 2 * (adapter.name.size() + 1);
			}
			put_pointer(self + suffix_at, base + position);
			position += 2;
			(void)dns_at;
			std::memcpy(block.data() + self + physical_at, adapter.hardware, 8);
			put32(self + physical_length_at, adapter.hardware_length);
			put32(self + flags_at, 0x10 | 0x80);
			put32(self + mtu_at, adapter.mtu);
			put32(self + type_at, adapter.type);
			put32(self + status_at, adapter.status);
			put32(self + index6_at, adapter.index);
			put32(self + metric4_at, 25);
			put32(self + metric4_at + 4, 25);
			(void)transmit_at;
			(void)guid_at;
			position = align(position, 8);
			if (!(flags & skip_unicast)) {
				size_t last = 0;
				for (const auto &address : adapter.unicast) {
					const size_t entry = position;
					position += unicast_record;
					put32(entry, uint32_t(unicast_record));
					put32(entry + 4, 0);
					const size_t stored = position;
					std::memcpy(block.data() + stored, address.socket_address.data(), address.socket_address.size());
					position += align(address.socket_address.size(), 8);
					put_pointer(entry + sockaddr_pointer_at, base + stored);
					put32(entry + sockaddr_length_at, uint32_t(address.socket_address.size()));
					block[entry + prefix_at] = address.prefix;
					put32(entry + origin_at, 3);
					put32(entry + origin_at + 4, 3);
					put32(entry + origin_at + 8, 4);
					put32(entry + origin_at + 12, 0xffffffffU);
					put32(entry + origin_at + 16, 0xffffffffU);
					put32(entry + origin_at + 20, 0xffffffffU);
					if (last)
						put_pointer(last + 8, base + entry);
					else
						put_pointer(self + unicast_at, base + entry);
					last = entry;
				}
			}
			position = align(position, 8);
		}
		call.write(base, std::span<const uint8_t>(block.data(), std::min(position, block.size())));
		(void)skip_anycast; (void)skip_multicast; (void)skip_dns_server;
		call.ret(0);
	});
	// Winsock events are ordinary manual-reset events.
	registry.add("WSACreateEvent", 0, [&objects](ApiCall &call) {
		const auto made = objects.create_event(0x1f0003, 0, false);
		if (made.status) {
			call.fail(wsa_not_enough_memory, 0);
			return;
		}
		call.ret(made.value);
	});
	registry.add("WSASetEvent", 1, [&objects](ApiCall &call) {
		if (objects.set_event(call[0], true).status) {
			call.fail(wsa_invalid_handle, 0);
			return;
		}
		call.ret(1);
	});
	registry.add("WSAResetEvent", 1, [&objects](ApiCall &call) {
		if (objects.set_event(call[0], false).status) {
			call.fail(wsa_invalid_handle, 0);
			return;
		}
		call.ret(1);
	});
	registry.add("WSACloseEvent", 1, [&objects](ApiCall &call) {
		if (objects.close(call[0])) {
			call.fail(wsa_invalid_handle, 0);
			return;
		}
		call.ret(1);
	});
	// A change notification waits for an address change that is never reported: the host's interfaces are not watched.
	registry.add("NotifyAddrChange", 2, [](ApiCall &call) { call.ret(call[1] ? error_io_pending : error_not_supported); });
	registry.add("NotifyRouteChange", 2, [](ApiCall &call) { call.ret(call[1] ? error_io_pending : error_not_supported); });
	// The computer name is the host's, in the forms Windows reports it.
	const auto computer_name = [](uint32_t type) -> std::optional<std::u16string> {
		char host[256] = {};
		::gethostname(host, sizeof(host) - 1);
		std::string name(host);
		const auto dot = name.find('.');
		if (type == 0 || type == 4) {
			std::string netbios = name.substr(0, dot);
			for (auto &character : netbios)
				character = char(std::toupper(static_cast<unsigned char>(character)));
			netbios.resize(std::min<size_t>(netbios.size(), 15));
			return std::u16string(netbios.begin(), netbios.end());
		}
		if (type == 1 || type == 5)
			return std::u16string(name.begin(), name.begin() + std::string::difference_type(dot == std::string::npos ? name.size() : dot));
		if (type == 2 || type == 6)
			return dot == std::string::npos ? std::u16string() : std::u16string(name.begin() + std::string::difference_type(dot) + 1, name.end());
		if (type == 3 || type == 7)
			return std::u16string(name.begin(), name.end());
		return std::nullopt;
	};
	const auto report_name = [computer_name](ApiCall &call, uint32_t type, bool wide) {
		const auto name = computer_name(type);
		if (!name || !call[2]) {
			call.fail(error_invalid_parameter, 0);
			return;
		}
		const uint32_t capacity = call.load<uint32_t>(call[2]);
		if (!call[1] || capacity <= name->size()) {
			call.store<uint32_t>(call[2], uint32_t(name->size() + 1));
			call.fail(error_more_data, 0);
			return;
		}
		if (wide)
			call.put_wide(call[1], *name, capacity);
		else
			call.put_narrow(call[1], std::string(name->begin(), name->end()), capacity);
		call.store<uint32_t>(call[2], uint32_t(name->size()));
		call.ret(1);
	};
	registry.add("GetComputerNameExW", 3, [report_name](ApiCall &call) {
		// The name goes to the second argument and its length to the third, as in GetComputerNameW.
		report_name(call, call.u32(0), true);
	});
	registry.add("GetComputerNameW", 2, [computer_name](ApiCall &call) {
		const auto name = computer_name(0);
		if (!call[0] || !call[1]) {
			call.fail(error_invalid_parameter, 0);
			return;
		}
		const uint32_t capacity = call.load<uint32_t>(call[1]);
		if (capacity <= name->size()) {
			call.store<uint32_t>(call[1], uint32_t(name->size() + 1));
			call.fail(error_more_data, 0);
			return;
		}
		call.put_wide(call[0], *name, capacity);
		call.store<uint32_t>(call[1], uint32_t(name->size()));
		call.ret(1);
	});
	registry.add("GetComputerNameA", 2, [computer_name](ApiCall &call) {
		const auto name = computer_name(0);
		if (!call[0] || !call[1]) {
			call.fail(error_invalid_parameter, 0);
			return;
		}
		const uint32_t capacity = call.load<uint32_t>(call[1]);
		if (capacity <= name->size()) {
			call.store<uint32_t>(call[1], uint32_t(name->size() + 1));
			call.fail(error_more_data, 0);
			return;
		}
		call.put_narrow(call[0], std::string(name->begin(), name->end()), capacity);
		call.store<uint32_t>(call[1], uint32_t(name->size()));
		call.ret(1);
	});
	// Device enumeration finds nothing: the set opens, holds no interfaces and closes.
	registry.add("SetupDiGetClassDevsW", 4, [&objects](ApiCall &call) {
		const auto made = objects.add_object(std::make_shared<DeviceInfoSet>());
		if (made.status) {
			call.fail(8, UINT64_MAX);
			return;
		}
		call.ret(made.value);
	});
	registry.add("SetupDiEnumDeviceInterfaces", 5, [&objects](ApiCall &call) {
		if (!objects.object_as<DeviceInfoSet>(call[0])) {
			call.fail(6, 0);
			return;
		}
		call.fail(error_no_more_items, 0);
	});
	registry.add("SetupDiDestroyDeviceInfoList", 1, [&objects](ApiCall &call) {
		if (!objects.object_as<DeviceInfoSet>(call[0])) {
			call.fail(6, 0);
			return;
		}
		objects.close(call[0]);
		call.ret(1);
	});
	registry.add("EvtQuery", 4, [&objects](ApiCall &call) {
		const auto made = objects.add_object(std::make_shared<EventQuery>());
		if (made.status) {
			call.fail(8, 0);
			return;
		}
		call.ret(made.value);
	});
	registry.add("EvtNext", 6, [&objects](ApiCall &call) {
		if (!objects.object_as<EventQuery>(call[0])) {
			call.fail(6, 0);
			return;
		}
		if (call[4])
			call.store<uint32_t>(call[4], 0);
		call.fail(error_no_more_items, 0);
	});
	registry.add("EvtClose", 1, [&objects](ApiCall &call) {
		if (!objects.object_as<EventQuery>(call[0])) {
			call.fail(6, 0);
			return;
		}
		objects.close(call[0]);
		call.ret(1);
	});
	// A device context has no color profile assigned.
	registry.add("GetICMProfileW", 3, [](ApiCall &call) { call.fail(2, 0); });
	// Device notifications are registered and never sent: the host reports no device arrivals to the program.
	registry.add("RegisterDeviceNotificationW", 3, [&objects](ApiCall &call) {
		const auto made = objects.add_object(std::make_shared<DeviceInfoSet>());
		if (made.status) {
			call.fail(8, 0);
			return;
		}
		call.ret(made.value);
	});
	registry.add("RegisterDeviceNotificationA", 3, [&objects](ApiCall &call) {
		const auto made = objects.add_object(std::make_shared<DeviceInfoSet>());
		if (made.status) {
			call.fail(8, 0);
			return;
		}
		call.ret(made.value);
	});
	registry.add("UnregisterDeviceNotification", 1, [&objects](ApiCall &call) {
		if (!objects.object_as<DeviceInfoSet>(call[0])) {
			call.fail(6, 0);
			return;
		}
		objects.close(call[0]);
		call.ret(1);
	});
	registry.add("EvtCreateRenderContext", 4, [&objects](ApiCall &call) {
		const auto made = objects.add_object(std::make_shared<EventQuery>());
		if (made.status) {
			call.fail(8, 0);
			return;
		}
		call.ret(made.value);
	});
	// What the thread's queue holds: the high word the kinds of message waiting, the low word the ones that arrived since the last call.
	registry.add("GetQueueStatus", 1, [&context](ApiCall &call) {
		const uint32_t kinds = call.u32(0) & 0x4ff;
		call.ret(context.message_ready && context.message_ready() ? uint64_t(kinds) << 16 | kinds : 0);
	});
	// Power information: the processors with their frequencies from the host, a machine on mains power with no battery, and no sleep states.
	registry.add("CallNtPowerInformation", 5, [](ApiCall &call) {
		constexpr uint32_t status_success = 0, status_buffer_too_small = 0xc0000023U, status_invalid_parameter = 0xc000000dU;
		const uint32_t level = call.u32(0);
		std::vector<uint8_t> data;
		if (level == 11) {
			// PROCESSOR_POWER_INFORMATION per processor: number, maximum, current and limit in MHz, idle states.
			const long count = std::max<long>(1, ::sysconf(_SC_NPROCESSORS_ONLN));
			for (long index = 0; index < count; ++index) {
				const auto read_khz = [&](const char *file) -> uint32_t {
					std::ifstream input("/sys/devices/system/cpu/cpu" + std::to_string(index) + "/cpufreq/" + file);
					uint64_t khz = 0;
					input >> khz;
					return uint32_t(khz / 1000);
				};
				uint32_t maximum = read_khz("cpuinfo_max_freq"), current = read_khz("scaling_cur_freq");
				if (!maximum) {
					std::ifstream cpuinfo("/proc/cpuinfo");
					for (std::string line; std::getline(cpuinfo, line);)
						if (line.starts_with("cpu MHz")) {
							maximum = uint32_t(std::stod(line.substr(line.find(':') + 1)));
							break;
						}
				}
				if (!current)
					current = maximum;
				const uint32_t fields[6] = {uint32_t(index), maximum, current, maximum, 0, 0};
				const auto raw = reinterpret_cast<const uint8_t *>(fields);
				data.insert(data.end(), raw, raw + sizeof(fields));
			}
		} else if (level == 5) {
			// SYSTEM_BATTERY_STATE: AC line on, no battery present.
			data.assign(32, 0);
			data[0] = 1;
		} else if (level == 4) {
			data.assign(76, 0);
		} else {
			call.ret(status_invalid_parameter);
			return;
		}
		if (!call[3] || call.u32(4) < data.size()) {
			call.ret(status_buffer_too_small);
			return;
		}
		call.write(call[3], data);
		call.ret(status_success);
	});
	// Interrupt time is the monotonic clock in 100 ns ticks, which does not run while the host sleeps.
	const auto interrupt_time = [](ApiCall &call) {
		if (!call[0]) {
			call.fail(87);
			return;
		}
		timespec now{};
		::clock_gettime(CLOCK_MONOTONIC, &now);
		call.store<uint64_t>(call[0], (uint64_t(now.tv_sec) * 1000000000ULL + uint64_t(now.tv_nsec)) / 100);
		call.ret(1);
	};
	registry.add("QueryUnbiasedInterruptTime", 1, interrupt_time);
	registry.add("QueryUnbiasedInterruptTimePrecise", 1, [interrupt_time](ApiCall &call) {
		interrupt_time(call);
		call.ret(1);
	});
	registry.add("QueryInterruptTimePrecise", 1, [](ApiCall &call) {
		if (!call[0]) {
			call.fail(87);
			return;
		}
		timespec now{};
		::clock_gettime(CLOCK_BOOTTIME, &now);
		call.store<uint64_t>(call[0], (uint64_t(now.tv_sec) * 1000000000ULL + uint64_t(now.tv_nsec)) / 100);
	});
	// The user's region is United States; the keyboard layout is US English.
	registry.add("GetUserGeoID", 1, [](ApiCall &call) { call.ret(244); });
	registry.add("GetGeoInfoW", 5, [](ApiCall &call) {
		if (call.u32(0) != 244) {
			call.fail(87, 0);
			return;
		}
		std::u16string text;
		switch (call.u32(1)) {
		case 4: text = u"US"; break;
		case 5: text = u"USA"; break;
		case 8: text = u"United States"; break;
		case 9: text = u"United States"; break;
		default:
			call.fail(87, 0);
			return;
		}
		if (call[2] && call.i32(3) > 0) {
			if (size_t(call.i32(3)) <= text.size()) {
				call.fail(122, 0);
				return;
			}
			call.put_wide(call[2], text, size_t(call.i32(3)));
		}
		call.ret(text.size() + 1);
	});
	registry.add("GetKeyboardLayoutList", 2, [](ApiCall &call) {
		if (call.i32(0) > 0 && call[1])
			call.store_pointer(call[1], 0x04090409);
		call.ret(1);
	});
	// A drive's volume: the prefix keeps the files, so every drive reports one NTFS volume.
	registry.add("GetVolumeInformationW", 8, [&context](ApiCall &call) {
		if (call[0]) {
			const auto root = context.paths.resolve(call.wide(call[0], 260));
			if (!root || !root->exists) {
				call.fail(3);
				return;
			}
		}
		if (call[1] && call.u32(2))
			call.put_wide(call[1], u"", call.u32(2));
		if (call[3])
			call.store<uint32_t>(call[3], 0x52415645);
		if (call[4])
			call.store<uint32_t>(call[4], 255);
		if (call[5])
			call.store<uint32_t>(call[5], 0x0000000f);
		if (call[6] && call.u32(7))
			call.put_wide(call[6], u"NTFS", call.u32(7));
		call.ret(1);
	});
	// Session change messages are never sent: the registration succeeds and nothing arrives.
	registry.add("WTSRegisterSessionNotification", 2, [](ApiCall &call) { call.ret(1); });
	registry.add("WTSUnRegisterSessionNotification", 1, [](ApiCall &call) { call.ret(1); });
	// No pointer devices other than the mouse are present.
	registry.add("RegisterPointerDeviceNotifications", 2, [](ApiCall &call) { call.ret(1); });
	registry.add("GetPointerDevices", 2, [](ApiCall &call) {
		if (!call[0]) {
			call.fail(error_invalid_parameter, 0);
			return;
		}
		call.store<uint32_t>(call[0], 0);
		call.ret(1);
	});
	// A URL is accepted as typed when it already names a scheme; otherwise the usual prefix is added.
	registry.add("UrlFixupW", 3, [](ApiCall &call) {
		auto url = call[0] ? call.wide(call[0], 2084) : std::u16string();
		if (url.find(u"://") == url.npos && !url.empty())
			url.insert(0, url.starts_with(u"ftp.") ? u"ftp://" : u"http://");
		if (!call[1] || url.size() >= call.u32(2)) {
			call.ret(0x80070057U);
			return;
		}
		call.put_wide(call[1], url, call.u32(2));
		call.ret(0);
	});
	// No name-space provider is installed, so a service lookup has nothing to search.
	registry.add("WSALookupServiceBeginW", 3, [](ApiCall &call) { call.fail(wsaservice_not_found, UINT64_MAX); });
	registry.add("WSALookupServiceBeginA", 3, [](ApiCall &call) { call.fail(wsaservice_not_found, UINT64_MAX); });
	registry.add("WSALookupServiceNextW", 4, [](ApiCall &call) { call.fail(wsa_invalid_handle, UINT64_MAX); });
	registry.add("WSALookupServiceNextA", 4, [](ApiCall &call) { call.fail(wsa_invalid_handle, UINT64_MAX); });
	registry.add("WSALookupServiceEnd", 1, [](ApiCall &call) { call.fail(wsa_invalid_handle, UINT64_MAX); });
}

}
