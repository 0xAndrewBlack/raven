#include "child_process.h"
#include "kernel_context.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace raven {

namespace {

// A socket is a host descriptor that stays non-blocking inside Raven: a blocking call waits on the host without stopping other guest
// threads, and whether the guest sees blocking behavior is a property of the object.
class SocketObject : public KernelObject {
public:
	explicit SocketObject(int descriptor) : descriptor(descriptor) {}
	~SocketObject() override { ::close(descriptor); }
	int signaled(uint32_t) const override { return 1; }
	int descriptor;
	bool guest_nonblocking = false;
	int type = SOCK_STREAM;
};

constexpr uint32_t wsaeintr = 10004, wsaebadf = 10009, wsaeacces = 10013, wsaefault = 10014, wsaeinval = 10022, wsaemfile = 10024,
	wsaewouldblock = 10035, wsaeinprogress = 10036, wsaealready = 10037, wsaenotsock = 10038, wsaedestaddrreq = 10039, wsaemsgsize = 10040,
	wsaeprototype = 10041, wsaenoprotoopt = 10042, wsaeprotonosupport = 10043, wsaesocktnosupport = 10044, wsaeopnotsupp = 10045,
	wsaeafnosupport = 10047, wsaeaddrinuse = 10048, wsaeaddrnotavail = 10049, wsaenetdown = 10050, wsaenetunreach = 10051,
	wsaeconnaborted = 10053, wsaeconnreset = 10054, wsaenobufs = 10055, wsaeisconn = 10056, wsaenotconn = 10057, wsaeshutdown = 10058,
	wsaetimedout = 10060, wsaeconnrefused = 10061, wsaehostunreach = 10065, wsanotinitialised = 10093, wsahost_not_found = 11001;

uint32_t wsa_error(int host)
{
	switch (host) {
	case EINTR: return wsaeintr;
	case EBADF: return wsaenotsock;
	case EACCES: case EPERM: return wsaeacces;
	case EFAULT: return wsaefault;
	case EINVAL: return wsaeinval;
	case EMFILE: case ENFILE: return wsaemfile;
	case EAGAIN: return wsaewouldblock;
	case EINPROGRESS: return wsaeinprogress;
	case EALREADY: return wsaealready;
	case ENOTSOCK: return wsaenotsock;
	case EDESTADDRREQ: return wsaedestaddrreq;
	case EMSGSIZE: return wsaemsgsize;
	case EPROTOTYPE: return wsaeprototype;
	case ENOPROTOOPT: return wsaenoprotoopt;
	case EPROTONOSUPPORT: return wsaeprotonosupport;
	case ESOCKTNOSUPPORT: return wsaesocktnosupport;
	case EOPNOTSUPP: return wsaeopnotsupp;
	case EAFNOSUPPORT: return wsaeafnosupport;
	case EADDRINUSE: return wsaeaddrinuse;
	case EADDRNOTAVAIL: return wsaeaddrnotavail;
	case ENETDOWN: return wsaenetdown;
	case ENETUNREACH: return wsaenetunreach;
	case ECONNABORTED: case EPIPE: return wsaeconnaborted;
	case ECONNRESET: return wsaeconnreset;
	case ENOBUFS: case ENOMEM: return wsaenobufs;
	case EISCONN: return wsaeisconn;
	case ENOTCONN: return wsaenotconn;
	case ESHUTDOWN: return wsaeshutdown;
	case ETIMEDOUT: return wsaetimedout;
	case ECONNREFUSED: return wsaeconnrefused;
	case EHOSTUNREACH: return wsaehostunreach;
	default: return wsaeinval;
	}
}

constexpr uint16_t windows_inet6 = 23;

int host_family(int family) { return family == windows_inet6 ? AF_INET6 : family; }
int windows_family(int family) { return family == AF_INET6 ? windows_inet6 : family; }

// A sockaddr as the host wants it: the family number is the only difference from the Windows layout.
std::vector<uint8_t> host_address(ApiCall &call, uint64_t address, size_t length)
{
	auto bytes = call.read(address, length);
	if (bytes.size() >= 2) {
		uint16_t family;
		std::memcpy(&family, bytes.data(), 2);
		family = uint16_t(host_family(family));
		std::memcpy(bytes.data(), &family, 2);
	}
	return bytes;
}

void put_address(ApiCall &call, uint64_t address, uint64_t length_address, const sockaddr_storage &storage, socklen_t length)
{
	if (!address || !length_address)
		return;
	const uint32_t capacity = call.load<uint32_t>(length_address);
	std::vector<uint8_t> bytes(reinterpret_cast<const uint8_t *>(&storage), reinterpret_cast<const uint8_t *>(&storage) + length);
	if (bytes.size() >= 2) {
		uint16_t family;
		std::memcpy(&family, bytes.data(), 2);
		family = uint16_t(windows_family(family));
		std::memcpy(bytes.data(), &family, 2);
	}
	call.write(address, std::span<const uint8_t>(bytes.data(), std::min<size_t>(bytes.size(), capacity)));
	call.store<uint32_t>(length_address, uint32_t(length));
}

constexpr uint32_t sol_socket_windows = 0xffff;

}

void register_winsock_api(ApiRegistry &registry, KernelContext &context)
{
	auto &objects = context.objects;
	auto &threads = context.threads;
	const auto socket_of = [&objects](uint64_t handle) { return objects.object_as<SocketObject>(handle); };
	const auto fail = [](ApiCall &call, uint32_t error, uint64_t value = UINT64_MAX) { call.fail(error, value); };

	// Waits until the descriptor is ready for the events or the time is up; true when it is ready. Other guest threads run meanwhile.
	const auto wait_ready = [&threads](int descriptor, short events, std::optional<std::chrono::steady_clock::time_point> wake) {
		const auto ready = [descriptor, events] {
			pollfd entry{descriptor, events, 0};
			return ::poll(&entry, 1, 0) > 0;
		};
		if (ready())
			return true;
		HostWait waiting;
		return threads.block(ready, wake);
	};

	const auto make_socket = [&objects](ApiCall &call, int family, int type, int protocol) -> uint64_t {
		const int descriptor = ::socket(host_family(family), type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
		if (descriptor < 0) {
			call.fail(wsa_error(errno), UINT64_MAX);
			return UINT64_MAX;
		}
		auto object = std::make_shared<SocketObject>(descriptor);
		object->type = type;
		const auto made = objects.add_object(object);
		if (made.status) {
			call.fail(wsaemfile, UINT64_MAX);
			return UINT64_MAX;
		}
		return made.value;
	};
	registry.add("socket", 3, [make_socket](ApiCall &call) { call.ret(make_socket(call, call.i32(0), call.i32(1), call.i32(2))); });
	const auto make_wsa = [make_socket](ApiCall &call) {
		const int family = call.i32(0) ? call.i32(0) : AF_INET, type = call.i32(1) ? call.i32(1) : SOCK_STREAM;
		call.ret(make_socket(call, family, type, call.i32(2)));
	};
	registry.add("WSASocketA", 6, make_wsa);
	registry.add("WSASocketW", 6, make_wsa);
	registry.add("closesocket", 1, [&objects, socket_of, fail](ApiCall &call) {
		if (!socket_of(call[0])) {
			fail(call, wsaenotsock, UINT64_MAX);
			return;
		}
		objects.close(call[0]);
		call.ret(0);
	});
	registry.add("shutdown", 2, [socket_of, fail](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket) {
			fail(call, wsaenotsock);
			return;
		}
		static constexpr int how[] = {SHUT_RD, SHUT_WR, SHUT_RDWR};
		if (call.u32(1) > 2 || ::shutdown(socket->descriptor, how[call.u32(1)])) {
			fail(call, call.u32(1) > 2 ? wsaeinval : wsa_error(errno));
			return;
		}
		call.ret(0);
	});
	registry.add("bind", 3, [socket_of, fail](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket || call.i32(2) < 2) {
			fail(call, socket ? wsaefault : wsaenotsock);
			return;
		}
		const auto address = host_address(call, call[1], size_t(call.i32(2)));
		if (::bind(socket->descriptor, reinterpret_cast<const sockaddr *>(address.data()), socklen_t(address.size()))) {
			fail(call, wsa_error(errno));
			return;
		}
		call.ret(0);
	});
	registry.add("listen", 2, [socket_of, fail](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket || ::listen(socket->descriptor, call.i32(1))) {
			fail(call, socket ? wsa_error(errno) : wsaenotsock);
			return;
		}
		call.ret(0);
	});
	registry.add("connect", 3, [socket_of, fail, wait_ready](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket || call.i32(2) < 2) {
			fail(call, socket ? wsaefault : wsaenotsock);
			return;
		}
		const auto address = host_address(call, call[1], size_t(call.i32(2)));
		if (::connect(socket->descriptor, reinterpret_cast<const sockaddr *>(address.data()), socklen_t(address.size())) == 0) {
			call.ret(0);
			return;
		}
		if (errno != EINPROGRESS) {
			fail(call, wsa_error(errno));
			return;
		}
		if (socket->guest_nonblocking) {
			fail(call, wsaewouldblock);
			return;
		}
		wait_ready(socket->descriptor, POLLOUT, std::nullopt);
		int error = 0;
		socklen_t length = sizeof(error);
		::getsockopt(socket->descriptor, SOL_SOCKET, SO_ERROR, &error, &length);
		if (error) {
			fail(call, wsa_error(error));
			return;
		}
		call.ret(0);
	});
	registry.add("accept", 3, [&objects, socket_of, fail, wait_ready](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket) {
			fail(call, wsaenotsock);
			return;
		}
		for (;;) {
			sockaddr_storage storage{};
			socklen_t length = sizeof(storage);
			const int accepted = ::accept4(socket->descriptor, reinterpret_cast<sockaddr *>(&storage), &length, SOCK_NONBLOCK | SOCK_CLOEXEC);
			if (accepted >= 0) {
				const auto made = objects.add_object(std::make_shared<SocketObject>(accepted));
				if (made.status) {
					::close(accepted);
					fail(call, wsaemfile);
					return;
				}
				put_address(call, call[1], call[2], storage, length);
				call.ret(made.value);
				return;
			}
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				fail(call, wsa_error(errno));
				return;
			}
			if (socket->guest_nonblocking) {
				fail(call, wsaewouldblock);
				return;
			}
			wait_ready(socket->descriptor, POLLIN, std::nullopt);
		}
	});

	// Data transfer: every form reads and writes through one pair of helpers so blocking and flags behave the same.
	const auto host_flags = [](uint32_t flags) {
		int result = MSG_NOSIGNAL;
		if (flags & 1)
			result |= MSG_OOB;
		if (flags & 2)
			result |= MSG_PEEK;
		if (flags & 4)
			result |= MSG_DONTROUTE;
		if (flags & 8)
			result |= MSG_WAITALL;
		return result;
	};
	// Receives into the guest buffer; the byte count, or -1 with the Windows error set.
	const auto receive = [wait_ready, host_flags](ApiCall &call, const std::shared_ptr<SocketObject> &socket, uint64_t buffer, size_t length,
		uint32_t flags, sockaddr_storage *from, socklen_t *from_length) -> int64_t {
		std::vector<uint8_t> bytes(std::min<size_t>(length, 1 << 20));
		for (;;) {
			if (from_length)
				*from_length = sizeof(sockaddr_storage);
			const ssize_t count = ::recvfrom(socket->descriptor, bytes.data(), bytes.size(), (host_flags(flags) & ~MSG_WAITALL) | MSG_DONTWAIT,
				reinterpret_cast<sockaddr *>(from), from_length);
			if (count >= 0) {
				call.write(buffer, std::span<const uint8_t>(bytes.data(), size_t(count)));
				return count;
			}
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				call.set_last_error(wsa_error(errno));
				return -1;
			}
			if (socket->guest_nonblocking) {
				call.set_last_error(wsaewouldblock);
				return -1;
			}
			wait_ready(socket->descriptor, POLLIN, std::nullopt);
		}
	};
	const auto transmit = [wait_ready, host_flags](ApiCall &call, const std::shared_ptr<SocketObject> &socket, uint64_t buffer, size_t length,
		uint32_t flags, const sockaddr *to, socklen_t to_length) -> int64_t {
		const auto bytes = call.read(buffer, length);
		size_t sent = 0;
		while (sent < bytes.size() || bytes.empty()) {
			const ssize_t count = ::sendto(socket->descriptor, bytes.data() + sent, bytes.size() - sent, host_flags(flags) | MSG_DONTWAIT, to, to_length);
			if (count >= 0) {
				sent += size_t(count);
				if (socket->type != SOCK_STREAM || bytes.empty())
					break;
				continue;
			}
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				call.set_last_error(wsa_error(errno));
				return -1;
			}
			// A non-blocking socket reports what it could take; with nothing taken it reports that it would block.
			if (socket->guest_nonblocking) {
				if (sent)
					break;
				call.set_last_error(wsaewouldblock);
				return -1;
			}
			wait_ready(socket->descriptor, POLLOUT, std::nullopt);
		}
		return int64_t(sent);
	};
	registry.add("recv", 4, [socket_of, fail, receive](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket) {
			fail(call, wsaenotsock);
			return;
		}
		const auto count = receive(call, socket, call[1], size_t(std::max(call.i32(2), 0)), call.u32(3), nullptr, nullptr);
		call.ret(count < 0 ? uint64_t(UINT64_MAX) : uint64_t(count));
	});
	registry.add("recvfrom", 6, [socket_of, fail, receive](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket) {
			fail(call, wsaenotsock);
			return;
		}
		sockaddr_storage from{};
		socklen_t from_length = sizeof(from);
		const auto count = receive(call, socket, call[1], size_t(std::max(call.i32(2), 0)), call.u32(3), call[4] ? &from : nullptr, call[4] ? &from_length : nullptr);
		if (count >= 0 && call[4])
			put_address(call, call[4], call[5], from, from_length);
		call.ret(count < 0 ? uint64_t(UINT64_MAX) : uint64_t(count));
	});
	registry.add("send", 4, [socket_of, fail, transmit](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket) {
			fail(call, wsaenotsock);
			return;
		}
		const auto count = transmit(call, socket, call[1], size_t(std::max(call.i32(2), 0)), call.u32(3), nullptr, 0);
		call.ret(count < 0 ? uint64_t(UINT64_MAX) : uint64_t(count));
	});
	registry.add("sendto", 6, [socket_of, fail, transmit](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket) {
			fail(call, wsaenotsock);
			return;
		}
		std::vector<uint8_t> to;
		if (call[4] && call.i32(5) >= 2)
			to = host_address(call, call[4], size_t(call.i32(5)));
		const auto count = transmit(call, socket, call[1], size_t(std::max(call.i32(2), 0)), call.u32(3),
			to.empty() ? nullptr : reinterpret_cast<const sockaddr *>(to.data()), socklen_t(to.size()));
		call.ret(count < 0 ? uint64_t(UINT64_MAX) : uint64_t(count));
	});
	// WSABUF is a length and a pointer: 8 bytes in a 32-bit program, 16 in a 64-bit one.
	struct Buffer {
		uint64_t address;
		uint32_t length;
	};
	const auto buffers_of = [](ApiCall &call, uint64_t array, uint32_t count) {
		std::vector<Buffer> result;
		const size_t width = call.pointer_width(), stride = width == 4 ? 8 : 16;
		for (uint32_t index = 0; index < count && index < 64; ++index)
			result.push_back({call.load_pointer(array + index * stride + (width == 4 ? 4 : 8)), call.load<uint32_t>(array + index * stride)});
		return result;
	};
	registry.add("WSARecv", 7, [socket_of, fail, receive, buffers_of](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket) {
			fail(call, wsaenotsock, UINT32_MAX);
			return;
		}
		if (call[5] || call[6]) {
			fail(call, wsaeopnotsupp, UINT32_MAX);
			return;
		}
		uint32_t flags = call[4] ? call.load<uint32_t>(call[4]) : 0;
		int64_t total = 0;
		for (const auto &buffer : buffers_of(call, call[1], call.u32(2))) {
			if (!buffer.length)
				continue;
			const auto count = receive(call, socket, buffer.address, buffer.length, flags, nullptr, nullptr);
			if (count < 0) {
				if (total)
					break;
				call.ret(UINT32_MAX);
				return;
			}
			total += count;
			if (uint32_t(count) < buffer.length)
				break;
		}
		if (call[3])
			call.store<uint32_t>(call[3], uint32_t(total));
		if (call[4])
			call.store<uint32_t>(call[4], 0);
		call.ret(0);
	});
	registry.add("WSASend", 7, [socket_of, fail, transmit, buffers_of](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket) {
			fail(call, wsaenotsock, UINT32_MAX);
			return;
		}
		if (call[5] || call[6]) {
			fail(call, wsaeopnotsupp, UINT32_MAX);
			return;
		}
		int64_t total = 0;
		for (const auto &buffer : buffers_of(call, call[1], call.u32(2))) {
			if (!buffer.length)
				continue;
			const auto count = transmit(call, socket, buffer.address, buffer.length, call.u32(4), nullptr, 0);
			if (count < 0) {
				if (total)
					break;
				call.ret(UINT32_MAX);
				return;
			}
			total += count;
			if (uint32_t(count) < buffer.length)
				break;
		}
		if (call[3])
			call.store<uint32_t>(call[3], uint32_t(total));
		call.ret(0);
	});
	registry.add("WSARecvFrom", 9, [socket_of, fail, receive, buffers_of](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket) {
			fail(call, wsaenotsock, UINT32_MAX);
			return;
		}
		if (call[7] || call[8]) {
			fail(call, wsaeopnotsupp, UINT32_MAX);
			return;
		}
		const auto buffers = buffers_of(call, call[1], call.u32(2));
		if (buffers.empty()) {
			fail(call, wsaeinval, UINT32_MAX);
			return;
		}
		sockaddr_storage from{};
		socklen_t from_length = sizeof(from);
		const auto count = receive(call, socket, buffers[0].address, buffers[0].length, call[4] ? call.load<uint32_t>(call[4]) : 0,
			call[5] ? &from : nullptr, call[5] ? &from_length : nullptr);
		if (count < 0) {
			call.ret(UINT32_MAX);
			return;
		}
		if (call[5])
			put_address(call, call[5], call[6], from, from_length);
		if (call[3])
			call.store<uint32_t>(call[3], uint32_t(count));
		if (call[4])
			call.store<uint32_t>(call[4], 0);
		call.ret(0);
	});
	registry.add("WSASendTo", 9, [socket_of, fail, transmit, buffers_of](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket) {
			fail(call, wsaenotsock, UINT32_MAX);
			return;
		}
		if (call[7] || call[8]) {
			fail(call, wsaeopnotsupp, UINT32_MAX);
			return;
		}
		const auto buffers = buffers_of(call, call[1], call.u32(2));
		if (buffers.empty()) {
			fail(call, wsaeinval, UINT32_MAX);
			return;
		}
		std::vector<uint8_t> to;
		if (call[5] && call.i32(6) >= 2)
			to = host_address(call, call[5], size_t(call.i32(6)));
		const auto count = transmit(call, socket, buffers[0].address, buffers[0].length, call.u32(4),
			to.empty() ? nullptr : reinterpret_cast<const sockaddr *>(to.data()), socklen_t(to.size()));
		if (count < 0) {
			call.ret(UINT32_MAX);
			return;
		}
		if (call[3])
			call.store<uint32_t>(call[3], uint32_t(count));
		call.ret(0);
	});

	registry.add("getsockname", 3, [socket_of, fail](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket || !call[2]) {
			fail(call, socket ? wsaefault : wsaenotsock);
			return;
		}
		sockaddr_storage storage{};
		socklen_t length = sizeof(storage);
		if (::getsockname(socket->descriptor, reinterpret_cast<sockaddr *>(&storage), &length)) {
			fail(call, wsa_error(errno));
			return;
		}
		put_address(call, call[1], call[2], storage, length);
		call.ret(0);
	});
	registry.add("getpeername", 3, [socket_of, fail](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket || !call[2]) {
			fail(call, socket ? wsaefault : wsaenotsock);
			return;
		}
		sockaddr_storage storage{};
		socklen_t length = sizeof(storage);
		if (::getpeername(socket->descriptor, reinterpret_cast<sockaddr *>(&storage), &length)) {
			fail(call, wsa_error(errno));
			return;
		}
		put_address(call, call[1], call[2], storage, length);
		call.ret(0);
	});

	// Options: the level and the option number differ between Windows and the host, and a few values have another shape.
	struct Option {
		int level, name;
	};
	const auto host_option = [](uint32_t level, uint32_t name) -> std::optional<Option> {
		if (level == sol_socket_windows) {
			switch (name) {
			case 0x0004: return Option{SOL_SOCKET, SO_REUSEADDR};
			case 0x0008: return Option{SOL_SOCKET, SO_KEEPALIVE};
			case 0x0020: return Option{SOL_SOCKET, SO_BROADCAST};
			case 0x0080: return Option{SOL_SOCKET, SO_LINGER};
			case 0x1001: return Option{SOL_SOCKET, SO_SNDBUF};
			case 0x1002: return Option{SOL_SOCKET, SO_RCVBUF};
			case 0x1005: return Option{SOL_SOCKET, SO_SNDTIMEO};
			case 0x1006: return Option{SOL_SOCKET, SO_RCVTIMEO};
			case 0x1007: return Option{SOL_SOCKET, SO_ERROR};
			case 0x1008: return Option{SOL_SOCKET, SO_TYPE};
			default: return std::nullopt;
			}
		}
		if (level == IPPROTO_TCP && name == 1)
			return Option{IPPROTO_TCP, TCP_NODELAY};
		if (level == IPPROTO_IPV6 && name == 27)
			return Option{IPPROTO_IPV6, IPV6_V6ONLY};
		if (level == IPPROTO_IP) {
			if (name == 4)
				return Option{IPPROTO_IP, IP_TOS};
			if (name == 2)
				return Option{IPPROTO_IP, IP_TTL};
		}
		return std::nullopt;
	};
	registry.add("setsockopt", 5, [socket_of, fail, host_option](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket) {
			fail(call, wsaenotsock);
			return;
		}
		const auto option = host_option(call.u32(1), call.u32(2));
		if (!option) {
			fail(call, wsaenoprotoopt);
			return;
		}
		const auto value = call[3] ? call.read(call[3], size_t(std::max(call.i32(4), 0))) : std::vector<uint8_t>{};
		int result;
		if (option->level == SOL_SOCKET && (option->name == SO_RCVTIMEO || option->name == SO_SNDTIMEO) && value.size() >= 4) {
			uint32_t milliseconds;
			std::memcpy(&milliseconds, value.data(), 4);
			timeval timeout{time_t(milliseconds / 1000), suseconds_t(milliseconds % 1000 * 1000)};
			result = ::setsockopt(socket->descriptor, option->level, option->name, &timeout, sizeof(timeout));
		} else if (option->level == SOL_SOCKET && option->name == SO_LINGER && value.size() >= 4) {
			uint16_t on, seconds;
			std::memcpy(&on, value.data(), 2);
			std::memcpy(&seconds, value.data() + 2, 2);
			linger setting{on, seconds};
			result = ::setsockopt(socket->descriptor, option->level, option->name, &setting, sizeof(setting));
		} else {
			result = ::setsockopt(socket->descriptor, option->level, option->name, value.data(), socklen_t(value.size()));
		}
		if (result) {
			fail(call, wsa_error(errno));
			return;
		}
		call.ret(0);
	});
	registry.add("getsockopt", 5, [socket_of, fail, host_option](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket || !call[3] || !call[4]) {
			fail(call, socket ? wsaefault : wsaenotsock);
			return;
		}
		const auto option = host_option(call.u32(1), call.u32(2));
		if (!option) {
			fail(call, wsaenoprotoopt);
			return;
		}
		int value = 0;
		socklen_t length = sizeof(value);
		if (::getsockopt(socket->descriptor, option->level, option->name, &value, &length)) {
			fail(call, wsa_error(errno));
			return;
		}
		if (option->level == SOL_SOCKET && option->name == SO_ERROR)
			value = int(value ? wsa_error(value) : 0);
		const uint32_t capacity = call.load<uint32_t>(call[4]);
		if (capacity < 4) {
			fail(call, wsaefault);
			return;
		}
		call.store<int32_t>(call[3], value);
		call.store<uint32_t>(call[4], 4);
		call.ret(0);
	});

	constexpr uint32_t fionbio = 0x8004667e, fionread = 0x4004667f, sio_keepalive_vals = 0x98000004;
	registry.add("ioctlsocket", 3, [socket_of, fail](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket || !call[2]) {
			fail(call, socket ? wsaefault : wsaenotsock);
			return;
		}
		if (call.u32(1) == fionbio) {
			socket->guest_nonblocking = call.load<uint32_t>(call[2]) != 0;
		} else if (call.u32(1) == fionread) {
			int available = 0;
			::ioctl(socket->descriptor, FIONREAD, &available);
			call.store<uint32_t>(call[2], uint32_t(available));
		} else {
			fail(call, wsaeinval);
			return;
		}
		call.ret(0);
	});
	registry.add("WSAIoctl", 9, [socket_of, fail](ApiCall &call) {
		const auto socket = socket_of(call[0]);
		if (!socket) {
			fail(call, wsaenotsock);
			return;
		}
		// Completion by overlapped structure or routine is not carried out: say so rather than finish the call as if it were.
		if (call[7] || call[8]) {
			fail(call, wsaeopnotsupp);
			return;
		}
		const auto code = call.u32(1);
		if (code == fionbio && call[2] && call.u32(3) >= 4) {
			socket->guest_nonblocking = call.load<uint32_t>(call[2]) != 0;
		} else if (code == fionread && call[4] && call.u32(5) >= 4) {
			int available = 0;
			::ioctl(socket->descriptor, FIONREAD, &available);
			call.store<uint32_t>(call[4], uint32_t(available));
		} else if (code == sio_keepalive_vals && call[2] && call.u32(3) >= 12) {
			const int enabled = call.load<uint32_t>(call[2]) != 0, idle = int(std::max<uint32_t>(call.load<uint32_t>(call[2] + 4) / 1000, 1)),
				interval = int(std::max<uint32_t>(call.load<uint32_t>(call[2] + 8) / 1000, 1));
			::setsockopt(socket->descriptor, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled));
			::setsockopt(socket->descriptor, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
			::setsockopt(socket->descriptor, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
		} else {
			fail(call, wsaeopnotsupp);
			return;
		}
		if (call[6])
			call.store<uint32_t>(call[6], code == fionread ? 4 : 0);
		call.ret(0);
	});

	// select: an fd_set is a count followed by that many socket handles, each as wide as the program's pointers.
	const auto set_at = [](ApiCall &call) { return call.pointer_width() == 4 ? size_t(4) : size_t(8); };
	registry.add("select", 5, [socket_of, fail, set_at, &threads](ApiCall &call) {
		struct Entry {
			uint64_t handle;
			int descriptor;
		};
		std::vector<Entry> sets[3];
		const size_t first = set_at(call), width = call.pointer_width();
		for (int kind = 0; kind < 3; ++kind) {
			const auto address = call[1 + size_t(kind)];
			if (!address)
				continue;
			const uint32_t count = std::min<uint32_t>(call.load<uint32_t>(address), 64);
			for (uint32_t index = 0; index < count; ++index) {
				const auto handle = call.load_pointer(address + first + index * width);
				const auto socket = socket_of(handle);
				if (!socket) {
					fail(call, wsaenotsock);
					return;
				}
				sets[kind].push_back({handle, socket->descriptor});
			}
		}
		std::optional<std::chrono::steady_clock::time_point> wake;
		if (call[4]) {
			const auto seconds = call.load<int32_t>(call[4]), micros = call.load<int32_t>(call[4] + 4);
			wake = std::chrono::steady_clock::now() + std::chrono::seconds(std::max(seconds, 0)) + std::chrono::microseconds(std::max(micros, 0));
		}
		static constexpr short events[3] = {POLLIN, POLLOUT, POLLPRI};
		const auto poll_once = [&](std::vector<pollfd> &entries) {
			entries.clear();
			for (int kind = 0; kind < 3; ++kind)
				for (const auto &item : sets[kind])
					entries.push_back({item.descriptor, events[kind], 0});
			return entries.empty() ? 0 : ::poll(entries.data(), nfds_t(entries.size()), 0);
		};
		std::vector<pollfd> entries;
		int ready = poll_once(entries);
		if (ready <= 0 && !(call[4] && wake && *wake <= std::chrono::steady_clock::now())) {
			HostWait waiting;
			threads.block([&] {
				std::vector<pollfd> again;
				return poll_once(again) > 0;
			}, wake);
			ready = poll_once(entries);
		}
		if (ready < 0) {
			fail(call, wsa_error(errno));
			return;
		}
		size_t position = 0;
		uint32_t total = 0;
		for (int kind = 0; kind < 3; ++kind) {
			const auto address = call[1 + size_t(kind)];
			std::vector<uint64_t> kept;
			for (const auto &item : sets[kind]) {
				const auto revents = entries[position++].revents;
				const bool hit = kind == 0 ? (revents & (POLLIN | POLLHUP | POLLERR)) != 0 : kind == 1 ? (revents & (POLLOUT | POLLERR)) != 0 : (revents & POLLPRI) != 0;
				if (hit)
					kept.push_back(item.handle);
			}
			total += uint32_t(kept.size());
			if (!address)
				continue;
			call.store<uint32_t>(address, uint32_t(kept.size()));
			for (size_t index = 0; index < kept.size(); ++index) {
				if (width == 4)
					call.store<uint32_t>(address + first + index * width, uint32_t(kept[index]));
				else
					call.store<uint64_t>(address + first + index * width, kept[index]);
			}
		}
		call.ret(total);
	});
	registry.add("__WSAFDIsSet", 2, [set_at](ApiCall &call) {
		const auto address = call[1];
		if (!address) {
			call.ret(0);
			return;
		}
		const size_t first = set_at(call), width = call.pointer_width();
		const uint32_t count = std::min<uint32_t>(call.load<uint32_t>(address), 64);
		for (uint32_t index = 0; index < count; ++index)
			if (call.load_pointer(address + first + index * width) == (width == 4 ? (call[0] & 0xffffffffULL) : call[0])) {
				call.ret(1);
				return;
			}
		call.ret(0);
	});

	// Names: the answers come from the host resolver, and the result is one block of guest memory that freeaddrinfo gives back.
	registry.add("getaddrinfo", 4, [&context](ApiCall &call) {
		const size_t width = call.pointer_width();
		// ADDRINFOA: four ints, the address length, then the canonical name, the address and the next entry.
		const size_t record = 16 + 4 * width;
		const size_t length_at = 16, canon_at = 16 + width, address_at = 16 + 2 * width, next_at = 16 + 3 * width;
		addrinfo hints{};
		const addrinfo *use = nullptr;
		if (call[2]) {
			hints.ai_flags = call.load<int32_t>(call[2]) & (AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST);
			hints.ai_family = host_family(call.load<int32_t>(call[2] + 4));
			hints.ai_socktype = call.load<int32_t>(call[2] + 8);
			hints.ai_protocol = call.load<int32_t>(call[2] + 12);
			use = &hints;
		}
		const auto node = call[0] ? call.narrow(call[0], 1025) : std::string();
		const auto service = call[1] ? call.narrow(call[1], 256) : std::string();
		addrinfo *found = nullptr;
		const int status = ::getaddrinfo(call[0] ? node.c_str() : nullptr, call[1] ? service.c_str() : nullptr, use, &found);
		if (status) {
			const uint32_t error = status == EAI_NONAME || status == EAI_NODATA ? wsahost_not_found : status == EAI_AGAIN ? 11002 :
				status == EAI_FAIL ? 11003 : status == EAI_SERVICE ? 10109 : status == EAI_FAMILY ? wsaeafnosupport : status == EAI_SOCKTYPE ? wsaesocktnosupport : wsaeinval;
			call.fail(error, error);
			return;
		}
		size_t count = 0, size = 0;
		for (const auto *entry = found; entry; entry = entry->ai_next) {
			++count;
			size += record + 32 + (entry->ai_canonname ? std::strlen(entry->ai_canonname) + 1 : 0);
		}
		const auto block = context.allocator.allocate(size, true);
		if (!block) {
			::freeaddrinfo(found);
			call.fail(wsaenobufs, wsaenobufs);
			return;
		}
		uint64_t cursor = block, previous = 0;
		for (const auto *entry = found; entry; entry = entry->ai_next) {
			const uint64_t self = cursor, address = self + record, canonical = address + 32;
			cursor = canonical + (entry->ai_canonname ? std::strlen(entry->ai_canonname) + 1 : 0);
			call.store<int32_t>(self, entry->ai_flags);
			call.store<int32_t>(self + 4, windows_family(entry->ai_family));
			call.store<int32_t>(self + 8, entry->ai_socktype);
			call.store<int32_t>(self + 12, entry->ai_protocol);
			if (width == 4)
				call.store<uint32_t>(self + length_at, entry->ai_addrlen);
			else
				call.store<uint64_t>(self + length_at, entry->ai_addrlen);
			std::vector<uint8_t> bytes(reinterpret_cast<const uint8_t *>(entry->ai_addr), reinterpret_cast<const uint8_t *>(entry->ai_addr) + entry->ai_addrlen);
			if (bytes.size() >= 2) {
				uint16_t family;
				std::memcpy(&family, bytes.data(), 2);
				family = uint16_t(windows_family(family));
				std::memcpy(bytes.data(), &family, 2);
			}
			call.write(address, bytes);
			call.store_pointer(self + address_at, address);
			if (entry->ai_canonname) {
				const std::string name(entry->ai_canonname);
				call.write(canonical, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(name.c_str()), name.size() + 1));
				call.store_pointer(self + canon_at, canonical);
			}
			if (previous)
				call.store_pointer(previous + next_at, self);
			previous = self;
		}
		::freeaddrinfo(found);
		call.store_pointer(call[3], block);
		call.ret(0);
		(void)count;
	});
	registry.add("freeaddrinfo", 1, [&context](ApiCall &call) {
		if (call[0])
			context.allocator.release(call[0]);
	});
	registry.add("gethostname", 2, [](ApiCall &call) {
		char name[256] = {};
		::gethostname(name, sizeof(name) - 1);
		const std::string text(name);
		if (!call[0] || call.i32(1) <= int(text.size())) {
			call.fail(call[0] ? wsaefault : wsaefault, UINT64_MAX);
			return;
		}
		call.put_narrow(call[0], text, size_t(call.i32(1)));
		call.ret(0);
	});
	registry.add("inet_addr", 1, [](ApiCall &call) {
		const auto text = call.narrow(call[0], 64);
		in_addr address{};
		call.ret(::inet_aton(text.c_str(), &address) ? address.s_addr : 0xffffffffU);
	});
	auto text_block = std::make_shared<uint64_t>(0);
	registry.add("inet_ntoa", 1, [&context, text_block](ApiCall &call) {
		if (!*text_block)
			*text_block = context.allocator.allocate(32, true);
		in_addr address{};
		address.s_addr = call.u32(0);
		const std::string text = ::inet_ntoa(address);
		call.put_narrow(*text_block, text, 32);
		call.ret(*text_block);
	});
	registry.add("htons", 1, [](ApiCall &call) { call.ret(uint16_t(call.u32(0) << 8 | (call.u32(0) >> 8 & 0xff))); });
	registry.add("ntohs", 1, [](ApiCall &call) { call.ret(uint16_t(call.u32(0) << 8 | (call.u32(0) >> 8 & 0xff))); });
	registry.add("htonl", 1, [](ApiCall &call) { call.ret(__builtin_bswap32(call.u32(0))); });
	registry.add("ntohl", 1, [](ApiCall &call) { call.ret(__builtin_bswap32(call.u32(0))); });

	// WSADATA differs in field order: the version words come first in both, the rest follows the program's layout.
	registry.add("WSAStartup", 2, [](ApiCall &call) {
		if (!call[1]) {
			call.ret(10014);
			return;
		}
		const uint16_t wanted = uint16_t(call.u32(0));
		const uint8_t major = uint8_t(wanted), minor = uint8_t(wanted >> 8);
		if (major == 0 || major > 2 || (major == 2 && minor > 2)) {
			call.ret(10092);
			return;
		}
		const bool narrow = call.pointer_width() == 4;
		std::vector<uint8_t> data(narrow ? 400 : 408);
		const uint16_t version = wanted, high = 0x0202;
		std::memcpy(data.data(), &version, 2);
		std::memcpy(data.data() + 2, &high, 2);
		const char description[] = "Raven Winsock 2.2", status[] = "Running";
		const uint16_t sockets = 0x7fff, datagram = 65467;
		if (narrow) {
			std::memcpy(data.data() + 4, description, sizeof(description));
			std::memcpy(data.data() + 261, status, sizeof(status));
			std::memcpy(data.data() + 390, &sockets, 2);
			std::memcpy(data.data() + 392, &datagram, 2);
		} else {
			std::memcpy(data.data() + 4, &sockets, 2);
			std::memcpy(data.data() + 6, &datagram, 2);
			std::memcpy(data.data() + 16, description, sizeof(description));
			std::memcpy(data.data() + 273, status, sizeof(status));
		}
		call.write(call[1], data);
		call.ret(0);
	});
	registry.add("WSACleanup", 0, [](ApiCall &call) { call.ret(0); });
	registry.add("WSAGetLastError", 0, [](ApiCall &call) { call.ret(call.last_error()); });
	registry.add("WSASetLastError", 1, [](ApiCall &call) { call.set_last_error(call.u32(0)); });
}

}
