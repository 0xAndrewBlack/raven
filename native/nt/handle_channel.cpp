#include "handle_channel.h"

#include "objects.h"
#include "threads.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <mutex>
#include <vector>

#include <sys/socket.h>
#include <unistd.h>

namespace raven {

namespace {

std::mutex channels_mutex;
std::vector<HandleChannel *> children;
HandleChannel *parent = nullptr;

// Frames that are not a handle sent over: a request names the value it wants in `handle` and its number in `size`; an answer carries
// the request number in `handle` and the kind of the object after this prefix, nothing after it when there is no such handle.
const std::string request_kind = "request", answer_prefix = "answer:";

}

HandleChannel::~HandleChannel()
{
	if (descriptor >= 0)
		::close(descriptor);
}

bool HandleChannel::send_frame(const InheritedHandle &record, int shared)
{
	if (descriptor < 0)
		return false;
	const auto bytes = serialize_inherited({record});
	iovec vector{const_cast<uint8_t *>(bytes.data()), bytes.size()};
	alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))] = {};
	msghdr message{};
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	if (shared >= 0) {
		message.msg_control = control;
		message.msg_controllen = sizeof(control);
		auto *header = CMSG_FIRSTHDR(&message);
		header->cmsg_level = SOL_SOCKET;
		header->cmsg_type = SCM_RIGHTS;
		header->cmsg_len = CMSG_LEN(sizeof(int));
		std::memcpy(CMSG_DATA(header), &shared, sizeof(int));
	}
	ssize_t sent;
	do sent = ::sendmsg(descriptor, &message, MSG_NOSIGNAL); while (sent < 0 && errno == EINTR);
	return sent == ssize_t(bytes.size());
}

uint64_t HandleChannel::send(InheritedHandle record, uint32_t inherit)
{
	const int shared = record.descriptor;
	if (shared < 0)
		return 0;
	const uint64_t value = next;
	next += 4;
	record.handle = value;
	record.descriptor = -1;
	if (inherit)
		record.bits |= 0x80000000U;
	return send_frame(record, shared) ? value : 0;
}

std::shared_ptr<KernelObject> HandleChannel::fetch(NativeObjects &objects, NativeThreads &threads, uint64_t value, bool close_source, uint32_t &access)
{
	const uint64_t number = next_request++;
	InheritedHandle request;
	request.kind = request_kind;
	request.handle = value;
	request.size = number;
	request.flags = close_source ? 1 : 0;
	if (!send_frame(request, -1))
		return nullptr;
	answers[number] = std::nullopt;
	// The other process answers when it next schedules its threads; meanwhile the threads of this one run.
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	threads.block([&] {
		receive(objects);
		const auto found = answers.find(number);
		return found == answers.end() || found->second.has_value();
	}, deadline);
	const auto found = answers.find(number);
	if (found == answers.end() || !found->second) {
		answers.erase(number);
		return nullptr;
	}
	auto record = *found->second;
	answers.erase(found);
	if (record.kind.empty() || record.descriptor < 0)
		return nullptr;
	access = record.handle_access;
	auto object = object_from_record(record);
	if (!object)
		::close(record.descriptor);
	return object;
}

void HandleChannel::receive(NativeObjects &objects)
{
	for (;;) {
		uint8_t buffer[65536];
		iovec vector{buffer, sizeof(buffer)};
		alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int) * 4)] = {};
		msghdr message{};
		message.msg_iov = &vector;
		message.msg_iovlen = 1;
		message.msg_control = control;
		message.msg_controllen = sizeof(control);
		ssize_t count;
		do count = ::recvmsg(descriptor, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC); while (count < 0 && errno == EINTR);
		if (count <= 0)
			return;
		int received = -1;
		for (auto *header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header))
			if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS)
				std::memcpy(&received, CMSG_DATA(header), sizeof(int));
		std::vector<InheritedHandle> records;
		try {
			records = parse_inherited({buffer, size_t(count)});
		} catch (const std::exception &) {
		}
		if (records.size() != 1) {
			if (received >= 0)
				::close(received);
			continue;
		}
		auto &record = records.front();
		if (record.kind == request_kind) {
			// The other process wants one of this process's handles: the answer carries the descriptor behind it.
			InheritedHandle answer;
			answer.kind = answer_prefix;
			answer.handle = record.size;
			const auto object = objects.object(record.handle);
			InheritedHandle described;
			int shared = -1;
			if (object && object->describe(described)) {
				shared = described.descriptor;
				answer = described;
				answer.kind = answer_prefix + described.kind;
				answer.handle = record.size;
				answer.descriptor = -1;
				answer.handle_access = objects.access_of(record.handle);
			}
			send_frame(answer, shared);
			if (shared >= 0 && (record.flags & 1))
				objects.close(record.handle);
			continue;
		}
		if (record.kind.starts_with(answer_prefix)) {
			record.kind = record.kind.substr(answer_prefix.size());
			record.descriptor = received;
			const auto found = answers.find(record.handle);
			if (found != answers.end())
				found->second = record;
			else if (received >= 0)
				::close(received);
			continue;
		}
		if (received < 0)
			continue;
		record.descriptor = received;
		try {
			adopt_inherited(objects, records);
		} catch (const std::exception &) {
			::close(received);
		}
	}
}

void set_parent_channel(int descriptor)
{
	std::lock_guard lock(channels_mutex);
	parent = new HandleChannel(descriptor, handle_range_to_parent);
}

HandleChannel *parent_channel()
{
	std::lock_guard lock(channels_mutex);
	return parent;
}

void add_child_channel(HandleChannel *channel)
{
	std::lock_guard lock(channels_mutex);
	children.push_back(channel);
}

void remove_child_channel(HandleChannel *channel)
{
	std::lock_guard lock(channels_mutex);
	children.erase(std::remove(children.begin(), children.end(), channel), children.end());
}

void receive_handles(NativeObjects &objects)
{
	std::vector<HandleChannel *> sources;
	{
		std::lock_guard lock(channels_mutex);
		sources = children;
		if (parent)
			sources.push_back(parent);
	}
	for (auto *channel : sources)
		channel->receive(objects);
}

}
