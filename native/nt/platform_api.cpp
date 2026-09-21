#include <cstdio>
#include "elevation.h"
#include "hash.h"
#include "host_names.h"
#include "kernel_context.h"

#include <sys/random.h>
#include "text.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <unistd.h>

namespace raven {

namespace {

constexpr uint32_t e_fail = 0x80004005U, e_handle = 0x80070006U, e_invalidarg = 0x80070057U, e_notimpl = 0x80004001U, s_ok = 0, s_false = 1;
constexpr uint32_t class_not_registered = 0x80040154U, class_string = 0x800401f3U, no_signature = 0x800b0100U;

// A CryptoAPI provider or hash handle is a small integer into these tables.
struct CryptState {
	std::map<uint64_t, bool> providers;
	std::map<uint64_t, std::unique_ptr<Digest>> hashes;
	uint64_t next = 0x1000;
};

// COM per thread: how often it was initialized and in which apartment, single-threaded or the multithreaded one.
struct ComState {
	struct Thread {
		int count = 0;
		bool multithreaded = false;
	};
	std::map<uint64_t, Thread> threads;
	uint64_t main_sta = 0;
	int mta_threads = 0;
};

}

void register_platform_api(ApiRegistry &registry, KernelContext &context)
{
	// uxtheme: the visual styles are the window manager's (desktop/theme.cpp); buffered painting draws straight to the target.
	registry.add("EnableTheming", 1, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("BeginBufferedPaint", 5, [](ApiCall &call) { call.ret(0); });
	registry.add("EndBufferedPaint", 2, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("BeginBufferedAnimation", 8, [](ApiCall &call) { call.ret(0); });
	registry.add("EndBufferedAnimation", 2, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("BufferedPaintStopAllAnimations", 1, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("BufferedPaintRenderAnimation", 2, [](ApiCall &call) { call.ret(0); });

	// dwmapi: no compositor interface; attribute requests are accepted and ignored.
	registry.add("DwmSetWindowAttribute", 4, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("DwmGetWindowAttribute", 4, [](ApiCall &call) { call.ret(e_invalidarg); });
	registry.add("DwmIsCompositionEnabled", 1, [](ApiCall &call) {
		call.store<uint32_t>(call[0], 0);
		call.ret(s_ok);
	});
	registry.add("DwmExtendFrameIntoClientArea", 2, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("DwmFlush", 0, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("DwmGetCompositionTimingInfo", 2, [](ApiCall &call) { call.ret(0x80263001U); });

	// imm32: there is no input method, so contexts do not exist and composition calls fail.
	registry.add("ImmGetContext", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmReleaseContext", 2, [](ApiCall &call) { call.ret(1); });
	registry.add("ImmCreateContext", 0, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmDestroyContext", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmAssociateContext", 2, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmAssociateContextEx", 3, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmGetDefaultIMEWnd", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmIsIME", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmGetCompositionStringW", 4, [](ApiCall &call) { call.ret(uint32_t(-1)); });
	registry.add("ImmSetCompositionStringW", 6, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmSetCompositionWindow", 2, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmSetCompositionFontW", 2, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmSetCandidateWindow", 2, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmNotifyIME", 4, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmEscapeW", 4, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmGetOpenStatus", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmSetOpenStatus", 2, [](ApiCall &call) { call.ret(0); });
	registry.add("ImmGetConversionStatus", 3, [](ApiCall &call) { call.ret(0); });

	// Network and trust services: no signatures are verifiable and no network is reported.
	registry.add("WinVerifyTrust", 3, [](ApiCall &call) { call.ret(no_signature); });
	registry.add("IsNetworkAlive", 1, [](ApiCall &call) {
		if (call[0]) call.store<uint32_t>(call[0], 0);
		call.ret(0);
	});
	registry.add("IsDestinationReachableW", 2, [](ApiCall &call) { call.ret(0); });
	registry.add("CertFindCertificateInStore", 6, [](ApiCall &call) { call.fail(0x80092004U, 0); });
	registry.add("CertGetCertificateContextProperty", 4, [](ApiCall &call) { call.fail(0x80092004U, 0); });
	registry.add("CertGetNameStringW", 6, [](ApiCall &call) { call.ret(0); });
	registry.add("CertNameToStrW", 5, [](ApiCall &call) { call.ret(0); });
	registry.add("CryptQueryObject", 11, [](ApiCall &call) { call.fail(0x80092009U, 0); });
	registry.add("CryptMsgGetParam", 5, [](ApiCall &call) { call.fail(0x80091004U, 0); });
	registry.add("CryptMsgClose", 1, [](ApiCall &call) { call.ret(1); });
	registry.add("ImageNtHeader", 1, [](ApiCall &call) {
		const auto offset = call.load<uint32_t>(call[0] + 0x3c);
		call.ret(call[0] + offset);
	});

	// wininet: URL cracking is pure text processing.
	registry.add("InternetCrackUrlW", 4, [](ApiCall &call) {
		const auto url = call.wide(call[0], 4096);
		const auto scheme_end = url.find(u"://");
		if (scheme_end == url.npos || !call[3]) {
			call.fail(12006);
			return;
		}
		const auto scheme = url.substr(0, scheme_end);
		const auto host_start = scheme_end + 3;
		const auto path_start = url.find_first_of(u"/?#", host_start);
		auto authority = url.substr(host_start, path_start == url.npos ? url.npos : path_start - host_start);
		std::u16string user, password;
		if (const auto at = authority.rfind(u'@'); at != authority.npos) {
			const auto credentials = authority.substr(0, at);
			authority = authority.substr(at + 1);
			const auto colon = credentials.find(u':');
			user = credentials.substr(0, colon);
			password = colon == credentials.npos ? u"" : credentials.substr(colon + 1);
		}
		uint32_t port = scheme == u"https" ? 443 : scheme == u"ftp" ? 21 : 80;
		std::u16string host = authority;
		if (const auto colon = authority.rfind(u':'); colon != authority.npos && authority.find(u']') == authority.npos) {
			host = authority.substr(0, colon);
			port = uint32_t(std::stoul(to_utf8(authority.substr(colon + 1))));
		}
		const auto rest = path_start == url.npos ? std::u16string() : url.substr(path_start);
		const auto extra_at = rest.find_first_of(u"?#");
		const auto path = rest.substr(0, extra_at);
		const auto extra = extra_at == rest.npos ? std::u16string() : rest.substr(extra_at);
		// URL_COMPONENTSW: size, scheme ptr/len, scheme id, host ptr/len, port, user ptr/len, password ptr/len, path ptr/len, extra ptr/len.
		const uint64_t components = call[3];
		const auto fill = [&](uint64_t pointer_at, uint64_t length_at, const std::u16string &value) {
			const uint64_t buffer = call.load<uint64_t>(components + pointer_at);
			const uint32_t capacity = call.load<uint32_t>(components + length_at);
			if (buffer) {
				if (capacity <= value.size()) {
					call.fail(122);
					return false;
				}
				call.put_wide(buffer, value, capacity);
			} else if (value.empty()) {
				call.store<uint64_t>(components + pointer_at, 0);
			} else {
				call.store<uint64_t>(components + pointer_at, call[0] + (url.size() - (url.size() - url.find(value))) * 2);
			}
			call.store<uint32_t>(components + length_at, uint32_t(value.size()));
			return true;
		};
		if (!fill(8, 16, scheme) || !fill(24, 32, host) || !fill(48, 56, user) || !fill(64, 72, password) || !fill(80, 88, path) || !fill(96, 104, extra))
			return;
		call.store<uint32_t>(components + 20, scheme == u"https" ? 2 : scheme == u"http" ? 3 : scheme == u"ftp" ? 1 : 0);
		call.store<uint32_t>(components + 40, port & 0xffff);
		call.ret(1);
	});

	// COM: no class registry exists, so object creation reports "class not registered".
	auto com = std::make_shared<ComState>();
	// A thread joins an apartment on its first initialization; asking for the other kind later fails with RPC_E_CHANGED_MODE.
	// Programs also read the apartment from the thread's OLE data, which TEB.ReservedForOle points at: its flags word (after two
	// pointers and the apartment id) has OLETLS_APARTMENTTHREADED (0x80), or OLETLS_MULTITHREADED with OLETLS_DISABLE_OLE1DDE (0x140).
	const auto ole_flags = [&context](ApiCall &call, uint32_t flags) {
		const size_t width = call.pointer_width();
		const uint64_t slot = context.environment.teb() + (width == 4 ? 0xf80 : 0x1758);
		uint64_t data = call.load_pointer(slot);
		if (!data) {
			data = context.allocator.allocate(0x100, true);
			if (!data)
				return;
			call.store_pointer(slot, data);
		}
		call.store<uint32_t>(data + 2 * width + 4, flags);
	};
	const auto initialize = [com, &context, ole_flags](ApiCall &call, bool multithreaded, bool no_dde) {
		const uint64_t thread = context.environment.teb();
		auto &state = com->threads[thread];
		if (state.count && state.multithreaded != multithreaded) {
			call.ret(0x80010106U);
			return;
		}
		if (!state.count++) {
			state.multithreaded = multithreaded;
			if (multithreaded)
				++com->mta_threads;
			else if (!com->main_sta)
				com->main_sta = thread;
			ole_flags(call, multithreaded ? 0x140U : no_dde ? 0xc0U : 0x80U);
			call.ret(s_ok);
			return;
		}
		call.ret(s_false);
	};
	registry.add("CoInitialize", 1, [initialize](ApiCall &call) { initialize(call, false, false); });
	registry.add("CoInitializeEx", 2, [initialize](ApiCall &call) { initialize(call, !(call.u32(1) & 2), call.u32(1) & 4); });
	registry.add("OleInitialize", 1, [initialize](ApiCall &call) { initialize(call, false, false); });
	const auto uninitialize = [com, &context, ole_flags](ApiCall &call) {
		const uint64_t thread = context.environment.teb();
		auto found = com->threads.find(thread);
		if (found == com->threads.end() || !found->second.count)
			return;
		if (!--found->second.count) {
			if (found->second.multithreaded)
				--com->mta_threads;
			else if (com->main_sta == thread)
				com->main_sta = 0;
			com->threads.erase(found);
			ole_flags(call, 0);
		}
	};
	// Message filters belong to single-threaded apartments; there is no filter before the first one, so the previous one is null.
	registry.add("CoRegisterMessageFilter", 2, [com, &context](ApiCall &call) {
		const auto found = com->threads.find(context.environment.teb());
		if (call[1])
			call.store_pointer(call[1], 0);
		if (found == com->threads.end() || !found->second.count || found->second.multithreaded) {
			call.ret(0x80004021U);
			return;
		}
		call.ret(s_ok);
	});
	// APTTYPE: STA 0, MTA 1, main STA 3. A thread that never initialized COM is in the multithreaded apartment implicitly while any
	// thread of the process holds it (qualifier APTTYPEQUALIFIER_IMPLICIT_MTA).
	registry.add("CoGetApartmentType", 2, [com, &context](ApiCall &call) {
		if (!call[0] || !call[1]) {
			call.ret(e_invalidarg);
			return;
		}
		const uint64_t thread = context.environment.teb();
		const auto found = com->threads.find(thread);
		uint32_t type = 0, qualifier = 0;
		if (found != com->threads.end() && found->second.count) {
			type = found->second.multithreaded ? 1 : com->main_sta == thread ? 3 : 0;
		} else if (com->mta_threads) {
			type = 1;
			qualifier = 1;
		} else {
			call.store<uint32_t>(call[0], 0xffffffffU);
			call.store<uint32_t>(call[1], 0);
			call.ret(0x800401f0U);
			return;
		}
		call.store<uint32_t>(call[0], type);
		call.store<uint32_t>(call[1], qualifier);
		call.ret(s_ok);
	});
	registry.add("CoUninitialize", 0, uninitialize);
	registry.add("OleUninitialize", 0, uninitialize);
	registry.add("CoCreateInstance", 5, [](ApiCall &call) {
		if (std::getenv("RAVEN_TRACE_API")) {
			const auto bytes = call.read(call[0], 16);
			std::fprintf(stderr, "com class");
			for (const auto byte : bytes) std::fprintf(stderr, " %02x", byte);
			std::fprintf(stderr, "\n");
		}
		if (call[4]) call.store_pointer(call[4], 0);
		call.ret(class_not_registered);
	});
	registry.add("CoGetClassObject", 5, [](ApiCall &call) {
		if (call[4]) call.store_pointer(call[4], 0);
		call.ret(class_not_registered);
	});
	registry.add("CLSIDFromProgID", 2, [](ApiCall &call) { call.ret(class_string); });
	// A GUID in its registry form, "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}", as the 16 bytes of the structure; nothing for any other text.
	const auto parse_guid = [](std::u16string_view text) -> std::optional<std::vector<uint8_t>> {
		static constexpr size_t digits[16][2] = {{7, 1}, {5, 1}, {3, 1}, {1, 1}, {12, 1}, {10, 1}, {17, 1}, {15, 1}, {20, 1}, {22, 1}, {25, 1}, {27, 1},
			{29, 1}, {31, 1}, {33, 1}, {35, 1}};
		if (text.size() != 38 || text[0] != u'{' || text[37] != u'}' || text[9] != u'-' || text[14] != u'-' || text[19] != u'-' || text[24] != u'-')
			return std::nullopt;
		const auto nibble = [](char16_t c) -> int {
			if (c >= u'0' && c <= u'9') return c - u'0';
			if (c >= u'a' && c <= u'f') return c - u'a' + 10;
			if (c >= u'A' && c <= u'F') return c - u'A' + 10;
			return -1;
		};
		std::vector<uint8_t> bytes(16);
		for (size_t index = 0; index < 16; ++index) {
			const int high = nibble(text[digits[index][0]]), low = nibble(text[digits[index][0] + digits[index][1]]);
			if (high < 0 || low < 0)
				return std::nullopt;
			bytes[index] = uint8_t(high << 4 | low);
		}
		return bytes;
	};
	// An empty or null text is the null class; a text that is not a GUID would be a program identifier, which no registered class answers.
	registry.add("CLSIDFromString", 2, [parse_guid](ApiCall &call) {
		const auto text = call[0] ? call.wide(call[0], 64) : std::u16string();
		if (text.empty()) {
			call.write(call[1], std::vector<uint8_t>(16));
			call.ret(0);
			return;
		}
		const auto bytes = parse_guid(text);
		if (!bytes) {
			call.write(call[1], std::vector<uint8_t>(16));
			call.ret(class_string);
			return;
		}
		call.write(call[1], *bytes);
		call.ret(0);
	});
	// A random GUID of version 4 with the RFC 4122 variant, as CoCreateGuid makes.
	registry.add("CoCreateGuid", 1, [](ApiCall &call) {
		std::vector<uint8_t> bytes(16);
		if (!call[0] || ::getrandom(bytes.data(), bytes.size(), 0) != ssize_t(bytes.size())) {
			call.ret(0x80070057U);
			return;
		}
		bytes[7] = uint8_t((bytes[7] & 0x0f) | 0x40);
		bytes[8] = uint8_t((bytes[8] & 0x3f) | 0x80);
		call.write(call[0], bytes);
		call.ret(0);
	});
	registry.add("IIDFromString", 2, [parse_guid](ApiCall &call) {
		const auto text = call[0] ? call.wide(call[0], 64) : std::u16string();
		const auto bytes = text.empty() ? std::optional(std::vector<uint8_t>(16)) : parse_guid(text);
		if (!bytes) {
			call.ret(0x80070057U);
			return;
		}
		call.write(call[1], *bytes);
		call.ret(0);
	});
	// The registry form of a GUID, "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}", from its sixteen bytes.
	const auto guid_text = [](const std::vector<uint8_t> &bytes) {
		static constexpr int order[16] = {3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1, 8, 9, -1, 10, 11};
		char text[40];
		int at = 0;
		text[at++] = '{';
		for (const int index : order) {
			if (index < 0) {
				text[at++] = '-';
				continue;
			}
			at += std::snprintf(text + at, 3, "%02X", bytes[size_t(index)]);
		}
		for (size_t index = 12; index < 16; ++index)
			at += std::snprintf(text + at, 3, "%02X", bytes[index]);
		text[at++] = '}';
		return widen_ascii(std::string_view(text, size_t(at)));
	};
	registry.add("StringFromGUID2", 3, [guid_text](ApiCall &call) {
		if (call.u32(2) < 39) {
			call.ret(0);
			return;
		}
		call.put_wide(call[1], guid_text(call.read(call[0], 16)), 39);
		call.ret(39);
	});
	// The same text in memory from the task allocator, which the caller frees with CoTaskMemFree.
	for (const char *name : {"StringFromCLSID", "StringFromIID"})
		registry.add(name, 2, [&context, guid_text](ApiCall &call) {
			const auto memory = context.allocator.allocate(39 * sizeof(char16_t), false);
			if (!memory) {
				call.store_pointer(call[1], 0);
				call.ret(0x8007000eU);
				return;
			}
			call.put_wide(memory, guid_text(call.read(call[0], 16)), 39);
			call.store_pointer(call[1], memory);
			call.ret(0);
		});
	registry.add("CoTaskMemAlloc", 1, [&context](ApiCall &call) { call.ret(context.allocator.allocate(call[0], false)); });
	registry.add("CoTaskMemFree", 1, [&context](ApiCall &call) {
		if (call[0]) context.allocator.release(call[0]);
	});
	registry.add("CoTaskMemRealloc", 2, [&context](ApiCall &call) {
		if (!call[0]) {
			call.ret(context.allocator.allocate(call[1], false));
			return;
		}
		const auto old = context.allocator.size(call[0]);
		const auto address = context.allocator.allocate(call[1], false);
		if (address && old != UINT64_MAX)
			call.write(address, call.read(call[0], std::min<uint64_t>(old, call[1])));
		if (address)
			context.allocator.release(call[0]);
		call.ret(address);
	});
	registry.add("RegisterDragDrop", 2, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("RevokeDragDrop", 1, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("DoDragDrop", 4, [](ApiCall &call) {
		if (call[3]) call.store<uint32_t>(call[3], 0);
		call.ret(0x40101);
	});
	registry.add("ReleaseStgMedium", 1, [](ApiCall &) {});
	registry.add("OleFlushClipboard", 0, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("OleGetClipboard", 1, [](ApiCall &call) {
		if (call[0]) call.store<uint64_t>(call[0], 0);
		call.ret(e_notimpl);
	});

	// BSTRs: a four-byte byte count precedes the characters, which are zero-terminated.
	const auto make_bstr = [&context](ApiCall &call, const uint8_t *bytes, size_t length) {
		const auto block = context.allocator.allocate(length + 4 + 2, false);
		if (!block) {
			call.ret(0);
			return;
		}
		std::vector<uint8_t> data(length + 6);
		std::memcpy(data.data(), &(const uint32_t &)(uint32_t(length)), 4);
		if (bytes)
			std::memcpy(data.data() + 4, bytes, length);
		call.write(block, data);
		call.ret(block + 4);
	};
	registry.add("SysAllocString", 1, [make_bstr](ApiCall &call) {
		if (!call[0]) {
			call.ret(0);
			return;
		}
		const auto text = call.wide(call[0], 1 << 24);
		make_bstr(call, reinterpret_cast<const uint8_t *>(text.data()), text.size() * 2);
	});
	registry.add("SysAllocStringLen", 2, [make_bstr](ApiCall &call) {
		const size_t count = call.u32(1);
		std::vector<uint8_t> bytes(count * 2);
		if (call[0] && count)
			bytes = call.read(call[0], count * 2);
		make_bstr(call, bytes.data(), bytes.size());
	});
	registry.add("SysAllocStringByteLen", 2, [make_bstr](ApiCall &call) {
		const size_t count = call.u32(1);
		std::vector<uint8_t> bytes(count);
		if (call[0] && count)
			bytes = call.read(call[0], count);
		make_bstr(call, bytes.data(), bytes.size());
	});
	registry.add("SysFreeString", 1, [&context](ApiCall &call) {
		if (call[0]) context.allocator.release(call[0] - 4);
	});
	// A VARIANT is 16 bytes in a 32-bit program and 24 in a 64-bit one: the type, three reserved words and the value, which may hold a pointer.
	registry.add("VariantInit", 1, [](ApiCall &call) {
		if (!call[0])
			return;
		call.write(call[0], std::vector<uint8_t>(call.pointer_width() == 4 ? 16 : 24));
	});
	registry.add("VariantClear", 1, [&context, &registry](ApiCall &call) {
		constexpr uint16_t vt_bstr = 8, vt_dispatch = 9, vt_unknown = 13, vt_byref = 0x4000, vt_array = 0x2000;
		if (!call[0]) {
			call.ret(0x80070057U);
			return;
		}
		const uint16_t type = call.load<uint16_t>(call[0]);
		const auto value = call.load_pointer(call[0] + 8);
		if (!(type & (vt_byref | vt_array)) && type == vt_bstr && value) {
			context.allocator.release(value - 4);
		} else if (!(type & (vt_byref | vt_array)) && (type == vt_dispatch || type == vt_unknown) && value) {
			// The object is told its reference is gone: Release is the third method of every interface.
			const auto table = call.load_pointer(value);
			const auto release = call.load_pointer(table + 2 * call.pointer_width());
			const uint64_t arguments[] = {value};
			context.call(release, arguments);
		}
		call.write(call[0], std::vector<uint8_t>(2));
		call.ret(0);
	});
	registry.add("SysStringLen", 1, [](ApiCall &call) { call.ret(call[0] ? call.load<uint32_t>(call[0] - 4) / 2 : 0); });
	registry.add("SysStringByteLen", 1, [](ApiCall &call) { call.ret(call[0] ? call.load<uint32_t>(call[0] - 4) : 0); });
	// SysReAllocString replaces the string a BSTR variable holds: the new copy is made before the old one is released.
	const auto reallocate = [&context, make_bstr](ApiCall &call, bool counted) {
		if (!call[0]) {
			call.fail(87);
			return;
		}
		const uint64_t old = call.load_pointer(call[0]);
		std::vector<uint8_t> bytes;
		if (call[1]) {
			const size_t count = counted ? call.u32(2) : call.wide(call[1], 1 << 24).size();
			bytes = count ? call.read(call[1], count * 2) : std::vector<uint8_t>{};
		}
		make_bstr(call, bytes.data(), bytes.size());
		if (!call.result)
			return;
		call.store_pointer(call[0], call.result);
		if (old)
			context.allocator.release(old - 4);
		call.ret(1);
	};
	registry.add("SysReAllocString", 2, [reallocate](ApiCall &call) { reallocate(call, false); });
	registry.add("SysReAllocStringLen", 3, [reallocate](ApiCall &call) { reallocate(call, true); });

	// Random bytes come from the host: RtlGenRandom (exported from advapi32 as SystemFunction036) and BCryptGenRandom.
	const auto random_bytes = [](ApiCall &call, uint64_t buffer, size_t length) {
		std::vector<uint8_t> bytes(length);
		for (size_t done = 0; done < length;) {
			const auto count = ::getrandom(bytes.data() + done, length - done, 0);
			if (count < 0 && errno != EINTR)
				return false;
			if (count > 0)
				done += size_t(count);
		}
		call.write(buffer, bytes);
		return true;
	};
	// CryptProtectMemory: the block is mixed in place with a keystream that only this process (flag 0) or every process of the user in
	// this prefix (flags 1 and 2) can make again. The length must be a whole number of 16-byte blocks.
	const auto protect_memory = [](ApiCall &call) {
		const uint64_t length = call.u32(1);
		const uint32_t scope = call.u32(2);
		if (!call[0] || length % 16 || scope > 2) {
			call.fail(87, 0);
			return;
		}
		static const std::vector<uint8_t> process_key = [] {
			std::vector<uint8_t> key(32);
			for (size_t done = 0; done < key.size();) {
				const auto count = ::getrandom(key.data() + done, key.size() - done, 0);
				if (count > 0)
					done += size_t(count);
			}
			return key;
		}();
		const std::string shared_seed = "raven-protect-memory:" + prefix_tag() + ":" + std::to_string(::getuid());
		auto bytes = call.read(call[0], length);
		for (uint64_t block = 0; block * 32 < length; ++block) {
			auto digest = make_digest(0x800c);
			if (scope == 0)
				digest->update(process_key);
			else
				digest->update(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(shared_seed.data()), shared_seed.size()));
			digest->update(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&block), sizeof(block)));
			const auto stream = digest->finish();
			for (size_t at = 0; at < 32 && block * 32 + at < length; ++at)
				bytes[block * 32 + at] ^= stream[at];
		}
		call.write(call[0], bytes);
		call.ret(1);
	};
	registry.add("CryptProtectMemory", 3, protect_memory);
	registry.add("CryptUnprotectMemory", 3, protect_memory);
	registry.add("SystemFunction036", 2, [random_bytes](ApiCall &call) {
		if (!call[0]) {
			call.fail(87);
			return;
		}
		call.ret(random_bytes(call, call[0], call.u32(1)));
	});
	// The generator that Chromium asks for by name: it fills the buffer and always reports success.
	registry.add("ProcessPrng", 2, [random_bytes](ApiCall &call) {
		if (call[0] && call[1])
			call.ret(random_bytes(call, call[0], size_t(call[1])));
		else
			call.ret(1);
	});
	registry.add("BCryptGenRandom", 4, [random_bytes](ApiCall &call) {
		// Only the system generator exists: the pseudo handle BCRYPT_RNG_ALG_HANDLE (0x81), or no handle with the preferred-generator flag.
		const bool generator = call[0] == 0x81 || (!call[0] && (call.u32(3) & 2));
		if (!generator || !call[1]) {
			call.ret(0xc0000008U);
			return;
		}
		call.ret(random_bytes(call, call[1], call.u32(2)) ? 0 : 0xc0000001U);
	});
	// Windows Runtime strings: a string handle points at a header (flags, length, pointer to the characters). A copy owns its characters in the
	// same block; a reference points at the caller's.
	const auto make_hstring = [&context](ApiCall &call, uint64_t source, uint32_t length, uint64_t out) -> uint32_t {
		if (!out)
			return 0x80070057U;
		if (!length) {
			call.store_pointer(out, 0);
			return 0;
		}
		const size_t width = call.pointer_width(), head = 8 + width;
		const auto block = context.allocator.allocate(head + (size_t(length) + 1) * 2, true);
		if (!block)
			return 0x8007000eU;
		std::vector<uint8_t> image(head + (size_t(length) + 1) * 2);
		const uint64_t characters = block + head;
		std::memcpy(image.data() + 4, &length, 4);
		std::memcpy(image.data() + 8, &characters, width);
		const auto text = call.read(source, size_t(length) * 2);
		std::memcpy(image.data() + head, text.data(), text.size());
		call.write(block, image);
		call.store_pointer(out, block);
		return 0;
	};
	registry.add("WindowsCreateString", 3, [make_hstring](ApiCall &call) { call.ret(make_hstring(call, call[0], call.u32(1), call[2])); });
	registry.add("WindowsDuplicateString", 2, [make_hstring](ApiCall &call) {
		if (!call[0]) {
			if (call[1])
				call.store_pointer(call[1], 0);
			call.ret(0);
			return;
		}
		const size_t width = call.pointer_width();
		call.ret(make_hstring(call, call.load_pointer(call[0] + 8), call.load<uint32_t>(call[0] + 4), call[1]));
		(void)width;
	});
	registry.add("WindowsCreateStringReference", 4, [](ApiCall &call) {
		if (!call[2] || !call[3]) {
			call.ret(0x80070057U);
			return;
		}
		if (!call.u32(1)) {
			call.store_pointer(call[3], 0);
			call.ret(0);
			return;
		}
		const size_t width = call.pointer_width();
		std::vector<uint8_t> header(8 + width);
		header[0] = 1;
		const uint32_t length = call.u32(1);
		std::memcpy(header.data() + 4, &length, 4);
		const uint64_t source = call[0];
		std::memcpy(header.data() + 8, &source, width);
		call.write(call[2], header);
		call.store_pointer(call[3], call[2]);
		call.ret(0);
	});
	registry.add("WindowsDeleteString", 1, [&context](ApiCall &call) {
		if (call[0] && !(call.load<uint32_t>(call[0]) & 1))
			context.allocator.release(call[0]);
		call.ret(0);
	});
	registry.add("WindowsGetStringRawBuffer", 2, [](ApiCall &call) {
		if (!call[0]) {
			if (call[1])
				call.store<uint32_t>(call[1], 0);
			static const uint16_t empty = 0;
			(void)empty;
			call.ret(0);
			return;
		}
		if (call[1])
			call.store<uint32_t>(call[1], call.load<uint32_t>(call[0] + 4));
		call.ret(call.load_pointer(call[0] + 8));
	});
	registry.add("WindowsGetStringLen", 1, [](ApiCall &call) { call.ret(call[0] ? call.load<uint32_t>(call[0] + 4) : 0); });
	registry.add("WindowsIsStringEmpty", 1, [](ApiCall &call) { call.ret(!call[0] || !call.load<uint32_t>(call[0] + 4)); });
	// No Windows Runtime class exists here: initialization joins the thread to a COM apartment like CoInitializeEx (RO_INIT_MULTITHREADED
	// is 1), and every activation reports that the class is not registered.
	registry.add("RoInitialize", 1, [initialize](ApiCall &call) { initialize(call, call.u32(0) == 1, true); });
	registry.add("RoUninitialize", 0, uninitialize);
	registry.add("RoGetActivationFactory", 3, [](ApiCall &call) {
		if (call[2])
			call.store_pointer(call[2], 0);
		call.ret(0x80040154U);
	});
	registry.add("RoActivateInstance", 2, [](ApiCall &call) {
		if (call[1])
			call.store_pointer(call[1], 0);
		call.ret(0x80040154U);
	});
	// Event tracing: there is no session to receive events, so registrations succeed and events go nowhere.
	registry.add("RegisterTraceGuidsW", 8, [](ApiCall &call) {
		if (call[7])
			call.store_pointer(call[7], 1);
		call.ret(0);
	});
	registry.add("UnregisterTraceGuids", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("EventRegister", 4, [](ApiCall &call) {
		if (call[3])
			call.store<uint64_t>(call[3], 1);
		call.ret(0);
	});
	registry.add("EventUnregister", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("EventSetInformation", 4, [](ApiCall &call) { call.ret(0); });
	registry.add("EventWriteTransfer", 6, [](ApiCall &call) { call.ret(0); });
	registry.add("EventEnabled", 2, [](ApiCall &call) { call.ret(0); });
	registry.add("TraceEvent", 2, [](ApiCall &call) { call.ret(0); });
	// Proxy discovery: no proxy is configured, so sessions open and every lookup answers "connect directly".
	struct WinHttpSession : KernelObject {};
	registry.add("WinHttpOpen", 5, [&context](ApiCall &call) {
		const auto made = context.objects.add_object(std::make_shared<WinHttpSession>());
		if (made.status) {
			call.fail(8, 0);
			return;
		}
		call.ret(made.value);
	});
	registry.add("WinHttpCloseHandle", 1, [&context](ApiCall &call) {
		if (!context.objects.object_as<WinHttpSession>(call[0])) {
			call.fail(6);
			return;
		}
		context.objects.close(call[0]);
		call.ret(1);
	});
	registry.add("WinHttpSetTimeouts", 5, [](ApiCall &call) { call.ret(1); });
	registry.add("WinHttpGetIEProxyConfigForCurrentUser", 1, [](ApiCall &call) {
		if (!call[0]) {
			call.fail(87);
			return;
		}
		// WINHTTP_CURRENT_USER_IE_PROXY_CONFIG: auto-detect flag and three string pointers, all empty.
		call.write(call[0], std::vector<uint8_t>(call.pointer_width() == 4 ? 16 : 32));
		call.ret(1);
	});
	registry.add("WinHttpDetectAutoProxyConfigUrl", 2, [](ApiCall &call) { call.fail(12180); });
	registry.add("WinHttpGetProxyForUrl", 4, [](ApiCall &call) {
		if (!call[3]) {
			call.fail(87);
			return;
		}
		// WINHTTP_PROXY_INFO: the access type (1 is no proxy) and two empty string pointers.
		std::vector<uint8_t> info(call.pointer_width() == 4 ? 12 : 24);
		info[0] = 1;
		call.write(call[3], info);
		call.ret(1);
	});
	// Display scaling: contexts are the small negative values of the Windows API; there is one display scale, so the setting is only remembered.
	auto dpi_context = std::make_shared<int64_t>(-1);
	registry.add("IsValidDpiAwarenessContext", 1, [](ApiCall &call) {
		const auto value = int64_t(call[0]);
		call.ret(value <= -1 && value >= -5);
	});
	registry.add("SetThreadDpiAwarenessContext", 1, [dpi_context](ApiCall &call) {
		const auto value = call.pointer_width() == 4 ? int64_t(int32_t(call.u32(0))) : int64_t(call[0]);
		if (value > -1 || value < -5) {
			call.ret(0);
			return;
		}
		const auto previous = *dpi_context;
		*dpi_context = value;
		call.ret(uint64_t(previous));
	});
	registry.add("GetThreadDpiAwarenessContext", 0, [dpi_context](ApiCall &call) { call.ret(uint64_t(*dpi_context)); });
	// advapi32 security helpers that need no token or policy database.
	registry.add("AllocateAndInitializeSid", 11, [&context](ApiCall &call) {
		const uint8_t count = uint8_t(call[1]);
		if (count < 1 || count > 8) {
			call.fail(87);
			return;
		}
		std::vector<uint8_t> sid(8 + count * 4);
		sid[0] = 1;
		sid[1] = count;
		const auto authority = call.read(call[0], 6);
		std::memcpy(sid.data() + 2, authority.data(), 6);
		for (uint8_t index = 0; index < count; ++index) {
			const uint32_t part = call.u32(2 + index);
			std::memcpy(sid.data() + 8 + index * 4, &part, 4);
		}
		const auto block = context.allocator.allocate(sid.size(), false);
		if (!block) {
			call.fail(8);
			return;
		}
		call.write(block, sid);
		call.store<uint64_t>(call[10], block);
		call.ret(1);
	});
	registry.add("FreeSid", 1, [&context](ApiCall &call) {
		if (call[0]) context.allocator.release(call[0]);
		call.ret(0);
	});
	registry.add("CheckTokenMembership", 3, [](ApiCall &call) {
		// The groups held are Users (S-1-5-32-545) and Everyone (S-1-1-0); Administrators (S-1-5-32-544) counts only in an elevated
		// process, since without elevation it is held for denying access alone.
		const auto count = call.read(call[1] + 1, 1)[0];
		const auto authority = call.read(call[1] + 2, 6)[5];
		const uint32_t first = count ? call.load<uint32_t>(call[1] + 8) : 0, second = count > 1 ? call.load<uint32_t>(call[1] + 12) : 0;
		const bool users = authority == 5 && count == 2 && first == 32 && second == 545;
		const bool administrators = authority == 5 && count == 2 && first == 32 && second == 544 && process_elevated();
		const bool everyone = authority == 1 && count == 1 && first == 0;
		call.store<uint32_t>(call[2], users || everyone || administrators);
		call.ret(1);
	});
	registry.add("IsTextUnicode", 3, [](ApiCall &call) {
		const size_t size = call.u32(1);
		const auto bytes = call.read(call[0], size);
		uint32_t tests = call[2] ? call.load<uint32_t>(call[2]) : 0xffffffffU;
		uint32_t found = 0;
		const bool even = size % 2 == 0;
		if (even && size >= 2 && (tests & 0x20) && bytes[0] == 0xff && bytes[1] == 0xfe) found |= 0x20;
		if (even && size >= 2 && (tests & 0x40) && bytes[0] == 0xfe && bytes[1] == 0xff) found |= 0x40;
		// Plain text with zero bytes in every second position is UTF-16 in this host's byte order.
		if (even && size >= 4 && (tests & 0x8000)) {
			size_t zeros = 0;
			for (size_t at = 1; at < size; at += 2)
				if (bytes[at] == 0 && bytes[at - 1] != 0)
					++zeros;
			if (zeros * 3 > size / 2 * 2)
				found |= 0x8000;
		}
		if (call[2]) call.store<uint32_t>(call[2], found);
		call.ret(found != 0);
	});

	// CryptoAPI hashing over the digests Raven implements.
	auto crypt = std::make_shared<CryptState>();
	registry.add("CryptAcquireContextW", 5, [crypt](ApiCall &call) {
		const auto handle = crypt->next++;
		crypt->providers[handle] = true;
		call.store<uint64_t>(call[0], handle);
		call.ret(1);
	});
	registry.add("CryptReleaseContext", 2, [crypt](ApiCall &call) {
		crypt->providers.erase(call[0]);
		call.ret(1);
	});
	// advapi32's MD5 keeps its state in the caller's MD5_CTX: the bit count (two words), the four state words, the pending bytes and
	// the digest, at offsets 0, 8, 24 and 88.
	registry.add("MD5Init", 1, [](ApiCall &call) {
		std::vector<uint8_t> context(104);
		const uint32_t initial[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
		std::memcpy(context.data() + 8, initial, 16);
		call.write(call[0], context);
	});
	const auto md5_feed = [](std::vector<uint8_t> &context, std::span<const uint8_t> data) {
		uint64_t bits;
		std::memcpy(&bits, context.data(), 8);
		size_t filled = size_t(bits >> 3) & 63;
		bits += uint64_t(data.size()) * 8;
		std::memcpy(context.data(), &bits, 8);
		std::array<uint32_t, 4> state;
		std::memcpy(state.data(), context.data() + 8, 16);
		for (const auto byte : data) {
			context[24 + filled++] = byte;
			if (filled == 64) {
				md5_block(state, context.data() + 24);
				filled = 0;
			}
		}
		std::memcpy(context.data() + 8, state.data(), 16);
	};
	registry.add("MD5Update", 3, [md5_feed](ApiCall &call) {
		auto context = call.read(call[0], 104);
		md5_feed(context, call.read(call[1], call.u32(2)));
		call.write(call[0], context);
	});
	registry.add("MD5Final", 1, [md5_feed](ApiCall &call) {
		auto context = call.read(call[0], 104);
		uint64_t bits;
		std::memcpy(&bits, context.data(), 8);
		const size_t filled = size_t(bits >> 3) & 63;
		// 0x80, zeros up to 56 bytes into a block, then the bit count before the padding.
		std::vector<uint8_t> padding(filled < 56 ? 56 - filled : 120 - filled);
		padding[0] = 0x80;
		md5_feed(context, padding);
		std::vector<uint8_t> length(8);
		std::memcpy(length.data(), &bits, 8);
		md5_feed(context, length);
		std::memcpy(context.data() + 88, context.data() + 8, 16);
		call.write(call[0], context);
	});
	registry.add("CryptCreateHash", 5, [crypt](ApiCall &call) {
		auto digest = make_digest(call.u32(1));
		if (!crypt->providers.contains(call[0]) || !digest) {
			call.fail(digest ? 0x80090016U : 0x80090008U);
			return;
		}
		const auto handle = crypt->next++;
		crypt->hashes[handle] = std::move(digest);
		call.store<uint64_t>(call[4], handle);
		call.ret(1);
	});
	registry.add("CryptHashData", 4, [crypt](ApiCall &call) {
		const auto found = crypt->hashes.find(call[0]);
		if (found == crypt->hashes.end()) {
			call.fail(6);
			return;
		}
		found->second->update(call.read(call[1], call.u32(2)));
		call.ret(1);
	});
	registry.add("CryptGetHashParam", 5, [crypt](ApiCall &call) {
		const auto found = crypt->hashes.find(call[0]);
		if (found == crypt->hashes.end()) {
			call.fail(6);
			return;
		}
		const uint32_t what = call.u32(1);
		if (what == 4) {
			call.store<uint32_t>(call[2], uint32_t(found->second->size()));
			call.store<uint32_t>(call[3], 4);
			call.ret(1);
			return;
		}
		if (what != 2) {
			call.fail(0x80090008U);
			return;
		}
		auto value = found->second->clone()->finish();
		const uint32_t capacity = call.load<uint32_t>(call[3]);
		call.store<uint32_t>(call[3], uint32_t(value.size()));
		if (!call[2]) {
			call.ret(1);
			return;
		}
		if (capacity < value.size()) {
			call.fail(234);
			return;
		}
		call.write(call[2], value);
		call.ret(1);
	});
	registry.add("CryptDestroyHash", 1, [crypt](ApiCall &call) {
		call.ret(crypt->hashes.erase(call[0]) ? 1 : 0);
	});
}

}
