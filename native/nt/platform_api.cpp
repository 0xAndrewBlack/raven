#include <cstdio>
#include "hash.h"
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

struct ComState {
	std::map<uint64_t, int> initialized;
};

}

void register_platform_api(ApiRegistry &registry, KernelContext &context)
{
	// uxtheme: visual styles are not provided, so every themed drawing path reports "no theme" and apps use classic drawing.
	registry.add("IsThemeActive", 0, [](ApiCall &call) { call.ret(0); });
	registry.add("IsAppThemed", 0, [](ApiCall &call) { call.ret(0); });
	registry.add("OpenThemeData", 2, [](ApiCall &call) { call.fail(e_handle, 0); });
	registry.add("OpenThemeDataEx", 3, [](ApiCall &call) { call.fail(e_handle, 0); });
	registry.add("CloseThemeData", 1, [](ApiCall &call) { call.ret(call[0] ? e_handle : s_ok); });
	registry.add("SetWindowTheme", 3, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("EnableThemeDialogTexture", 2, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("EnableTheming", 1, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("GetThemeAppProperties", 0, [](ApiCall &call) { call.ret(0); });
	registry.add("IsThemeBackgroundPartiallyTransparent", 3, [](ApiCall &call) { call.ret(0); });
	registry.add("DrawThemeBackground", 6, [](ApiCall &call) { call.ret(e_handle); });
	registry.add("DrawThemeBackgroundEx", 6, [](ApiCall &call) { call.ret(e_handle); });
	registry.add("DrawThemeParentBackground", 3, [](ApiCall &call) { call.ret(e_fail); });
	registry.add("DrawThemeText", 9, [](ApiCall &call) { call.ret(e_handle); });
	registry.add("DrawThemeTextEx", 9, [](ApiCall &call) { call.ret(e_handle); });
	registry.add("GetThemeBackgroundContentRect", 6, [](ApiCall &call) { call.ret(e_handle); });
	registry.add("GetThemePartSize", 7, [](ApiCall &call) { call.ret(e_handle); });
	registry.add("GetThemeFont", 6, [](ApiCall &call) { call.ret(e_handle); });
	registry.add("GetThemeColor", 5, [](ApiCall &call) { call.ret(e_handle); });
	registry.add("GetThemeMetric", 6, [](ApiCall &call) { call.ret(e_handle); });
	registry.add("GetThemeInt", 5, [](ApiCall &call) { call.ret(e_handle); });
	registry.add("GetThemeTransitionDuration", 6, [](ApiCall &call) { call.ret(e_handle); });
	registry.add("BufferedPaintInit", 0, [](ApiCall &call) { call.ret(s_ok); });
	registry.add("BufferedPaintUnInit", 0, [](ApiCall &call) { call.ret(s_ok); });
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
	registry.add("CoInitialize", 1, [com, &context](ApiCall &call) {
		auto &count = com->initialized[context.environment.teb()];
		call.ret(count++ ? s_false : s_ok);
	});
	registry.add("CoInitializeEx", 2, [com, &context](ApiCall &call) {
		auto &count = com->initialized[context.environment.teb()];
		call.ret(count++ ? s_false : s_ok);
	});
	registry.add("OleInitialize", 1, [com, &context](ApiCall &call) {
		auto &count = com->initialized[context.environment.teb()];
		call.ret(count++ ? s_false : s_ok);
	});
	const auto uninitialize = [com, &context](ApiCall &) {
		auto &count = com->initialized[context.environment.teb()];
		if (count > 0)
			--count;
	};
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
	registry.add("CLSIDFromString", 2, [](ApiCall &call) { call.ret(class_string); });
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
	registry.add("SystemFunction036", 2, [random_bytes](ApiCall &call) {
		if (!call[0]) {
			call.fail(87);
			return;
		}
		call.ret(random_bytes(call, call[0], call.u32(1)));
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
		// Membership in the local Administrators group follows the host account; every other group is not held.
		const auto count = call.read(call[1] + 1, 1)[0];
		const auto authority = call.read(call[1] + 2, 6);
		const bool nt_authority = authority[5] == 5;
		uint32_t first = count ? call.load<uint32_t>(call[1] + 8) : 0, second = count > 1 ? call.load<uint32_t>(call[1] + 12) : 0;
		const bool administrators = nt_authority && count == 2 && first == 32 && second == 544;
		call.store<uint32_t>(call[2], administrators && ::geteuid() == 0);
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
