#include "kernel_context.h"

#ifdef RAVEN_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#endif

#include "prefix.h"

#include <array>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <unistd.h>

namespace raven {

#ifdef RAVEN_OPENSSL

namespace {

constexpr uint32_t error_asn1_bad_tag = 0x8009310b, trust_not_time_valid = 0x1, trust_not_signature_valid = 0x8, trust_revoked = 0x4,
	trust_untrusted_root = 0x20, trust_partial_chain = 0x10000, trust_self_signed = 0x8;
constexpr uint32_t store_provider_memory = 2, store_provider_system_a = 9, store_provider_system_w = 10;

constexpr uint32_t error_invalid_data = 13, error_invalid_parameter = 87;
// A protected blob: the magic, the length of the description in bytes, the description as UTF-16, the IV, the tag and the ciphertext.
constexpr char protected_magic[4] = {'R', 'V', 'D', 'P'};

// The secret behind CryptProtectData lives in the prefix, so blobs open again in later runs of the same prefix and nowhere else.
std::array<uint8_t, 32> protection_secret()
{
	static std::mutex lock;
	std::lock_guard guard(lock);
	const auto path = NativePrefix::from_environment().root() / "dpapi.key";
	std::array<uint8_t, 32> secret{};
	{
		std::ifstream input(path, std::ios::binary);
		if (input.read(reinterpret_cast<char *>(secret.data()), secret.size()) && size_t(input.gcount()) == secret.size())
			return secret;
	}
	RAND_bytes(secret.data(), int(secret.size()));
	const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (descriptor >= 0) {
		const auto written = ::write(descriptor, secret.data(), secret.size());
		::close(descriptor);
		(void)written;
	} else if (std::ifstream input(path, std::ios::binary); input.read(reinterpret_cast<char *>(secret.data()), secret.size())) {
		// Another process of the prefix made the key first.
	}
	return secret;
}

std::array<uint8_t, 32> protection_key(std::span<const uint8_t> entropy)
{
	const auto secret = protection_secret();
	std::array<uint8_t, 32> key{};
	unsigned int length = 0;
	HMAC(EVP_sha256(), secret.data(), int(secret.size()), entropy.data(), entropy.size(), key.data(), &length);
	return key;
}

using X509Pointer = std::unique_ptr<X509, decltype(&X509_free)>;

// A certificate store: the encoded certificates it holds, in the order they were added.
class CertificateStore : public KernelObject {
public:
	std::vector<std::vector<uint8_t>> certificates;
};

// Lays a structure out in the guest's memory with the natural alignment of its fields: pointers are as wide as the program's.
class Layout {
public:
	explicit Layout(size_t width) : width(width) {}
	size_t reserve(size_t size, size_t alignment)
	{
		offset = (offset + alignment - 1) / alignment * alignment;
		const auto at = offset;
		offset += size;
		return at;
	}
	size_t dword() { return reserve(4, 4); }
	size_t pointer() { return reserve(width, width); }
	size_t size() const { return (offset + width - 1) / width * width; }
	const size_t width;

private:
	size_t offset = 0;
};

std::vector<uint8_t> der_of(X509 *certificate)
{
	const int length = i2d_X509(certificate, nullptr);
	std::vector<uint8_t> bytes(length > 0 ? size_t(length) : 0);
	unsigned char *at = bytes.data();
	if (length > 0)
		i2d_X509(certificate, &at);
	return bytes;
}

X509Pointer parse(std::span<const uint8_t> bytes)
{
	const unsigned char *at = bytes.data();
	return X509Pointer(d2i_X509(nullptr, &at, long(bytes.size())), X509_free);
}

// The trust anchors: the certificate bundle of the host, read once.
X509_STORE *system_roots()
{
	static X509_STORE *store = [] {
		auto *created = X509_STORE_new();
		if (created)
			for (const char *path : {"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"})
				if (X509_STORE_load_file(created, path))
					break;
		return created;
	}();
	return store;
}

uint64_t filetime_of(const ASN1_TIME *time)
{
	if (!time)
		return 0;
	int days = 0, seconds = 0;
	ASN1_TIME epoch;
	std::memset(&epoch, 0, sizeof(epoch));
	ASN1_TIME *unix_epoch = ASN1_TIME_set(nullptr, 0);
	if (!unix_epoch || !ASN1_TIME_diff(&days, &seconds, unix_epoch, time)) {
		ASN1_STRING_free(unix_epoch);
		return 0;
	}
	ASN1_STRING_free(unix_epoch);
	const int64_t unix_seconds = int64_t(days) * 86400 + seconds;
	return uint64_t(unix_seconds + 11644473600LL) * 10000000ULL;
}

uint32_t trust_of(int error)
{
	switch (error) {
	case X509_V_OK: return 0;
	case X509_V_ERR_CERT_HAS_EXPIRED: case X509_V_ERR_CERT_NOT_YET_VALID: return trust_not_time_valid;
	case X509_V_ERR_CERT_SIGNATURE_FAILURE: return trust_not_signature_valid;
	case X509_V_ERR_CERT_REVOKED: return trust_revoked;
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
		return trust_partial_chain;
	default: return trust_untrusted_root;
	}
}

}

void register_crypt32_api(ApiRegistry &registry, KernelContext &context)
{
	auto &objects = context.objects;
	auto &allocator = context.allocator;
	// A certificate context in the guest points at its encoded bytes and at a CERT_INFO with the fields programs read most.
	const auto make_context = [&allocator](ApiCall &call, const std::vector<uint8_t> &encoded, uint64_t store) -> uint64_t {
		const auto certificate = parse(encoded);
		if (!certificate)
			return 0;
		const size_t width = call.pointer_width();
		Layout info(width);
		const auto version_at = info.dword();
		const auto serial_size = info.dword(), serial_data = info.pointer();
		const auto algorithm_name = info.pointer(), parameters_size = info.dword(), parameters_data = info.pointer();
		const auto issuer_size = info.dword(), issuer_data = info.pointer();
		const auto not_before = info.reserve(8, 4), not_after = info.reserve(8, 4);
		const auto subject_size = info.dword(), subject_data = info.pointer();
		const auto key_algorithm_name = info.pointer(), key_parameters_size = info.dword(), key_parameters_data = info.pointer();
		const auto key_size = info.dword(), key_data = info.pointer(), key_unused = info.dword();
		const auto issuer_unique = info.reserve(width == 4 ? 12 : 24, width), subject_unique = info.reserve(width == 4 ? 12 : 24, width);
		const auto extension_count = info.dword(), extension_data = info.pointer();
		Layout head(width);
		const auto encoding_at = head.dword(), encoded_at = head.pointer(), encoded_size_at = head.dword(), info_at = head.pointer(), store_at = head.pointer();
		const auto *name = X509_get_serialNumber(certificate.get());
		std::vector<uint8_t> serial(name ? size_t(name->length) : 0);
		if (name)
			std::memcpy(serial.data(), name->data, serial.size());
		const auto name_bytes = [](X509_NAME *value) {
			const int length = i2d_X509_NAME(value, nullptr);
			std::vector<uint8_t> bytes(length > 0 ? size_t(length) : 0);
			unsigned char *at = bytes.data();
			if (length > 0)
				i2d_X509_NAME(value, &at);
			return bytes;
		};
		const auto issuer = name_bytes(X509_get_issuer_name(certificate.get())), subject = name_bytes(X509_get_subject_name(certificate.get()));
		// One block: the context, the CERT_INFO, then the byte strings they point at.
		const size_t info_start = (head.size() + 15) / 16 * 16, bytes_start = (info_start + info.size() + 15) / 16 * 16;
		const size_t total = bytes_start + encoded.size() + serial.size() + issuer.size() + subject.size() + 64;
		const auto block = allocator.allocate(total, true);
		if (!block)
			return 0;
		std::vector<uint8_t> image(total);
		const auto put32 = [&](size_t at, uint32_t value) { std::memcpy(image.data() + at, &value, 4); };
		const auto put_pointer = [&](size_t at, uint64_t value) { std::memcpy(image.data() + at, &value, width); };
		size_t cursor = bytes_start;
		const auto place = [&](const std::vector<uint8_t> &bytes) {
			const auto address = block + cursor;
			std::memcpy(image.data() + cursor, bytes.data(), bytes.size());
			cursor += bytes.size();
			return address;
		};
		put32(encoding_at, 0x10001);
		put_pointer(encoded_at, place(encoded));
		put32(encoded_size_at, uint32_t(encoded.size()));
		put_pointer(info_at, block + info_start);
		put_pointer(store_at, store);
		put32(info_start + version_at, uint32_t(X509_get_version(certificate.get())));
		put32(info_start + serial_size, uint32_t(serial.size()));
		put_pointer(info_start + serial_data, place(serial));
		put32(info_start + issuer_size, uint32_t(issuer.size()));
		put_pointer(info_start + issuer_data, place(issuer));
		put32(info_start + subject_size, uint32_t(subject.size()));
		put_pointer(info_start + subject_data, place(subject));
		const auto before = filetime_of(X509_get0_notBefore(certificate.get())), after = filetime_of(X509_get0_notAfter(certificate.get()));
		std::memcpy(image.data() + info_start + not_before, &before, 8);
		std::memcpy(image.data() + info_start + not_after, &after, 8);
		(void)algorithm_name; (void)parameters_size; (void)parameters_data; (void)key_algorithm_name; (void)key_parameters_size;
		(void)key_parameters_data; (void)key_size; (void)key_data; (void)key_unused; (void)issuer_unique; (void)subject_unique;
		(void)extension_count; (void)extension_data;
		call.write(block, image);
		return block;
	};
	// Encoded bytes of a context the guest holds.
	const auto encoded_of = [](ApiCall &call, uint64_t certificate) {
		const size_t width = call.pointer_width();
		const auto bytes = call.load_pointer(certificate + (width == 4 ? 4 : 8));
		const auto size = call.load<uint32_t>(certificate + (width == 4 ? 8 : 16));
		return call.read(bytes, size);
	};

	registry.add("CertOpenStore", 5, [&objects](ApiCall &call) {
		const uint64_t provider = call[0];
		auto store = std::make_shared<CertificateStore>();
		if (provider == store_provider_system_w || provider == store_provider_system_a) {
			// The root store is the host's bundle; every other system store starts empty.
			const auto name = provider == store_provider_system_w ? call.wide(call[4], 64) : [&] {
				const auto narrow = call.narrow(call[4], 64);
				return std::u16string(narrow.begin(), narrow.end());
			}();
			if (name == u"ROOT" || name == u"root") {
				if (auto *roots = system_roots()) {
					const auto *objects_list = X509_STORE_get0_objects(roots);
					for (int index = 0; objects_list && index < sk_X509_OBJECT_num(objects_list); ++index)
						if (auto *certificate = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objects_list, index)))
							store->certificates.push_back(der_of(certificate));
				}
			}
		} else if (provider != store_provider_memory) {
			call.fail(0x80092009U, 0);
			return;
		}
		const auto made = objects.add_object(store);
		if (made.status) {
			call.fail(8, 0);
			return;
		}
		call.ret(made.value);
	});
	registry.add("CertCloseStore", 2, [&objects](ApiCall &call) {
		if (!objects.object_as<CertificateStore>(call[0])) {
			call.fail(6);
			return;
		}
		objects.close(call[0]);
		call.ret(1);
	});
	registry.add("CertCreateCertificateContext", 3, [make_context](ApiCall &call) {
		if (!call[1] || !call.u32(2)) {
			call.fail(87, 0);
			return;
		}
		const auto encoded = call.read(call[1], call.u32(2));
		const auto made = make_context(call, encoded, 0);
		if (!made) {
			call.fail(error_asn1_bad_tag, 0);
			return;
		}
		call.ret(made);
	});
	registry.add("CertAddEncodedCertificateToStore", 6, [&objects, make_context](ApiCall &call) {
		const auto store = objects.object_as<CertificateStore>(call[0]);
		if (!store || !call[2]) {
			call.fail(store ? 87 : 6);
			return;
		}
		const auto encoded = call.read(call[2], call.u32(3));
		if (!parse(encoded)) {
			call.fail(error_asn1_bad_tag);
			return;
		}
		store->certificates.push_back(encoded);
		if (call[5]) {
			const auto made = make_context(call, encoded, call[0]);
			call.store_pointer(call[5], made);
		}
		call.ret(1);
	});
	registry.add("CertAddCertificateContextToStore", 4, [&objects, encoded_of, make_context](ApiCall &call) {
		const auto store = objects.object_as<CertificateStore>(call[0]);
		if (!store || !call[1]) {
			call.fail(store ? 87 : 6);
			return;
		}
		const auto encoded = encoded_of(call, call[1]);
		store->certificates.push_back(encoded);
		if (call[3]) {
			const auto made = make_context(call, encoded, call[0]);
			call.store_pointer(call[3], made);
		}
		call.ret(1);
	});
	registry.add("CertDuplicateCertificateContext", 1, [encoded_of, make_context](ApiCall &call) {
		if (!call[0]) {
			call.ret(0);
			return;
		}
		call.ret(make_context(call, encoded_of(call, call[0]), 0));
	});
	registry.add("CertFreeCertificateContext", 1, [&allocator](ApiCall &call) {
		if (call[0])
			allocator.release(call[0]);
		call.ret(1);
	});
	registry.add("CertEnumCertificatesInStore", 2, [&objects, &allocator, make_context](ApiCall &call) {
		const auto store = objects.object_as<CertificateStore>(call[0]);
		if (!store) {
			call.fail(6, 0);
			return;
		}
		// The previous context says where the walk stands: it names the store and the certificate it was made from.
		size_t next = 0;
		if (call[1]) {
			const size_t width = call.pointer_width();
			const auto size = call.load<uint32_t>(call[1] + (width == 4 ? 8 : 16));
			const auto bytes = call.read(call.load_pointer(call[1] + (width == 4 ? 4 : 8)), size);
			for (size_t index = 0; index < store->certificates.size(); ++index)
				if (store->certificates[index] == bytes) {
					next = index + 1;
					break;
				}
			allocator.release(call[1]);
		}
		if (next >= store->certificates.size()) {
			call.fail(0x80092004U, 0);
			return;
		}
		call.ret(make_context(call, store->certificates[next], call[0]));
	});
	registry.add("CertFreeCertificateChain", 1, [&allocator](ApiCall &call) {
		if (call[0])
			allocator.release(call[0]);
	});
	// The chain is built with the host's X.509 verifier against the host's trust anchors; the guest receives the Windows structures:
	// CERT_CHAIN_CONTEXT, one CERT_SIMPLE_CHAIN and a CERT_CHAIN_ELEMENT for each certificate.
	registry.add("CertGetCertificateChain", 8, [&objects, &allocator, encoded_of, make_context](ApiCall &call) {
		if (!call[1] || !call[7]) {
			call.fail(87);
			return;
		}
		const auto leaf = parse(encoded_of(call, call[1]));
		if (!leaf) {
			call.fail(error_asn1_bad_tag);
			return;
		}
		X509_STORE_CTX *verify = X509_STORE_CTX_new();
		STACK_OF(X509) *untrusted = sk_X509_new_null();
		if (!verify || !untrusted || !system_roots()) {
			if (verify)
				X509_STORE_CTX_free(verify);
			if (untrusted)
				sk_X509_free(untrusted);
			call.fail(8);
			return;
		}
		std::vector<X509Pointer> held;
		if (const auto extra = objects.object_as<CertificateStore>(call[3]))
			for (const auto &encoded : extra->certificates)
				if (auto parsed = parse(encoded)) {
					sk_X509_push(untrusted, parsed.get());
					held.push_back(std::move(parsed));
				}
		X509_STORE_CTX_init(verify, system_roots(), leaf.get(), untrusted);
		X509_STORE_CTX_set_flags(verify, X509_V_FLAG_TRUSTED_FIRST);
		const uint64_t now = uint64_t(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
		uint64_t at = now;
		if (call[2]) {
			const auto ticks = call.load<uint64_t>(call[2]);
			if (ticks > 11644473600ULL * 10000000ULL)
				at = ticks / 10000000ULL - 11644473600ULL;
		}
		X509_VERIFY_PARAM_set_time(X509_STORE_CTX_get0_param(verify), time_t(at));
		const int accepted = X509_verify_cert(verify);
		const int error = accepted > 0 ? X509_V_OK : X509_STORE_CTX_get_error(verify);
		STACK_OF(X509) *built = X509_STORE_CTX_get0_chain(verify);
		std::vector<std::vector<uint8_t>> chain;
		for (int index = 0; built && index < sk_X509_num(built); ++index)
			chain.push_back(der_of(sk_X509_value(built, index)));
		if (chain.empty())
			chain.push_back(der_of(leaf.get()));
		const bool anchored = accepted > 0;
		X509_STORE_CTX_free(verify);
		sk_X509_free(untrusted);
		const uint32_t status = trust_of(error);
		// Layouts of the three structures.
		const size_t width = call.pointer_width();
		Layout context_layout(width), simple_layout(width), element_layout(width);
		const auto context_size = context_layout.dword(), context_error = context_layout.dword(), context_info = context_layout.dword(),
			context_chains = context_layout.dword(), context_array = context_layout.pointer(), context_lower = context_layout.dword(),
			context_lower_array = context_layout.pointer(), context_fresh = context_layout.dword(), context_fresh_time = context_layout.dword();
		const auto simple_size = simple_layout.dword(), simple_error = simple_layout.dword(), simple_info = simple_layout.dword(),
			simple_count = simple_layout.dword(), simple_array = simple_layout.pointer(), simple_list = simple_layout.pointer(),
			simple_fresh = simple_layout.dword(), simple_fresh_time = simple_layout.dword();
		const auto element_size = element_layout.dword(), element_context = element_layout.pointer(), element_error = element_layout.dword(),
			element_info = element_layout.dword(), element_revocation = element_layout.pointer(), element_issuance = element_layout.pointer(),
			element_application = element_layout.pointer(), element_message = element_layout.pointer();
		const size_t chain_pointers = chain.size() * width, elements_size = chain.size() * element_layout.size();
		size_t total = context_layout.size() + width + simple_layout.size() + chain_pointers + elements_size + 64;
		const auto block = allocator.allocate(total, true);
		if (!block) {
			call.fail(8);
			return;
		}
		std::vector<uint8_t> image(total);
		const auto put32 = [&](size_t at, uint32_t value) { std::memcpy(image.data() + at, &value, 4); };
		const auto put_pointer = [&](size_t at, uint64_t value) { std::memcpy(image.data() + at, &value, width); };
		const size_t context_at = 0, array_at = (context_layout.size() + 15) / 16 * 16, simple_at = array_at + 16,
			pointers_at = (simple_at + simple_layout.size() + 15) / 16 * 16, elements_at = pointers_at + (chain_pointers + 15) / 16 * 16;
		put32(context_at + context_size, uint32_t(context_layout.size()));
		put32(context_at + context_error, status);
		put32(context_at + context_info, 0);
		put32(context_at + context_chains, 1);
		put_pointer(context_at + context_array, block + array_at);
		put32(context_at + context_lower, 0);
		put_pointer(context_at + context_lower_array, 0);
		put32(context_at + context_fresh, 0);
		put32(context_at + context_fresh_time, 0);
		put_pointer(array_at, block + simple_at);
		put32(simple_at + simple_size, uint32_t(simple_layout.size()));
		put32(simple_at + simple_error, status);
		put32(simple_at + simple_info, 0);
		put32(simple_at + simple_count, uint32_t(chain.size()));
		put_pointer(simple_at + simple_array, block + pointers_at);
		put_pointer(simple_at + simple_list, 0);
		put32(simple_at + simple_fresh, 0);
		put32(simple_at + simple_fresh_time, 0);
		// The element contexts are separate allocations, which the guest releases through CertFreeCertificateContext.
		for (size_t index = 0; index < chain.size(); ++index) {
			const auto element = elements_at + index * element_layout.size();
			put_pointer(pointers_at + index * width, block + element);
			put32(element + element_size, uint32_t(element_layout.size()));
			put_pointer(element + element_context, make_context(call, chain[index], 0));
			const bool last = index + 1 == chain.size();
			put32(element + element_error, last ? status : 0);
			put32(element + element_info, last && anchored ? trust_self_signed : 0);
			(void)element_revocation; (void)element_issuance; (void)element_application; (void)element_message;
		}
		call.write(block, image);
		call.store_pointer(call[7], block);
		call.ret(1);
		(void)total;
	});

	// Data protection: the blob is sealed with AES-256-GCM under a key made from the prefix secret and the optional entropy.
	const auto blob_in = [](ApiCall &call, uint64_t blob) {
		const size_t width = call.pointer_width();
		if (!blob)
			return std::optional<std::vector<uint8_t>>();
		const auto size = call.load<uint32_t>(blob);
		const uint64_t data = width == 4 ? call.load<uint32_t>(blob + 4) : call.load<uint64_t>(blob + 8);
		if (!size)
			return std::optional(std::vector<uint8_t>());
		if (!data)
			return std::optional<std::vector<uint8_t>>();
		return std::optional(call.read(data, size));
	};
	const auto blob_out = [&context](ApiCall &call, uint64_t blob, std::span<const uint8_t> bytes) {
		const size_t width = call.pointer_width();
		const auto memory = context.allocator.allocate(std::max<size_t>(bytes.size(), 1), true);
		if (!memory)
			return false;
		if (!bytes.empty())
			call.write(memory, bytes);
		call.store<uint32_t>(blob, uint32_t(bytes.size()));
		if (width == 4)
			call.store<uint32_t>(blob + 4, uint32_t(memory));
		else
			call.store<uint64_t>(blob + 8, memory);
		return true;
	};
	// No key storage provider is installed here, so key creation and use fail the way they do on a machine without one; programs fall back.
	for (const auto &[name, count] : {std::pair<const char *, size_t>{"NCryptOpenStorageProvider", 3}, {"NCryptIsAlgSupported", 3},
		{"NCryptCreatePersistedKey", 6}, {"NCryptFinalizeKey", 2}, {"NCryptExportKey", 8}, {"NCryptOpenKey", 5}, {"NCryptSignHash", 8},
		{"NCryptGetProperty", 6}, {"NCryptSetProperty", 5}, {"NCryptDeleteKey", 2}, {"NCryptEnumKeys", 5}})
		registry.add(name, count, [](ApiCall &call) { call.ret(0x80090029U); });
	registry.add("NCryptFreeObject", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("CryptProtectData", 7, [blob_in, blob_out](ApiCall &call) {
		const auto plain = blob_in(call, call[0]);
		if (!plain || !call[6]) {
			call.fail(error_invalid_parameter, 0);
			return;
		}
		const auto entropy = blob_in(call, call[2]).value_or(std::vector<uint8_t>());
		const auto description = call[1] ? call.wide(call[1]) : std::u16string();
		const auto key = protection_key(entropy);
		uint8_t iv[12], tag[16];
		RAND_bytes(iv, sizeof(iv));
		std::vector<uint8_t> sealed(plain->size());
		int length = 0, total = 0;
		std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
		if (!EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, key.data(), iv) ||
			(!plain->empty() && !EVP_EncryptUpdate(context.get(), sealed.data(), &length, plain->data(), int(plain->size()))) ||
			!EVP_EncryptFinal_ex(context.get(), sealed.data() + length, &total) || !EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag)) {
			call.fail(error_invalid_data, 0);
			return;
		}
		std::vector<uint8_t> blob(protected_magic, protected_magic + 4);
		const uint32_t description_bytes = uint32_t(description.size() * 2);
		blob.insert(blob.end(), reinterpret_cast<const uint8_t *>(&description_bytes), reinterpret_cast<const uint8_t *>(&description_bytes) + 4);
		blob.insert(blob.end(), reinterpret_cast<const uint8_t *>(description.data()), reinterpret_cast<const uint8_t *>(description.data()) + description_bytes);
		blob.insert(blob.end(), iv, iv + sizeof(iv));
		blob.insert(blob.end(), tag, tag + sizeof(tag));
		blob.insert(blob.end(), sealed.begin(), sealed.end());
		if (!blob_out(call, call[6], blob)) {
			call.fail(8, 0);
			return;
		}
		call.ret(1);
	});
	registry.add("CryptUnprotectData", 7, [blob_in, blob_out, &context](ApiCall &call) {
		const auto blob = blob_in(call, call[0]);
		if (!blob || !call[6]) {
			call.fail(error_invalid_parameter, 0);
			return;
		}
		if (blob->size() < 4 + 4 + 12 + 16 || std::memcmp(blob->data(), protected_magic, 4)) {
			call.fail(error_invalid_data, 0);
			return;
		}
		uint32_t description_bytes;
		std::memcpy(&description_bytes, blob->data() + 4, 4);
		if (description_bytes % 2 || size_t(8) + description_bytes + 28 > blob->size()) {
			call.fail(error_invalid_data, 0);
			return;
		}
		const uint8_t *iv = blob->data() + 8 + description_bytes, *tag = iv + 12, *cipher = tag + 16;
		const size_t cipher_size = blob->size() - (8 + description_bytes + 28);
		const auto entropy = blob_in(call, call[2]).value_or(std::vector<uint8_t>());
		const auto key = protection_key(entropy);
		std::vector<uint8_t> plain(cipher_size);
		int length = 0, total = 0;
		std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipher_context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
		if (!EVP_DecryptInit_ex(cipher_context.get(), EVP_aes_256_gcm(), nullptr, key.data(), iv) ||
			(cipher_size && !EVP_DecryptUpdate(cipher_context.get(), plain.data(), &length, cipher, int(cipher_size))) ||
			!EVP_CIPHER_CTX_ctrl(cipher_context.get(), EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t *>(tag)) ||
			EVP_DecryptFinal_ex(cipher_context.get(), plain.data() + length, &total) <= 0) {
			// Wrong entropy or a changed blob.
			call.fail(error_invalid_data, 0);
			return;
		}
		if (call[1]) {
			std::u16string description(description_bytes / 2, u'\0');
			std::memcpy(description.data(), blob->data() + 8, description_bytes);
			const auto memory = context.allocator.allocate(description_bytes + 2, true);
			if (!memory) {
				call.fail(8, 0);
				return;
			}
			call.put_wide(memory, description, description.size() + 1);
			call.store_pointer(call[1], memory);
		}
		if (!blob_out(call, call[6], plain)) {
			call.fail(8, 0);
			return;
		}
		call.ret(1);
	});
}

#else

void register_crypt32_api(ApiRegistry &, KernelContext &)
{
}

#endif

}
