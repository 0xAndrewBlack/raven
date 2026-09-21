#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace raven {

// Incremental message digests for the CryptoAPI hash objects.
class Digest {
public:
	virtual ~Digest() = default;
	virtual void update(std::span<const uint8_t> data) = 0;
	virtual std::vector<uint8_t> finish() = 0;
	virtual std::unique_ptr<Digest> clone() const = 0;
	virtual size_t size() const = 0;
};

// One 64-byte block of MD5 folded into the four state words, for callers that keep the state themselves (advapi32's MD5_CTX).
void md5_block(std::array<uint32_t, 4> &state, const uint8_t *block);

// CALG_MD5, CALG_SHA1 and the CALG_SHA_256/384/512 identifiers; null for algorithms Raven does not implement.
std::unique_ptr<Digest> make_digest(uint32_t algorithm);

}
