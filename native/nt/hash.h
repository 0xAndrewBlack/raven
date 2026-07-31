#pragma once

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

// CALG_MD5, CALG_SHA1 and the CALG_SHA_256/384/512 identifiers; null for algorithms Raven does not implement.
std::unique_ptr<Digest> make_digest(uint32_t algorithm);

}
