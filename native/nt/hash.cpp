#include "hash.h"

#include <array>
#include <cstring>

namespace raven {

namespace {

uint32_t rotate_left(uint32_t value, unsigned bits) { return value << bits | value >> (32 - bits); }
uint32_t rotate_right(uint32_t value, unsigned bits) { return value >> bits | value << (32 - bits); }
uint64_t rotate_right64(uint64_t value, unsigned bits) { return value >> bits | value << (64 - bits); }

// Block-buffering base: subclasses consume whole blocks and finish with the Merkle-Damgard padding.
template<size_t Block> class BlockDigest : public Digest {
public:
	void update(std::span<const uint8_t> data) override
	{
		length += data.size();
		for (const auto byte : data) {
			buffer[filled++] = byte;
			if (filled == Block) {
				process(buffer.data());
				filled = 0;
			}
		}
	}

protected:
	virtual void process(const uint8_t *block) = 0;
	// Pads with 0x80, zeros and the bit length in the width and byte order the algorithm defines.
	void pad(bool big_endian, size_t length_bytes)
	{
		const uint64_t bits = length * 8;
		buffer[filled++] = 0x80;
		if (filled > Block - length_bytes) {
			while (filled < Block)
				buffer[filled++] = 0;
			process(buffer.data());
			filled = 0;
		}
		while (filled < Block - length_bytes)
			buffer[filled++] = 0;
		for (size_t index = 0; index < length_bytes; ++index) {
			const size_t from_low = big_endian ? length_bytes - 1 - index : index;
			buffer[filled++] = from_low < 8 ? uint8_t(bits >> (8 * from_low)) : 0;
		}
		process(buffer.data());
		filled = 0;
	}
	std::array<uint8_t, Block> buffer{};
	size_t filled = 0;
	uint64_t length = 0;
};

class Md5 : public BlockDigest<64> {
public:
	size_t size() const override { return 16; }
	std::unique_ptr<Digest> clone() const override { return std::make_unique<Md5>(*this); }
	std::vector<uint8_t> finish() override
	{
		pad(false, 8);
		std::vector<uint8_t> out(16);
		for (size_t index = 0; index < 4; ++index)
			std::memcpy(out.data() + index * 4, &state[index], 4);
		return out;
	}

protected:
	void process(const uint8_t *block) override
	{
		static constexpr uint32_t k[64] = {
			0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1,
			0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453,
			0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942,
			0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
			0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
			0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
		static constexpr unsigned s[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
			4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
		uint32_t words[16];
		std::memcpy(words, block, 64);
		uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
		for (unsigned index = 0; index < 64; ++index) {
			uint32_t f;
			unsigned g;
			if (index < 16) { f = (b & c) | (~b & d); g = index; }
			else if (index < 32) { f = (d & b) | (~d & c); g = (5 * index + 1) % 16; }
			else if (index < 48) { f = b ^ c ^ d; g = (3 * index + 5) % 16; }
			else { f = c ^ (b | ~d); g = (7 * index) % 16; }
			const uint32_t next = d;
			d = c;
			c = b;
			b = b + rotate_left(a + f + k[index] + words[g], s[index]);
			a = next;
		}
		state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	}

private:
	std::array<uint32_t, 4> state{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
};

class Sha1 : public BlockDigest<64> {
public:
	size_t size() const override { return 20; }
	std::unique_ptr<Digest> clone() const override { return std::make_unique<Sha1>(*this); }
	std::vector<uint8_t> finish() override
	{
		pad(true, 8);
		std::vector<uint8_t> out(20);
		for (size_t index = 0; index < 5; ++index)
			for (size_t byte = 0; byte < 4; ++byte)
				out[index * 4 + byte] = uint8_t(state[index] >> (24 - 8 * byte));
		return out;
	}

protected:
	void process(const uint8_t *block) override
	{
		uint32_t w[80];
		for (size_t index = 0; index < 16; ++index)
			w[index] = uint32_t(block[index * 4]) << 24 | uint32_t(block[index * 4 + 1]) << 16 | uint32_t(block[index * 4 + 2]) << 8 | block[index * 4 + 3];
		for (size_t index = 16; index < 80; ++index)
			w[index] = rotate_left(w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16], 1);
		uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
		for (size_t index = 0; index < 80; ++index) {
			uint32_t f, k;
			if (index < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
			else if (index < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
			else if (index < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
			else { f = b ^ c ^ d; k = 0xca62c1d6; }
			const uint32_t next = rotate_left(a, 5) + f + e + k + w[index];
			e = d; d = c; c = rotate_left(b, 30); b = a; a = next;
		}
		state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
	}

private:
	std::array<uint32_t, 5> state{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
};

class Sha256 : public BlockDigest<64> {
public:
	size_t size() const override { return 32; }
	std::unique_ptr<Digest> clone() const override { return std::make_unique<Sha256>(*this); }
	std::vector<uint8_t> finish() override
	{
		pad(true, 8);
		std::vector<uint8_t> out(32);
		for (size_t index = 0; index < 8; ++index)
			for (size_t byte = 0; byte < 4; ++byte)
				out[index * 4 + byte] = uint8_t(state[index] >> (24 - 8 * byte));
		return out;
	}

protected:
	void process(const uint8_t *block) override
	{
		static constexpr uint32_t k[64] = {
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
			0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
			0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
			0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
			0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
			0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
		uint32_t w[64];
		for (size_t index = 0; index < 16; ++index)
			w[index] = uint32_t(block[index * 4]) << 24 | uint32_t(block[index * 4 + 1]) << 16 | uint32_t(block[index * 4 + 2]) << 8 | block[index * 4 + 3];
		for (size_t index = 16; index < 64; ++index) {
			const uint32_t s0 = rotate_right(w[index - 15], 7) ^ rotate_right(w[index - 15], 18) ^ (w[index - 15] >> 3);
			const uint32_t s1 = rotate_right(w[index - 2], 17) ^ rotate_right(w[index - 2], 19) ^ (w[index - 2] >> 10);
			w[index] = w[index - 16] + s0 + w[index - 7] + s1;
		}
		auto h = state;
		for (size_t index = 0; index < 64; ++index) {
			const uint32_t s1 = rotate_right(h[4], 6) ^ rotate_right(h[4], 11) ^ rotate_right(h[4], 25);
			const uint32_t choice = (h[4] & h[5]) ^ (~h[4] & h[6]);
			const uint32_t first = h[7] + s1 + choice + k[index] + w[index];
			const uint32_t s0 = rotate_right(h[0], 2) ^ rotate_right(h[0], 13) ^ rotate_right(h[0], 22);
			const uint32_t majority = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
			const uint32_t second = s0 + majority;
			h[7] = h[6]; h[6] = h[5]; h[5] = h[4]; h[4] = h[3] + first; h[3] = h[2]; h[2] = h[1]; h[1] = h[0]; h[0] = first + second;
		}
		for (size_t index = 0; index < 8; ++index)
			state[index] += h[index];
	}

private:
	std::array<uint32_t, 8> state{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
};

class Sha512 : public BlockDigest<128> {
public:
	explicit Sha512(bool truncated = false) : truncated(truncated)
	{
		if (truncated)
			state = {0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
				0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};
	}
	size_t size() const override { return truncated ? 48 : 64; }
	std::unique_ptr<Digest> clone() const override { return std::make_unique<Sha512>(*this); }
	std::vector<uint8_t> finish() override
	{
		pad(true, 16);
		std::vector<uint8_t> out(64);
		for (size_t index = 0; index < 8; ++index)
			for (size_t byte = 0; byte < 8; ++byte)
				out[index * 8 + byte] = uint8_t(state[index] >> (56 - 8 * byte));
		out.resize(size());
		return out;
	}

protected:
	void process(const uint8_t *block) override
	{
		static constexpr uint64_t k[80] = {
			0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
			0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
			0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
			0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
			0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
			0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
			0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
			0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
			0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
			0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
			0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
			0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
			0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
			0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};
		uint64_t w[80];
		for (size_t index = 0; index < 16; ++index) {
			w[index] = 0;
			for (size_t byte = 0; byte < 8; ++byte)
				w[index] = w[index] << 8 | block[index * 8 + byte];
		}
		for (size_t index = 16; index < 80; ++index) {
			const uint64_t s0 = rotate_right64(w[index - 15], 1) ^ rotate_right64(w[index - 15], 8) ^ (w[index - 15] >> 7);
			const uint64_t s1 = rotate_right64(w[index - 2], 19) ^ rotate_right64(w[index - 2], 61) ^ (w[index - 2] >> 6);
			w[index] = w[index - 16] + s0 + w[index - 7] + s1;
		}
		auto h = state;
		for (size_t index = 0; index < 80; ++index) {
			const uint64_t s1 = rotate_right64(h[4], 14) ^ rotate_right64(h[4], 18) ^ rotate_right64(h[4], 41);
			const uint64_t choice = (h[4] & h[5]) ^ (~h[4] & h[6]);
			const uint64_t first = h[7] + s1 + choice + k[index] + w[index];
			const uint64_t s0 = rotate_right64(h[0], 28) ^ rotate_right64(h[0], 34) ^ rotate_right64(h[0], 39);
			const uint64_t majority = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
			const uint64_t second = s0 + majority;
			h[7] = h[6]; h[6] = h[5]; h[5] = h[4]; h[4] = h[3] + first; h[3] = h[2]; h[2] = h[1]; h[1] = h[0]; h[0] = first + second;
		}
		for (size_t index = 0; index < 8; ++index)
			state[index] += h[index];
	}

private:
	bool truncated;
	std::array<uint64_t, 8> state{0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
		0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
};

}

std::unique_ptr<Digest> make_digest(uint32_t algorithm)
{
	switch (algorithm) {
	case 0x8003: return std::make_unique<Md5>();
	case 0x8004: return std::make_unique<Sha1>();
	case 0x800c: return std::make_unique<Sha256>();
	case 0x800d: return std::make_unique<Sha512>(true);
	case 0x800e: return std::make_unique<Sha512>();
	default: return nullptr;
	}
}

}
