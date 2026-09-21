#include "authenticode.h"

#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>

// Every file named must carry a trusted Authenticode signature, and a copy of the first with one byte of its content changed must not.
int main(int argc, char **argv)
{
	if (argc < 2) {
		std::fprintf(stderr, "usage: authenticode_test SIGNED_FILE...\n");
		return 2;
	}
	std::vector<uint8_t> first;
	for (int index = 1; index < argc; ++index) {
		std::ifstream input(argv[index], std::ios::binary);
		const std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
		const auto result = raven::verify_authenticode(bytes);
		std::printf("%s: status %08x, %zu certificates, %s\n", argv[index], result.status, result.chain.size(), result.anchored ? "anchored" : "not anchored");
		if (result.status || !result.anchored)
			return 1;
		if (index == 1)
			first = bytes;
	}
	// A byte in the middle of the file: content the digest covers.
	first[first.size() / 2] ^= 0x55;
	const auto tampered = raven::verify_authenticode(first);
	std::printf("changed copy: status %08x\n", tampered.status);
	if (tampered.status != 0x80096010)
		return 1;
	std::printf("PASS: signatures verified and a changed file refused\n");
	return 0;
}
