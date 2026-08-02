#pragma once

#include "environment.h"
#include "pe/module_set.h"

#include <map>
#include <vector>

namespace raven {

// Static thread local storage of a 32-bit process: the TLS directory of each image names a template; every thread has an array of block
// pointers at TEB+0x2c and the code reaches its block through that array at the index the loader stored in the image.
class NativeX86Tls {
public:
	explicit NativeX86Tls(NativeProcess &process) : process(process) {}
	void attach_main(uint64_t teb) { create_thread(teb); }
	// Registers an image that is mapped in the guest and has a TLS directory; images without one are ignored.
	void add(PEModule &module);
	// The callbacks of an image's TLS directory, in order.
	std::vector<uint64_t> callbacks(const PEModule &module) const;
	void create_thread(uint64_t teb);
	void release_thread(uint64_t teb);

private:
	struct Template {
		std::vector<uint8_t> data;
		uint32_t zero_fill = 0, index = 0;
		std::vector<uint64_t> callbacks;
	};
	struct Thread {
		uint64_t array = 0;
		std::vector<uint64_t> blocks;
	};
	NativeProcess &process;
	std::map<const PEModule *, Template> templates;
	std::map<uint64_t, Thread> threads;
	uint32_t next_index = 0;
	void make_block(Thread &thread, const Template &item);
};

}
