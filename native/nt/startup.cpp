#include "environment.h"

#include <algorithm>
#include <stdexcept>

namespace raven {

bool NativeEnvironment::startup_information(std::string_view name)
{
	require_current();
	const auto args=process.api_arguments(1);
	if (!startup_info_ansi) throw std::runtime_error("native startup information is not initialized");
	if (process.mode()==NativeMode::x86) {
		if (name!="GetStartupInfoA" && name!="GetStartupInfoW") return false;
		try {
			auto bytes=process.read_memory(startup_info_ansi,68);
			if (name=="GetStartupInfoW") {
				// The wide form names the same desktop and title as the process parameters hold them: wide strings.
				const auto pointer=process.read_memory(process_block+0x10,4);
				uint32_t parameters=0;
				for (size_t i=0;i<4;++i) parameters|=uint32_t(pointer[i])<<(i*8);
				if (parameters) {
					const auto fields=process.read_memory(parameters,0x80);
					std::copy_n(fields.begin()+0x7c,4,bytes.begin()+8);
					std::copy_n(fields.begin()+0x74,4,bytes.begin()+12);
				}
			}
			process.write_memory(args[0],bytes);
		} catch (const std::runtime_error &error) {
			const std::string_view message=error.what();
			if (message.find("writable")==message.npos) throw;
			NativeResult fault{NativeStop::exception,0xc0000005U,process.context().registers.rip-1,0};
			fault.fault_address=args[0];
			fault.exception_information={1,args[0]};
			throw fault;
		}
		process.return_api(0);
		return true;
	}
	uint64_t fault_address=args[0],access=1;
	try {
		if (name=="GetStartupInfoA") {
			const auto bytes=process.read_memory(startup_info_ansi,104);
			process.write_memory(args[0],bytes);
		} else {
			const auto pointer=process.read_memory(process_block+0x20,8);
			uint64_t parameters=0;
			for (size_t i=0;i<8;++i) parameters|=uint64_t(pointer[i])<<(i*8);
			fault_address=parameters;access=0;
			const auto fields=process.read_memory(parameters,0xf0);
			std::array<uint8_t,104> bytes{};
			const auto copy=[&](size_t destination,size_t source,size_t length) {
				std::copy_n(fields.begin()+static_cast<ptrdiff_t>(source),length,bytes.begin()+static_cast<ptrdiff_t>(destination));
			};
			bytes[0]=104;
			copy(16,0xc8,8);copy(24,0xb8,8);copy(32,0x88,32);
			copy(64,0xa8,2);copy(66,0xe0,2);copy(72,0xe8,8);
			copy(80,0x20,24);
			const auto write=[&](size_t offset,size_t length) {
				fault_address=args[0]+offset;access=1;
				process.write_memory(fault_address,std::span<const uint8_t>(bytes).subspan(offset,length));
			};
			// Do not touch caller padding or unused standard-handle slots.
			write(0,4);write(8,60);write(72,8);
			if (fields[0xa5]&1) write(80,24);
		}
	} catch (const std::runtime_error &error) {
		const std::string_view message=error.what();
		if (message.find("readable")==message.npos && message.find("writable")==message.npos) throw;
		NativeResult fault{NativeStop::exception,0xc0000005U,process.context().registers.rip-1,0};
		fault.fault_address=fault_address;
		fault.exception_information={access,fault_address};
		throw fault;
	}
	process.return_api(0);
	return true;
}

}
