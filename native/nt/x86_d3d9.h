#pragma once

#include "x86_com.h"

namespace raven {

// Direct3D 9 for 32-bit programs that bring no library of their own: the interfaces exist and answer "not implemented" until their behaviour is written.
class NativeX86D3D9 {
public:
	explicit NativeX86D3D9(NativeProcess &process);
	NativeX86Com &com() { return com_; }
	static std::vector<std::string_view> method_names();
	static uint32_t method_words(std::string_view name);
	static std::span<const std::string_view> entry_names();
	bool dispatch(std::string_view name);

private:
	NativeProcess &process;
	NativeX86Com com_;
};

}
