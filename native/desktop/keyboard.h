#pragma once

#include <cstdint>
#include <memory>
#include <string_view>

namespace raven {

struct KeyboardKey {
	uint32_t code,scan,character;
	bool extended;
};

class KeyboardMap {
public:
	KeyboardMap();
	~KeyboardMap();
	void load(std::string_view text);
	void modifiers(uint32_t depressed,uint32_t latched,uint32_t locked,uint32_t group);
	KeyboardKey decode(uint32_t code) const;
	uint32_t mouse_modifiers() const;
private:
	struct State;
	std::unique_ptr<State> state;
};

}
