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
	// Whether the shift (0x10), control (0x11) or alt (0x12) modifier is held in the current keymap state.
	bool modifier_active(uint32_t virtual_key) const;
private:
	struct State;
	std::unique_ptr<State> state;
};

}
