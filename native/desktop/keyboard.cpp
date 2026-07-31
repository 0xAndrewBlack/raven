#include "keyboard.h"
#include <stdexcept>
#include <string>
#include <iterator>
#ifdef RAVEN_XKB
#include <xkbcommon/xkbcommon.h>
#include <xkbcommon/xkbcommon-keysyms.h>
#endif

namespace raven {

struct KeyboardMap::State {
#ifdef RAVEN_XKB
	xkb_context *context=xkb_context_new(XKB_CONTEXT_NO_DEFAULT_INCLUDES);
	xkb_keymap *map=nullptr;
	xkb_state *keys=nullptr;
	~State() { if (keys) xkb_state_unref(keys); if (map) xkb_keymap_unref(map); if (context) xkb_context_unref(context); }
#endif
};

KeyboardMap::KeyboardMap() : state(std::make_unique<State>()) {}
KeyboardMap::~KeyboardMap()=default;

void KeyboardMap::load(std::string_view text)
{
#ifdef RAVEN_XKB
	if (!state->context || text.empty() || text.size()>1024*1024 || text.find('\0')!=text.npos)
		throw std::runtime_error("invalid native keyboard keymap");
	auto *map=xkb_keymap_new_from_buffer(state->context,text.data(),text.size(),XKB_KEYMAP_FORMAT_TEXT_V1,XKB_KEYMAP_COMPILE_NO_FLAGS);
	if (!map) throw std::runtime_error("cannot compile native keyboard keymap");
	auto *keys=xkb_state_new(map);
	if (!keys) { xkb_keymap_unref(map); throw std::runtime_error("cannot create native keyboard state"); }
	if (state->keys) xkb_state_unref(state->keys);
	if (state->map) xkb_keymap_unref(state->map);
	state->map=map; state->keys=keys;
#else
	(void)text; throw std::runtime_error("native keyboard keymap support not built");
#endif
}

void KeyboardMap::modifiers(uint32_t depressed,uint32_t latched,uint32_t locked,uint32_t group)
{
#ifdef RAVEN_XKB
	if (!state->keys || group>=xkb_keymap_num_layouts(state->map)) throw std::runtime_error("invalid native keyboard modifier state");
	xkb_state_update_mask(state->keys,depressed,latched,locked,0,0,group);
#else
	(void)depressed; (void)latched; (void)locked; (void)group;
	throw std::runtime_error("native keyboard keymap support not built");
#endif
}

uint32_t KeyboardMap::mouse_modifiers() const
{
#ifdef RAVEN_XKB
	if (!state->keys) return 0;
	return (xkb_state_mod_name_is_active(state->keys,XKB_MOD_NAME_SHIFT,XKB_STATE_MODS_EFFECTIVE)>0 ? 4U : 0U) |
		(xkb_state_mod_name_is_active(state->keys,XKB_MOD_NAME_CTRL,XKB_STATE_MODS_EFFECTIVE)>0 ? 8U : 0U);
#else
	return 0;
#endif
}

KeyboardKey KeyboardMap::decode(uint32_t code) const
{
#ifdef RAVEN_XKB
	if (!state->keys || code>255 || code+8<xkb_keymap_min_keycode(state->map) || code+8>xkb_keymap_max_keycode(state->map))
		throw std::runtime_error("unsupported native keyboard keycode");
	if (xkb_state_mod_name_is_active(state->keys,XKB_MOD_NAME_ALT,XKB_STATE_MODS_EFFECTIVE)>0)
		throw std::runtime_error("system keyboard messages require qualification");
	const auto layout=xkb_state_key_get_layout(state->keys,code+8);
	const xkb_keysym_t *symbols=nullptr;
	if (xkb_keymap_key_get_syms_by_level(state->map,code+8,layout,0,&symbols)!=1)
		throw std::runtime_error("unsupported native keyboard symbol sequence");
	const auto symbol=symbols[0];
	KeyboardKey key{0,code,xkb_state_key_get_utf32(state->keys,code+8),false};
	const auto *name=xkb_keymap_key_get_name(state->map,code+8);
	if (!name) throw std::runtime_error("keyboard key has no physical name");
	const std::string_view physical(name);
	if (physical.size()==4 && physical[2]>='0' && physical[2]<='9' && physical[3]>='0' && physical[3]<='9') {
		const auto position=unsigned(physical[2]-'0')*10+unsigned(physical[3]-'0');
		if (physical.substr(0,2)=="AD" && position>=1 && position<=10) key.scan=15+position;
		else if (physical.substr(0,2)=="AC" && position>=1 && position<=9) key.scan=29+position;
		else if (physical.substr(0,2)=="AB" && position>=1 && position<=10) key.scan=43+position;
		else if (physical.substr(0,2)=="AE" && position>=1 && position<=10) key.scan=1+position;
		else if (physical.substr(0,2)=="FK" && position>=1 && position<=12) key.scan=position<=10 ? 58+position : 76+position;
		else if (code>=1 && code<=88) key.scan=code;
		else throw std::runtime_error("unsupported physical keyboard position "+std::string(physical)+" (evdev "+std::to_string(code)+")");
	} else {
		static constexpr std::string_view names[]{"ESC","TAB","BKSP","RTRN","LFSH","RTSH","LCTL","RCTL","CAPS","SPCE","LEFT","RGHT","UP","DOWN","HOME","END","DELE","LWIN","RWIN","MENU","COMP","NMLK","SCLK"};
		static constexpr uint32_t scans[]{1,15,14,28,42,54,29,29,58,57,75,77,72,80,71,79,83,91,92,93,93,69,70};
		bool found=false;
		for (size_t index=0;index<std::size(names);++index) if (physical==names[index]) { key.scan=scans[index]; found=true; break; }
		// Layout-independent keymaps (virtual keyboards) name keys arbitrarily; evdev codes up to 88 equal their set-1 scan codes.
		if (!found && code>=1 && code<=88) key.scan=code;
		else if (!found) throw std::runtime_error("unsupported physical keyboard position "+std::string(physical)+" (evdev "+std::to_string(code)+")");
	}
	if (symbol>='a' && symbol<='z') key.code=symbol-'a'+'A';
	else if (symbol>='A' && symbol<='Z') key.code=symbol;
	else if (symbol>='0' && symbol<='9') key.code=symbol;
	else if (symbol>=XKB_KEY_F1 && symbol<=XKB_KEY_F12) key.code=0x70+symbol-XKB_KEY_F1;
	else switch (symbol) {
		case XKB_KEY_Super_L: key.code=0x5b; key.extended=true; break;
		case XKB_KEY_Super_R: key.code=0x5c; key.extended=true; break;
		case XKB_KEY_Menu: key.code=0x5d; key.extended=true; break;
		case XKB_KEY_Num_Lock: key.code=0x90; break;
		case XKB_KEY_Scroll_Lock: key.code=0x91; break;
		case XKB_KEY_space: key.code=32; break;
		case XKB_KEY_BackSpace: key.code=8; break;
		case XKB_KEY_Tab: key.code=9; break;
		case XKB_KEY_Return: key.code=13; break;
		case XKB_KEY_Escape: key.code=27; break;
		case XKB_KEY_Shift_L: case XKB_KEY_Shift_R: key.code=16; break;
		case XKB_KEY_Control_L: key.code=17; break;
		case XKB_KEY_Control_R: key.code=17; key.scan=29; key.extended=true; break;
		case XKB_KEY_Caps_Lock: key.code=20; break;
		case XKB_KEY_Left: key.code=37; key.scan=75; key.extended=true; break;
		case XKB_KEY_Up: key.code=38; key.scan=72; key.extended=true; break;
		case XKB_KEY_Right: key.code=39; key.scan=77; key.extended=true; break;
		case XKB_KEY_Down: key.code=40; key.scan=80; key.extended=true; break;
		case XKB_KEY_Home: key.code=36; key.scan=71; key.extended=true; break;
		case XKB_KEY_End: key.code=35; key.scan=79; key.extended=true; break;
		case XKB_KEY_Delete: key.code=46; key.scan=83; key.extended=true; break;
		default: throw std::runtime_error("unsupported native keyboard virtual key");
	}
	if (key.scan>127 || key.character>0x10ffff || (key.character>=0xd800 && key.character<=0xdfff))
		throw std::runtime_error("invalid native keyboard translation");
	if (key.code==46) key.character=0;
	return key;
#else
	(void)code; throw std::runtime_error("native keyboard keymap support not built");
#endif
}

}
