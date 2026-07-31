#include "windows.h"
#include "brush.h"
#include "nt/nls.h"

#include <array>
#include <algorithm>
#include <limits>
#include <new>
#include <stdexcept>
#include <sys/mman.h>
#include <thread>
#include <utility>

namespace raven {

static uint64_t read(std::span<const uint8_t> bytes,size_t at,size_t width);

NativeWindows::NativeWindows(NativeProcess &process, NativeEnvironment &environment, DesktopObjects &objects)
	: process(process), environment(environment), objects(objects), deadline(std::chrono::steady_clock::now()) {}

void NativeWindows::shutdown()
{
	for (const auto handle : objects.window_handles()) {
		const auto *window=objects.window(handle);
		if (handle!=desktop && !window->parent && window->bitmap && presentation.remove) presentation.remove(handle);
	}
}

void NativeWindows::set_deadline(std::chrono::steady_clock::time_point end)
{
	deadline=end;
}

void NativeWindows::set_call(std::function<NativeResult(uint64_t,std::span<const uint64_t>)> caller)
{
	invoke=std::move(caller);
}

void NativeWindows::set_presentation(DesktopPresentation backend)
{
	presentation=std::move(backend);
}

uint64_t NativeWindows::surface_dc(uint64_t handle)
{
	auto *window=objects.window(handle);
	if (!window) throw uint32_t(1400);
	if (window->dc) return window->dc;
	if (window->parent) {
		const auto root=objects.window_root(handle);surface_dc(root);
		window=objects.window(handle);const auto bitmap=objects.window(root)->bitmap;
		DesktopDC device{bitmap,bitmap,handle};objects.configure_window_dc(handle,device,false);
		const auto dc=objects.add(device);if (!dc) throw uint32_t(8);
		window=objects.window(handle);window->bitmap=bitmap;window->dc=dc;return dc;
	}

	const auto width=int64_t(window->outer.right)-window->outer.left,height=int64_t(window->outer.bottom)-window->outer.top;
	if (width<=0 || height<=0 || width>8192 || height>8192 || uint64_t(width)*uint64_t(height)>16*1024*1024)
		throw uint32_t(87);
	const auto size=(size_t(width)*size_t(height)*4+4095)&~size_t(4095);
	const auto address=process.map_memory(size,PROT_READ | PROT_WRITE);
	uint64_t bitmap=0,dc=0;
	try {
		bitmap=objects.add(DesktopBitmap{uint32_t(width),uint32_t(height),32,{},address,true,true});
		if (!bitmap) throw uint32_t(8);
		DesktopDC device{bitmap,bitmap,handle};
		objects.configure_window_dc(handle,device,false);
		dc=objects.add(device);
		if (!dc) throw uint32_t(8);
		window=objects.window(handle); window->bitmap=bitmap; window->dc=dc;
		return dc;
	} catch (...) { if (dc) objects.erase(dc); if (bitmap) objects.erase(bitmap); process.unmap_memory(address); throw; }
}

void NativeWindows::present(uint64_t handle)
{
	// The desktop is the screen itself; guest drawing on it never becomes a host window.
	if (handle==desktop) return;
	handle=objects.window_root(handle);
	if (!handle) throw uint32_t(1400);
	if (!presentation.present) throw uint32_t(120);
	surface_dc(handle);
	paint_nonclient(handle);
	const auto *window=objects.window(handle);
	const auto *bitmap=objects.bitmap(window->bitmap);
	const auto pixels=process.read_memory(bitmap->address,size_t(bitmap->width)*bitmap->height*4);
	// Host titles use replacement characters; the guest retains every UTF-16 code unit.
	presentation.present(handle,encode_utf8(window->title,true),bitmap->width,bitmap->height,pixels);
}

void NativeWindows::drawing(uint64_t handle)
{
	if (handle==desktop) return;
	const auto *window=objects.window(handle);
	if (window && objects.window_visible(handle)) present(handle);
}

void NativeWindows::release_surface(uint64_t handle)
{
	const auto *window=objects.window(handle);
	if (!window) return;
	objects.detach_window_dcs(handle);
	if (focus==handle) focus=0;
	if (active==handle) active=0;
	if (!window->parent && window->bitmap && presentation.remove) presentation.remove(handle);
	const auto bitmap=window->bitmap,dc=window->dc;
	if (dc) objects.erase(dc);
	if (bitmap && !window->parent) {
		const auto address=objects.bitmap(bitmap)->address;
		process.unmap_memory(address); objects.erase(bitmap);
	}
}

DesktopRect NativeWindows::update_rect(uint64_t handle,uint64_t address)
{
	const auto *window=objects.window(handle); if (!window) throw uint32_t(1400);
	DesktopRect rect{0,0,window->width,window->height};
	if (address) {
		const auto bytes=process.read_memory(address,16);
		rect={int32_t(read(bytes,0,4)),int32_t(read(bytes,4,4)),int32_t(read(bytes,8,4)),int32_t(read(bytes,12,4))};
		rect.left=std::max(rect.left,0); rect.top=std::max(rect.top,0);
		rect.right=std::min(rect.right,window->width); rect.bottom=std::min(rect.bottom,window->height);
	}
	return rect;
}

NativeWindows::PaintStart NativeWindows::start_paint(uint64_t handle)
{
	const auto dc=surface_dc(handle);
	const bool erase=objects.start_paint(handle);
	const auto rect=objects.dc(dc)->clip->bounds();
	const bool pending=erase && !send(handle,0x14,dc,0);
	if (!objects.window(handle)) throw std::runtime_error("background callback destroyed its painting window");
	return {dc,rect,pending};
}

static uint64_t read(std::span<const uint8_t> bytes, size_t at, size_t width)
{
	uint64_t value=0;
	for (size_t byte=0; byte<width; ++byte) value|=uint64_t(bytes[at+byte])<<(byte*8);
	return value;
}

static void put(std::span<uint8_t> bytes, size_t at, uint64_t value, size_t width)
{
	for (size_t byte=0; byte<width; ++byte) bytes[at+byte]=uint8_t(value>>(byte*8));
}

// Guest MSG: hwnd, message, wParam, lParam, time, pt. Offsets differ between the 32-bit and 64-bit Windows ABIs.
struct MessageLayout { size_t size, message, wparam, lparam, time, x, y, pointer; };
static MessageLayout message_layout(bool narrow)
{
	return narrow ? MessageLayout{28,4,8,12,16,20,24,4} : MessageLayout{48,8,16,24,32,36,40,8};
}

static uint32_t message_time()
{
	return uint32_t(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

void NativeWindows::post(uint64_t window,uint32_t message,uint64_t wparam,uint64_t lparam)
{
	if (window==0xffff) throw uint32_t(120);
	if (window && !objects.window(window)) throw uint32_t(1400);
	if (message && message!=0x10 && message!=0x12 && message<0x400) throw uint32_t(120);
	if (messages.size()>=10000) throw uint32_t(1816);
	messages.push_back({window,wparam,lparam,message,message_time(),cursor_x,cursor_y});
}

void NativeWindows::receive(const DesktopEvent &event)
{
	if (event.kind==DesktopEventKind::message) { post(event.window,event.message,event.wparam,event.lparam); return; }
	if (event.kind==DesktopEventKind::keymap) {
		if (std::any_of(key_down.begin(),key_down.end(),[](bool down) { return down; }))
			throw std::runtime_error("keyboard map change with held keys requires qualification");
		keyboard_map.load(event.keymap); key_translation.reset(); return;
	}
	if (event.kind==DesktopEventKind::modifiers) {
		keyboard_map.modifiers(event.message,uint32_t(event.wparam),uint32_t(event.lparam),uint32_t(event.lparam>>32)); return;
	}
	if (event.kind==DesktopEventKind::keyboard_focus) {
		std::array<bool,256> initial{};
		for (const auto code : event.held_keys) {
			if (code>=initial.size() || initial[code]) throw std::runtime_error("invalid initial keyboard key state");
			initial[code]=true;
		}
		if ((!event.window && !event.held_keys.empty()) || (event.window &&
			(!objects.window(event.window) || !objects.window(event.window)->visible)))
			throw std::runtime_error("keyboard focus requires its visible guest window");
		key_down=initial; key_translation.reset();
		if (!event.window) { set_focus(0); activate(0); }
		else if (!focus || objects.window_root(focus)!=event.window) set_focus(event.window);
		return;
	}
	if (event.kind==DesktopEventKind::key) {
		if (!event.window || objects.window_root(focus)!=event.window || !objects.window(focus) || !objects.window_visible(focus))
			throw std::runtime_error("keyboard event requires its focused guest window");
		if (event.wparam>1 || event.message>=key_down.size() || messages.size()>=10000)
			throw std::runtime_error("invalid native keyboard event or queue exhaustion");
		const auto key=keyboard_map.decode(event.message);
		const bool pressed=event.wparam!=0,previous=key_down[event.message];
		if (!pressed && !previous) throw std::runtime_error("keyboard release without a qualified key press");
		const uint64_t flags=1 | (uint64_t(key.scan)<<16) | (uint64_t(key.extended)<<24) |
			(uint64_t(previous)<<30) | (uint64_t(!pressed)<<31);
		messages.push_back({focus,key.code,flags,pressed ? 0x100U : 0x101U,message_time(),cursor_x,cursor_y,pressed ? key.character : 0});
		key_down[event.message]=pressed;
		return;
	}
	if (event.x<INT16_MIN || event.x>INT16_MAX || event.y<INT16_MIN || event.y>INT16_MAX)
		throw std::runtime_error("pointer coordinates exceed the guest message contract");
	uint32_t message=0x200,buttons=mouse_buttons;
	if (event.kind==DesktopEventKind::pointer_button) {
		uint32_t mask=0;
		if (event.message==0x110) { mask=1; message=0x201; }
		else if (event.message==0x111) { mask=2; message=0x204; }
		else if (event.message==0x112) { mask=16; message=0x207; }
		else throw std::runtime_error("unsupported pointer button");
		if (event.wparam>1) throw std::runtime_error("invalid pointer button state");
		if (event.wparam) buttons|=mask; else { buttons&=~mask; ++message; }
	}
	if (!event.window && event.kind==DesktopEventKind::pointer_button) { mouse_buttons=buttons; return; }
	const auto *window=objects.window(event.window);
	if (!window || !window->visible) throw std::runtime_error("pointer event targets an unavailable guest window");
	if (messages.size()>=10000) throw std::runtime_error("guest input queue limit reached");
	const auto x=int64_t(window->outer.left)+event.x,y=int64_t(window->outer.top)+event.y;
	if (x<INT32_MIN || x>INT32_MAX || y<INT32_MIN || y>INT32_MAX)
		throw std::runtime_error("guest cursor coordinates overflow");
	mouse_buttons=buttons; cursor_x=int32_t(x); cursor_y=int32_t(y);
	if (capture && !objects.window(capture)) capture=0;
	const auto target=capture ? capture : pointer_child(event.window,int32_t(x),int32_t(y));window=objects.window(target);
	const bool inset=window->x!=window->outer.left || window->y!=window->outer.top ||
		int64_t(window->width)!=int64_t(window->outer.right)-window->outer.left ||
		int64_t(window->height)!=int64_t(window->outer.bottom)-window->outer.top;
	const bool inside=x>=window->outer.left && y>=window->outer.top && x<window->outer.right && y<window->outer.bottom;
	const auto hit=!capture && inset && inside ? send(target,0x84,0,uint16_t(x)|(uint64_t(uint16_t(y))<<16)) : 1;
	window=objects.window(target);
	if (!window || !objects.window_visible(target) || !hit) return;
	if (hit!=1) throw std::runtime_error("nonclient pointer dispatch requires qualification");
	if ((message==0x201 || message==0x204 || message==0x207) && window->parent && !(window->ex_style & 4)) {
		for (auto parent=window->parent;parent;) {
			const auto *ancestor=objects.window(parent);if (!ancestor) break;
			const auto next=ancestor->parent;
			send(parent,0x210,message,uint16_t(x-ancestor->x)|(uint64_t(uint16_t(y-ancestor->y))<<16));
			parent=next;
		}
		window=objects.window(target);if (!window || !objects.window_visible(target)) return;
	}
	if (messages.size()>=10000) throw std::runtime_error("guest input queue limit reached");
	messages.push_back({target,buttons|keyboard_map.mouse_modifiers(),uint16_t(x-window->x)|(uint64_t(uint16_t(y-window->y))<<16),message,message_time(),int32_t(x),int32_t(y)});
}

NativeWindows::Modifiers NativeWindows::modifier_state() const
{
	Modifiers state{false,false,false};
	for (size_t code=0;code<key_down.size();++code) {
		if (!key_down[code]) continue;
		const auto key=keyboard_map.decode(uint32_t(code)).code;
		state.shift|=key==0x10 || key==0xa0 || key==0xa1;
		state.control|=key==0x11 || key==0xa2 || key==0xa3;
		state.alt|=key==0x12 || key==0xa4 || key==0xa5;
	}
	return state;
}

uint64_t NativeWindows::retrieve(std::span<const uint64_t> args,bool blocking)
{
	const auto layout=message_layout(process.mode()==NativeMode::x86);
	// A 32-bit (HWND)-1 selects thread messages exactly like its 64-bit sign extension.
	const auto window=process.mode()==NativeMode::x86 && args[1]==UINT32_MAX ? UINT64_MAX : args[1];
	const auto minimum=uint32_t(args[2]),maximum=uint32_t(args[3]);
	if (window && window!=UINT64_MAX && !objects.window(window)) throw uint32_t(1400);
	if ((minimum || maximum) && (minimum>maximum || maximum>0xffff)) throw uint32_t(87);
	const auto flags=blocking ? 1U : uint32_t(args[4]);
	if (flags & ~1U) throw uint32_t(120);
	for (;;) {
		if (presentation.poll)
			for (const auto &event : presentation.poll(std::chrono::milliseconds(0)))
				receive(event);
		auto found=std::find_if(messages.begin(),messages.end(),[&](const Message &message) {
			return (!window || (window==UINT64_MAX ? !message.window : message.window==window || objects.is_child(window,message.window))) &&
				(message.message==0x12 || (!minimum && !maximum) || (message.message>=minimum && message.message<=maximum));
		});
		if (found!=messages.end() || quit) {
			const auto value=found!=messages.end() ? *found : Message{0,*quit,0,0x12,message_time(),cursor_x,cursor_y};
			std::vector<uint8_t> bytes(layout.size);
			put(bytes,0,value.window,layout.pointer); put(bytes,layout.message,value.message,4);
			put(bytes,layout.wparam,value.wparam,layout.pointer); put(bytes,layout.lparam,value.lparam,layout.pointer);
			put(bytes,layout.time,value.time,4);
			put(bytes,layout.x,uint32_t(value.x),4); put(bytes,layout.y,uint32_t(value.y),4);
			process.write_memory(args[0],bytes);
			if (value.message==0x100 || value.message==0x101) key_translation=value;
			if (flags & 1U) { if (found!=messages.end()) messages.erase(found); else quit.reset(); }
			return blocking && value.message==0x12 ? 0 : 1;
		}
		// WM_TIMER ranks below input and paint, so it is only generated when neither is waiting.
		if (found==messages.end() && !quit) {
			const auto before=messages.size();
			if (!objects.invalid_window(window)) post_due_timers();
			if (messages.size()!=before) continue;
		}
		const auto paint=(!minimum && !maximum) || (minimum<=0x0f && maximum>=0x0f) ? objects.invalid_window(window) : 0;
		if (paint) {
			std::vector<uint8_t> bytes(layout.size);
			put(bytes,0,paint,layout.pointer); put(bytes,layout.message,0x0f,4); put(bytes,layout.time,message_time(),4);
			process.write_memory(args[0],bytes);
			return 1;
		}
		if (!blocking) return 0;
		if (std::chrono::steady_clock::now()>=deadline) throw NativeResult{NativeStop::timeout,0,0,0};
		if (presentation.poll) {
			const auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now());
			for (const auto &event : presentation.poll(std::min(remaining,std::chrono::milliseconds(20))))
				receive(event);
		} else std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

std::string NativeWindows::text(uint64_t address)
{
	std::string result;
	for (size_t index=0; index<256; ++index) {
		const auto bytes=process.read_memory(address+index*2,2);
		const auto character=read(bytes,0,2);
		if (!character) return result;
		if (character>127) throw uint32_t(120);
		result.push_back(char(character));
	}
	throw uint32_t(87);
}

std::u16string NativeWindows::window_text(uint64_t address)
{
	std::u16string result;
	if (!address) return result;
	for (size_t index=0;index<=32766;++index) {
		if (address>UINT64_MAX-index*2) throw uint32_t(87);
		const auto character=char16_t(read(process.read_memory(address+index*2,2),0,2));
		if (!character) return result;
		if (index==32766) throw uint32_t(120);
		result.push_back(character);
	}
	throw uint32_t(120);
}

uint64_t NativeWindows::copy_window_text(uint64_t handle,uint64_t output,uint64_t capacity)
{
	const auto *window=objects.window(handle);if (!window) throw uint32_t(1400);
	if (!capacity) return 0;
	const auto length=std::min(uint64_t(window->title.size()),capacity-1);
	std::vector<uint8_t> bytes(size_t(length+1)*2);
	for (size_t index=0;index<length;++index) put(bytes,index*2,window->title[index],2);
	process.write_memory(output,bytes);return length;
}

uint16_t NativeWindows::atom(uint64_t name, uint64_t instance)
{
	if (name && name<=UINT16_MAX) {
		return objects.find_class(instance,uint16_t(name));
	}
	auto value=text(name);
	for (auto &character : value)
		if (character>='A' && character<='Z') character=char(character+('a'-'A'));
	return objects.find_class(instance,value);
}

uint64_t NativeWindows::send(uint64_t handle, uint32_t message, uint64_t wparam, uint64_t lparam)
{
	const auto *window=objects.window(handle);
	if (!window) throw uint32_t(1400);
	if (!invoke) throw std::runtime_error("native window callbacks are not connected");
	const auto procedure=window->procedure;
	const uint64_t arguments[]{handle,message,wparam,lparam};
	// The desktop window belongs to the system and has no guest procedure.
	if (!procedure) return default_message(arguments);
	const auto result=invoke(procedure,arguments);
	if (result.stop!=NativeStop::returned) throw result;
	return result.value;
}

void NativeWindows::activate(uint64_t handle)
{
	if (handle) handle=objects.window_root(handle);
	if (active==handle) return;
	if (activating) throw std::runtime_error("unsupported reentrant window activation");
	activating=true;
	try {
		const auto previous=active;
		if (previous && objects.window(previous)) {
			if (!send(previous,0x86,0,handle)) throw std::runtime_error("nonclient activation veto requires Windows qualification");
			send(previous,6,0,handle);
		}
		if (handle && !objects.window(handle)) throw std::runtime_error("activation callback destroyed its target");
		active=handle;
		if (handle) { send(handle,0x86,1,previous); send(handle,6,1,previous); }
		activating=false;
	} catch (...) { activating=false; throw; }
}

uint64_t NativeWindows::set_focus(uint64_t handle)
{
	if (handle && (!objects.window(handle) || objects.window(handle)->destroying)) throw uint32_t(1400);
	if (handle) activate(handle);
	const auto previous=focus;
	if (previous==handle) return previous;
	if (focusing) throw std::runtime_error("unsupported reentrant focus transition");
	focusing=true;
	try {
		focus=handle;
		if (previous && objects.window(previous)) send(previous,8,handle,0);
		if (handle && objects.window(handle)) send(handle,7,previous,0);
		focusing=false;
		return previous;
	} catch (...) { focusing=false; throw; }
}

bool NativeWindows::destroy(uint64_t handle)
{
	auto *window=objects.window(handle);
	if (!window || window->destroying) throw uint32_t(5);
	for (const auto owned:objects.window_handles())
		if (objects.is_child(handle,owned) && objects.window(owned)->destroying) throw uint32_t(120);
	window->destroying=true;window->visible=false;window->style&=~0x10000000U;
	if (active==handle) activate(0);
	if (focus==handle || objects.is_child(handle,focus)) set_focus(0);
	parent_notify(handle,2);
	send(handle,2,0,0);
	for (const auto child:objects.child_windows(handle)) if (objects.window(child)) destroy(child);
	if (objects.window(handle)) send(handle,0x82,0,0);
	window=objects.window(handle);
	if (window && window->parent) {
		const auto *parent=objects.window(window->parent);
		if (parent && !parent->destroying) {
			const auto relative=[](int64_t value) { return int32_t(std::clamp(value,int64_t(INT32_MIN),int64_t(INT32_MAX))); };
			if (!objects.invalidate(window->parent,{relative(int64_t(window->outer.left)-parent->x),relative(int64_t(window->outer.top)-parent->y),
				relative(int64_t(window->outer.right)-parent->x),relative(int64_t(window->outer.bottom)-parent->y)},true)) throw uint32_t(8);
		}
	}
	release_surface(handle);
	return objects.erase(handle);
}

uint64_t NativeWindows::default_message(std::span<const uint64_t> args)
{
	auto *window=objects.window(args[0]);
	if (!window) throw uint32_t(1400);
	const auto message=uint32_t(args[1]);
	if (message==0x200 || message==0x201 || message==0x202 || message==0x204 || message==0x207 || message==0x208 || message==0x7b) return 0;
	if (message==0x205) {
		const auto x=uint16_t(int64_t(window->x)+int16_t(uint16_t(args[3])));
		const auto y=uint16_t(int64_t(window->y)+int16_t(uint16_t(args[3]>>16)));
		send(args[0],0x7b,args[0],uint32_t(x)|(uint32_t(y)<<16));
		return 0;
	}
	if (message==0x210 && (uint16_t(args[2])==1 || uint16_t(args[2])==2 || uint16_t(args[2])==0x201 || uint16_t(args[2])==0x204 || uint16_t(args[2])==0x207)) return 0;
	if (message==0x86) return 1;
	if (message==6) { if (uint16_t(args[2]) && !uint16_t(args[2]>>16)) set_focus(args[0]); return 0; }
	if (message==7 || message==8) return 0;
	if (message==0x81 || message==0x0c) {
		const bool narrow=process.mode()==NativeMode::x86;
		const auto address=message==0x81 ? (narrow ? read(process.read_memory(args[3],48),36,4) :
			read(process.read_memory(args[3],80),56,8)) : args[3];
		if (!objects.set_title(args[0],window_text(address))) throw uint32_t(8);
		if (objects.window_visible(args[0])) present(args[0]);
		return 1;
	}
	if (message==0x0e) return window->title.size();
	if (message==0x0d) return copy_window_text(args[0],args[3],args[2]);
	if (message==0x10) { destroy(args[0]); return 0; }
	if (message>=0x132 && message<=0x138) {
		if (message==0x137) throw uint32_t(120);
		auto *dc=objects.dc(args[2]);if (!dc) throw uint32_t(6);
		const auto background=message==0x133 || message==0x134 ? 5 : 15;
		dc->text_color=objects.system_color(8);dc->background_color=objects.system_color(background);
		return objects.system_brush(background);
	}
	if (message==0x14) {
		const auto background=objects.window_class(window->class_id)->background;
		if (!background) return 0;
		const auto *dc=objects.dc(args[2]);
		const auto *bitmap=dc ? objects.bitmap(dc->bitmap) : nullptr;
		if (!bitmap) throw uint32_t(6);
		const auto target=dc->window; const bool leased=dc->leased;
		const auto changed=fill_rect(process,objects,args[2],{INT32_MIN,INT32_MIN,INT32_MAX,INT32_MAX},background);
		if (changed && target && leased) drawing(target);
		return 1;
	}
	if (message==0x85) {
		// The frame is repainted from window state each time the surface is presented.
		if (objects.window_visible(args[0])) present(args[0]);
		return 0;
	}
	if (message==0x84 && !window->parent && (frame_layout(*window).border || frame_layout(*window).caption_height || window->menu))
		return nonclient_hit(*window,int16_t(uint16_t(args[3])),int16_t(uint16_t(args[3]>>16)));
	if (message==0x84) {
		const auto x=int16_t(uint16_t(args[3])),y=int16_t(uint16_t(args[3]>>16));
		return x>=window->outer.left && y>=window->outer.top && x<window->outer.right && y<window->outer.bottom &&
			x>=window->x && y>=window->y && int64_t(x)<int64_t(window->x)+window->width &&
			int64_t(y)<int64_t(window->y)+window->height ? 1 : 0;
	}
	if (message==0x0f) {
		if (window->painting) throw uint32_t(170);
		start_paint(args[0]); objects.finish_paint(args[0]);
		if (objects.window(args[0])->visible) present(args[0]);
		return 0;
	}
	if (message==0x83) {
		if (args[2]) throw std::runtime_error("unsupported default extended nonclient calculation");
		auto rect=process.read_memory(args[3],16);
		// The client area is the window rectangle minus what AdjustWindowRectEx adds for this style.
		const auto frame=adjust_window_rect(objects.nonclient_metrics(),{0,0,0,0},window->style & ~0x10000000U,window->menu!=0,window->ex_style);
		const int32_t edges[4]={frame.left,frame.top,frame.right,frame.bottom};
		for (size_t index=0;index<4;++index)
			put(rect,index*4,uint32_t(int32_t(read(rect,index*4,4))-edges[index]),4);
		process.write_memory(args[3],rect);
		return 0;
	}
	if (message==0x112) {
		// SC_CLOSE becomes WM_CLOSE; the other system commands need window state transitions that are not modeled.
		if ((uint32_t(args[2]) & 0xfff0U)==0xf060U) { send(args[0],0x10,0,0); return 0; }
		return 0;
	}
	if (message==0x21) return 1;
	if (message==0x11) return 1;
	if (!message || message==1 || message==2 || message==3 || message==5 || message==0x82 || message==0x18) return 0;
	// Messages whose Windows default is "no action, result 0": cursor, activation notices, window-position notices,
	// non-client mouse notices, capture loss, keyboard and timer/command traffic nobody consumed.
	if (message==0x20 || message==0x16 || message==0x1c || message==0x24 || message==0x46 || message==0x47 || message==0x4e ||
		message==0x7f || message==0x80 || (message>=0xa0 && message<=0xa9) || message==0x215 || (message>=0x100 && message<=0x109) ||
		message==0x111 || message==0x113) return 0;
	throw std::runtime_error("unsupported default window message "+std::to_string(message));
}

uint64_t NativeWindows::create(std::span<const uint64_t> args)
{
	const auto style=uint32_t(args[3]),ex_style=uint32_t(args[0]);
	const bool child=(style & 0x40000000U)!=0;
	// Top-level styles: popup or overlapped with a frame (border, caption, system menu, sizing and caption buttons).
	constexpr uint32_t top_level_styles=0x80000000U | 0x10000000U | 0x00cf0000U | 0x04000000U | 0x02000000U;
	if ((child ? (style & ~0x10000000U)!=0x40000000U || (ex_style & ~4U) :
		(style & ~top_level_styles) || ex_style || args[8] || (args[9] && !objects.menu(args[9]))) ||
		((style & 0x10000000U) && !presentation.present)) throw uint32_t(120);
	const auto *parent=child ? objects.window(args[8]) : nullptr;
	if (child && (!parent || parent->destroying)) throw uint32_t(1400);
	if (parent && !parent->client_ready) throw uint32_t(120);
	const auto class_atom=atom(args[1],args[10]);
	const auto *definition=objects.window_class(class_atom);
	if (!definition) throw uint32_t(1407);
	auto x=int32_t(args[4]),y=int32_t(args[5]);
	const auto width=int32_t(args[6]),height=int32_t(args[7]);
	if (x==INT32_MIN || y==INT32_MIN || width==INT32_MIN || height==INT32_MIN) throw uint32_t(120);
	if (width<0 || height<0 || width>8192 || height>8192 || int64_t(x)+width>INT32_MAX || int64_t(y)+height>INT32_MAX)
		throw uint32_t(87);
	const auto relative_x=x,relative_y=y;
	if (parent) {
		const auto absolute_x=int64_t(parent->x)+x,absolute_y=int64_t(parent->y)+y;
		if (absolute_x<INT32_MIN || absolute_y<INT32_MIN || absolute_x+width>INT32_MAX || absolute_y+height>INT32_MAX) throw uint32_t(87);
		x=int32_t(absolute_x);y=int32_t(absolute_y);
	}
	if (args[2]) window_text(args[2]);
	DesktopWindow record{class_atom,definition->procedure,{},x,y,width,height};
	record.instance=args[10]; record.style=style | (child ? 0U : 0x04000000U);record.ex_style=ex_style;
	record.parent=child ? args[8] : 0;record.child_id=child ? args[9] : 0;record.client_ready=false;
	// A class default menu would need resource loading here; refuse it rather than create a window without its menu.
	if (!child && !args[9] && (definition->menu_id || !definition->menu_name.empty())) throw uint32_t(120);
	if (!child) record.menu=args[9];
	record.extra.resize(definition->window_extra);
	const auto handle=objects.add(std::move(record));
	if (!handle) throw uint32_t(8);
	uint64_t scratch=0;
	try {
		scratch=process.map_memory(4096,PROT_READ | PROT_WRITE);
		// CREATESTRUCTW followed by the 16-byte window rectangle used for WM_NCCALCSIZE.
		const bool narrow=process.mode()==NativeMode::x86;
		const size_t rect_at=narrow ? 48 : 80;
		std::vector<uint8_t> bytes(rect_at+16);
		if (narrow) {
			put(bytes,0,args[11],4); put(bytes,4,args[10],4);put(bytes,8,args[9],4);put(bytes,12,args[8],4);
			put(bytes,16,uint32_t(height),4); put(bytes,20,uint32_t(width),4);
			put(bytes,24,uint32_t(relative_y),4); put(bytes,28,uint32_t(relative_x),4); put(bytes,32,uint32_t(args[3]),4);
			put(bytes,36,args[2],4); put(bytes,40,args[1],4);put(bytes,44,ex_style,4);
		} else {
			put(bytes,0,args[11],8); put(bytes,8,args[10],8);put(bytes,16,args[9],8);put(bytes,24,args[8],8);
			put(bytes,32,uint32_t(height),4); put(bytes,36,uint32_t(width),4);
			put(bytes,40,uint32_t(relative_y),4); put(bytes,44,uint32_t(relative_x),4); put(bytes,48,uint32_t(args[3]),4);
			put(bytes,56,args[2],8); put(bytes,64,args[1],8);put(bytes,72,ex_style,4);
		}
		put(bytes,rect_at,uint32_t(x),4); put(bytes,rect_at+4,uint32_t(y),4);
		put(bytes,rect_at+8,uint32_t(x+width),4); put(bytes,rect_at+12,uint32_t(y+height),4);
		process.write_memory(scratch,bytes);
		const auto accepted=send(handle,0x81,0,scratch);
		if (!objects.window(handle)) { process.unmap_memory(scratch); return 0; }
		if (!accepted) {
			send(handle,0x82,0,0);
			release_surface(handle);
			objects.erase(handle); process.unmap_memory(scratch); return 0;
		}
		send(handle,0x83,0,scratch+rect_at);
		if (!objects.window(handle)) { process.unmap_memory(scratch); return 0; }
		const auto client=process.read_memory(scratch+rect_at,16);
		const auto left=int32_t(uint32_t(read(client,0,4))),top=int32_t(uint32_t(read(client,4,4)));
		// A window smaller than its frame has an empty client area, not a negative one.
		const auto right=uint32_t(std::max(int32_t(uint32_t(read(client,8,4))),left)),bottom=uint32_t(std::max(int32_t(uint32_t(read(client,12,4))),top));
		if (int64_t(left)-x<INT32_MIN || int64_t(left)-x>INT32_MAX || int64_t(top)-y<INT32_MIN || int64_t(top)-y>INT32_MAX) {
			send(handle,0x82,0,0);
			throw uint32_t(120);
		}
		auto *geometry=objects.window(handle);
		geometry->x=left; geometry->y=top;
		geometry->width=int32_t(right-uint32_t(left)); geometry->height=int32_t(bottom-uint32_t(top));
		objects.update_window_dcs(handle);geometry->client_ready=true;
		const auto created=send(handle,1,0,scratch);
		process.unmap_memory(scratch); scratch=0;
		if (!objects.window(handle)) return 0;
		if (created==UINT64_MAX) { reject_tree(handle);return 0; }
		const auto *window=objects.window(handle);
		send(handle,5,0,uint16_t(window->width) | (uint64_t(uint16_t(window->height))<<16));
		window=objects.window(handle);
		if (!window) throw uint32_t(1400);
		send(handle,3,0,uint16_t(child ? int64_t(window->x)-objects.window(args[8])->x : window->x) |
			(uint64_t(uint16_t(child ? int64_t(window->y)-objects.window(args[8])->y : window->y))<<16));
		if (!objects.window(handle)) throw uint32_t(1400);
		if (child) parent_notify(handle,1);
		if (!objects.window(handle)) return 0;
		if (style & 0x10000000U) {
			auto *window=objects.window(handle);window->visible=true;objects.update_window_dcs(handle);
			if (objects.window_visible(handle)) present(handle);
			if (!objects.invalidate(handle,{0,0,window->width,window->height},true)) throw uint32_t(8);
		}
		return handle;
	} catch (...) {
		discard_tree(handle);
		if (scratch) process.unmap_memory(scratch);
		throw;
	}
}

uint64_t NativeWindows::map_points(uint64_t from,uint64_t to,uint64_t points,uint32_t count)
{
	const auto origin = [&](uint64_t handle) {
		if (!handle) return std::pair<int32_t,int32_t>{0,0};
		const auto *window=objects.window(handle);
		if (!window) throw uint32_t(1400);
		return std::pair<int32_t,int32_t>{window->x,window->y};
	};
	const auto source=origin(from),destination=origin(to);
	const auto dx=uint32_t(int64_t(source.first)-destination.first);
	const auto dy=uint32_t(int64_t(source.second)-destination.second);
	if (count>65536) throw uint32_t(120);
	if (count) {
		auto bytes=process.read_memory(points,size_t(count)*8);
		for (size_t offset=0;offset<bytes.size();offset+=8) {
			put(bytes,offset,uint32_t(read(bytes,offset,4))+dx,4);
			put(bytes,offset+4,uint32_t(read(bytes,offset+4,4))+dy,4);
		}
		process.write_memory(points,bytes);
	}
	return uint16_t(dx) | (uint32_t(uint16_t(dy))<<16);
}

bool NativeWindows::dispatch(std::string_view name)
{
	if (tree_dispatch(name) || system_dispatch(name)) return true;
	const bool data=(name.starts_with("GetWindowLong") || name.starts_with("SetWindowLong") || name.starts_with("GetClassLong") || name.starts_with("SetClassLong"));
	const bool info=name=="GetClassInfoW" || name=="GetClassInfoExW" || name=="GetClassNameW" || name=="GetClassNameA";
	const bool registration=name=="RegisterClassExW" || name=="RegisterClassW";
	const bool creation=name=="CreateWindowExW";
	const bool coordinate=name=="ClientToScreen" || name=="ScreenToClient";
	const bool adjustment=name=="AdjustWindowRect" || name=="AdjustWindowRectEx";
	if (!adjustment && name!="GetSystemMetrics" && !coordinate && name!="MapWindowPoints" && !info && !data && name!="CallWindowProcW" && !registration && !creation && name!="DestroyWindow" && name!="SendMessageW" && name!="IsWindow" &&
		name!="IsWindowUnicode" && name!="UnregisterClassW" && name!="ShowWindow" && name!="GetDC" && name!="GetWindowDC" && name!="ReleaseDC" &&
		name!="UpdateWindow" && name!="IsWindowVisible" && name!="BeginPaint" && name!="EndPaint" &&
		name!="PostMessageW" && name!="PeekMessageW" && name!="GetMessageW" && name!="DispatchMessageW" &&
		name!="TranslateMessage" && name!="PostQuitMessage" && name!="DefWindowProcW" &&
		name!="GetWindowTextW" && name!="InternalGetWindowText" && name!="GetWindowTextLengthW" && name!="SetWindowTextW" &&
		name!="GetFocus" && name!="SetFocus" && name!="GetActiveWindow" && name!="GetClientRect" && name!="GetWindowRect" &&
		name!="InvalidateRect" && name!="ValidateRect" && name!="GetUpdateRect") return false;
	const auto args=process.api_arguments(adjustment ? (name=="AdjustWindowRectEx" ? 4 : 3) : coordinate ? 2 : name=="MapWindowPoints" ? 4 : info ? 3 : data ? (name.starts_with("Set") ? 3 : 2) : name=="CallWindowProcW" ? 5 : registration ? 1 : creation ? 12 : name=="SendMessageW" ? 4 :
		name=="PostMessageW" || name=="GetMessageW" || name=="DefWindowProcW" ? 4 : name=="PeekMessageW" ? 5 :
		name=="GetWindowTextW" || name=="InternalGetWindowText" || name=="InvalidateRect" || name=="GetUpdateRect" ? 3 :
		name=="SetWindowTextW" || name=="GetClientRect" || name=="GetWindowRect" || name=="ValidateRect" ? 2 :
		name=="UnregisterClassW" || name=="ShowWindow" || name=="ReleaseDC" || name=="BeginPaint" || name=="EndPaint" ? 2 : 1);
	uint64_t result=name=="GetMessageW" ? UINT64_MAX : 0;
	try {
		if (name=="GetSystemMetrics") {
			const auto index=int32_t(uint32_t(args[0]));
			if (index==11 || index==12) {
				const auto display=objects.display();result=index==11 ? display.width : display.height;
				if (result>INT32_MAX) throw uint32_t(120);
			} else result=uint32_t(objects.nonclient_metrics().get(index));
		}
		else if (adjustment) {
			const auto bytes=process.read_memory(args[0],16);
			const DesktopRect rect{int32_t(read(bytes,0,4)),int32_t(read(bytes,4,4)),int32_t(read(bytes,8,4)),int32_t(read(bytes,12,4))};
			const auto adjusted=adjust_window_rect(objects.nonclient_metrics(),rect,uint32_t(args[1]),uint32_t(args[2])!=0,name=="AdjustWindowRectEx" ? uint32_t(args[3]) : 0);
			std::array<uint8_t,16> output{};
			put(output,0,uint32_t(adjusted.left),4); put(output,4,uint32_t(adjusted.top),4);
			put(output,8,uint32_t(adjusted.right),4); put(output,12,uint32_t(adjusted.bottom),4);
			process.write_memory(args[0],output); result=1;
		} else if (coordinate) {
			if (!objects.window(args[0])) throw uint32_t(1400);
			map_points(name=="ClientToScreen" ? args[0] : 0,name=="ScreenToClient" ? args[0] : 0,args[1],1);
			result=1;
		} else if (name=="MapWindowPoints") result=map_points(args[0],args[1],args[2],uint32_t(args[3]));
		else if (info) result=class_info(name,args);
		else if (data) result=long_value(name,args);
		else if (name=="CallWindowProcW") {
			if (!args[0] || !invoke) throw uint32_t(120);
			const auto called=invoke(args[0],std::span<const uint64_t>(args).subspan(1));
			if (called.stop!=NativeStop::returned) throw called;
			result=called.value;
		}
		else if (name=="GetFocus") result=focus;
		else if (name=="GetActiveWindow") result=active;
		else if (name=="SetFocus") result=set_focus(args[0]);
		else if (name=="InvalidateRect" || name=="ValidateRect") {
			if (!args[0]) throw uint32_t(120);
			const auto rect=update_rect(args[0],args[1]);
			if (!(name=="InvalidateRect" ? objects.invalidate(args[0],rect,args[2]!=0) : objects.validate(args[0],rect))) throw uint32_t(8);
			result=1;
		} else if (name=="GetUpdateRect") {
			const auto *window=objects.window(args[0]); if (!window) throw uint32_t(1400);
			if (args[2]) throw uint32_t(120);
			const auto rect=window->update.bounds();
			if (args[1]) {
				std::array<uint8_t,16> bytes{};
				put(bytes,0,uint32_t(rect.left),4); put(bytes,4,uint32_t(rect.top),4);
				put(bytes,8,uint32_t(rect.right),4); put(bytes,12,uint32_t(rect.bottom),4);
				process.write_memory(args[1],bytes);
			}
			result=!window->update.empty();
		}
		else if (name=="GetClientRect" || name=="GetWindowRect") {
			const auto *window=objects.window(args[0]); if (!window) throw uint32_t(1400);
			const auto bounds=name=="GetClientRect" ? DesktopRect{0,0,window->width,window->height} : window->outer;
			std::array<uint8_t,16> rect{};
			put(rect,0,uint32_t(bounds.left),4); put(rect,4,uint32_t(bounds.top),4);
			put(rect,8,uint32_t(bounds.right),4); put(rect,12,uint32_t(bounds.bottom),4);
			process.write_memory(args[1],rect); result=1;
		}
		else if (name=="DefWindowProcW") result=default_message(args);
		else if (name=="GetWindowTextLengthW") result=send(args[0],0x0e,0,0);
		else if (name=="SetWindowTextW") result=send(args[0],0x0c,0,args[1]);
		else if (name=="GetWindowTextW") {
			if (int32_t(args[2])>0) result=send(args[0],0x0d,uint32_t(args[2]),args[1]);
		}
		else if (name=="InternalGetWindowText") {
			if (int32_t(args[2])>0) result=copy_window_text(args[0],args[1],uint32_t(args[2]));
		}
		else if (name=="PostMessageW") { post(args[0],uint32_t(args[1]),args[2],args[3]); result=1; }
		else if (name=="PostQuitMessage") { quit=uint32_t(args[0]); }
		else if (name=="PeekMessageW" || name=="GetMessageW") result=retrieve(args,name=="GetMessageW");
		else if (name=="DispatchMessageW" || name=="TranslateMessage") {
			const auto layout=message_layout(process.mode()==NativeMode::x86);
			const auto bytes=process.read_memory(args[0],layout.size);
			const auto message=uint32_t(read(bytes,layout.message,4));
			if (name=="TranslateMessage") {
				if (message==0x100 || message==0x101) {
					if (!key_translation || key_translation->window!=read(bytes,0,layout.pointer) || key_translation->message!=message ||
						key_translation->wparam!=read(bytes,layout.wparam,layout.pointer) || key_translation->lparam!=read(bytes,layout.lparam,layout.pointer) ||
						key_translation->time!=read(bytes,layout.time,4))
						throw std::runtime_error("keyboard translation requires the current retrieved key message");
					const auto key=*key_translation;
					if (message==0x100 && key.character) {
						const auto units=key.character>0xffff ? 2U : 1U;
						if (messages.size()>10000-units) throw std::runtime_error("guest character queue limit reached");
						if (units==2) {
							const auto value=key.character-0x10000;
							messages.push_back({key.window,0xd800+(value>>10),key.lparam,0x102,key.time,key.x,key.y});
							try { messages.push_back({key.window,0xdc00+(value & 0x3ff),key.lparam,0x102,key.time,key.x,key.y}); }
							catch (...) { messages.pop_back(); throw; }
						} else messages.push_back({key.window,key.character,key.lparam,0x102,key.time,key.x,key.y});
					}
					result=1;
				} else if (message>=0x100 && message<=0x109) throw uint32_t(120);
			} else if (read(bytes,0,layout.pointer)) {
				const auto target=read(bytes,0,layout.pointer);
				if (message==0x113 && read(bytes,layout.lparam,layout.pointer)) {
					// A timer with its own callback bypasses the window procedure.
					if (!invoke) throw std::runtime_error("native window callbacks are not connected");
					const uint64_t arguments[]{target,0x113,read(bytes,layout.wparam,layout.pointer),read(bytes,layout.time,4)};
					const auto called=invoke(read(bytes,layout.lparam,layout.pointer),arguments);
					if (called.stop!=NativeStop::returned) throw called;
					result=0;
				} else
				result=send(target,message,read(bytes,layout.wparam,layout.pointer),read(bytes,layout.lparam,layout.pointer));
			}
		}
		else if (registration) {
			const bool extended=name=="RegisterClassExW";
			const bool narrow=process.mode()==NativeMode::x86;
			const size_t P=narrow ? 4 : 8;
			// WNDCLASSW fields follow style at 0; the 32-bit WNDCLASSEXW shifts all of them by its cbSize.
			const size_t shift=narrow && extended ? 4 : 0;
			const size_t size=narrow ? (extended ? 48 : 40) : (extended ? 80 : 72);
			const auto bytes=process.read_memory(args[0],size);
			if (extended && read(bytes,0,4)!=size) throw uint32_t(87);
			const auto style=uint32_t(read(bytes,extended ? 4 : 0,4));
			if ((style & ~0x4000U) || (extended && read(bytes,8*P+8+shift,P)))
				throw uint32_t(120);
			const auto icon=read(bytes,3*P+8+shift,P),cursor=read(bytes,4*P+8+shift,P),menu_name=read(bytes,6*P+8+shift,P);
			const bool stock_cursor=cursor>=desktop_stock_cursor && cursor<desktop_stock_cursor+desktop_stock_cursor_count;
			if ((icon && !objects.icon(icon)) || (cursor && !stock_cursor)) throw uint32_t(1402);
			const auto class_extra=int32_t(uint32_t(read(bytes,2*P+shift,4))),window_extra=int32_t(uint32_t(read(bytes,2*P+4+shift,4)));
			if (class_extra<0 || window_extra<0) throw uint32_t(87);
			if (class_extra>4096 || window_extra>4096) throw uint32_t(120);
			const auto background=read(bytes,5*P+8+shift,P);
			if (background && background>31 && !objects.brush(background)) throw uint32_t(background<=32 ? 120 : 6);
			const auto procedure=read(bytes,P+shift,P), instance=read(bytes,2*P+8+shift,P);
			auto class_name=text(read(bytes,7*P+8+shift,P));
			if (!procedure || class_name.empty()) throw uint32_t(87);
			if (objects.class_registered(instance,class_name,(style & 0x4000)!=0)) throw uint32_t(1410);
			DesktopClass definition{std::move(class_name),instance,procedure,background,uint32_t(window_extra),std::vector<uint8_t>(size_t(class_extra)),style};
			definition.icon=icon; definition.cursor=cursor;
			if (menu_name && menu_name<=UINT16_MAX) definition.menu_id=uint32_t(menu_name);
			else if (menu_name) definition.menu_name=window_text(menu_name);
			const auto id=objects.register_class(std::move(definition));
			if (!id) throw uint32_t(8);
			result=objects.window_class(id)->atom;
		} else if (creation) result=create(args);
		else if (name=="SendMessageW") result=send(args[0],uint32_t(args[1]),args[2],args[3]);
		else if (name=="DestroyWindow") result=destroy(args[0]);
		else if (name=="GetDC" || name=="GetWindowDC") {
			// A null window selects the screen, which is the desktop window's surface.
			const auto target=args[0] ? args[0] : desktop_window();
			surface_dc(target);
			const auto *window=objects.window(target);
			DesktopDC device{window->bitmap,window->bitmap,target}; device.leased=true;
			objects.configure_window_dc(target,device,name=="GetWindowDC");
			result=objects.add(device);
			if (!result) throw uint32_t(8);
		}
		else if (name=="BeginPaint") {
			auto *window=objects.window(args[0]); if (!window) throw uint32_t(1400);
			if (window->painting) throw uint32_t(170);
			const bool narrow=process.mode()==NativeMode::x86;
			const size_t P=narrow ? 4 : 8;
			const auto old=process.read_memory(args[1],narrow ? 64 : 72); process.write_memory(args[1],old);
			const auto paint=start_paint(args[0]);
			std::vector<uint8_t> output(old.size());
			put(output,0,paint.dc,P); put(output,P,paint.erase,4);
			put(output,P+4,uint32_t(paint.rect.left),4); put(output,P+8,uint32_t(paint.rect.top),4);
			put(output,P+12,uint32_t(paint.rect.right),4); put(output,P+16,uint32_t(paint.rect.bottom),4);
			process.write_memory(args[1],output); result=paint.dc;
		} else if (name=="EndPaint") {
			auto *window=objects.window(args[0]); if (!window) throw uint32_t(1400);
			const bool narrow=process.mode()==NativeMode::x86;
			const auto paint=process.read_memory(args[1],narrow ? 64 : 72);
			if (!window->painting || read(paint,0,narrow ? 4 : 8)!=window->dc) throw uint32_t(87);
			objects.finish_paint(args[0]);
			if (objects.window_visible(args[0])) present(args[0]);
			result=1;
		}
		else if (name=="ReleaseDC") {
			const auto owner=args[0] ? args[0] : desktop_window();
			const auto *window=objects.window(owner);
			const auto *device=objects.dc(args[1]);
			if (window) {
				if (!device || !device->leased || device->window!=owner) throw uint32_t(1400);
				result=objects.erase(args[1]);
			}
		} else if (name=="IsWindowVisible") {
			result=objects.window_visible(args[0]);
		} else if (name=="ShowWindow") {
			auto *window=objects.window(args[0]); if (!window) throw uint32_t(1400);
			// SW_HIDE, SW_SHOWNORMAL, SW_SHOWNOACTIVATE, SW_SHOW, SW_SHOWNA and SW_SHOWDEFAULT; minimize/maximize states are not modeled.
			const auto command=uint32_t(args[1]);
			if (command!=0 && command!=1 && command!=4 && command!=5 && command!=8 && command!=10) throw uint32_t(120);
			const auto previous=window->visible;
			const bool show=command!=0;
			if (show && (!window->parent || objects.window_visible(window->parent))) present(args[0]);
			else if (!show && previous && !window->parent && presentation.remove) presentation.remove(args[0]);
			window=objects.window(args[0]); window->visible=show;
			window->style=(window->style & ~0x10000000U) | (window->visible ? 0x10000000U : 0);
			objects.update_window_dcs(args[0]);
			if (window->visible && !objects.invalidate(args[0],{0,0,window->width,window->height},true)) throw uint32_t(8);
			// Showing a top-level window with an activating command also gives it the active state and keyboard focus.
			if (show && !window->parent && (command==1 || command==5 || command==10) && objects.window(args[0])) set_focus(args[0]);
			window=objects.window(args[0]);if (!window) throw uint32_t(1400);
			if (!window->visible && previous && window->parent) {
				const auto *parent=objects.window(window->parent);
				if (!objects.invalidate(window->parent,{window->outer.left-parent->x,window->outer.top-parent->y,window->outer.right-parent->x,window->outer.bottom-parent->y},true)) throw uint32_t(8);
			}
			result=previous;
		} else if (name=="UpdateWindow") {
			if (!objects.window(args[0])) throw uint32_t(1400);
			if (!objects.window(args[0])->update.empty()) send(args[0],0x0f,0,0);
			result=1;
		}
		else if (name=="UnregisterClassW") {
			const auto error=objects.unregister_class(atom(args[0],args[1]));
			if (error) throw error;
			result=1;
		} else result=objects.window(args[0])!=nullptr;
	} catch (uint32_t error) { environment.set_last_error(error); }
	catch (const std::bad_alloc &) { environment.set_last_error(8); }
	catch (const std::runtime_error &failure) {
		const std::string_view message=failure.what();
		if (message.find("readable")==message.npos && message.find("writable")==message.npos) throw;
		environment.set_last_error(998);
	}
	process.return_api(result);
	return true;
}

}
