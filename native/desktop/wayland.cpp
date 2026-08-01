#include "wayland.h"
#include "xdg-shell-client-protocol.h"

#include <wayland-client.h>
#include <algorithm>
#include <chrono>
#include <fcntl.h>
#include <optional>
#include <set>
#include <string>
#include <cstring>
#include <map>
#include <poll.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace raven {

struct WaylandPresentation::State {
	struct Buffer {
		wl_buffer *proxy=nullptr;
		void *pixels=MAP_FAILED;
		size_t size=0;
		bool released=false;
		~Buffer() { if (proxy) wl_buffer_destroy(proxy); if (pixels!=MAP_FAILED) munmap(pixels,size); }
	};
	struct Surface {
		wl_surface *proxy=nullptr;
		xdg_surface *shell=nullptr;
		xdg_toplevel *role=nullptr;
		xdg_popup *popup=nullptr;
		bool is_popup=false;
		bool configured=false, closed=false, resized=false, close_posted=false, first_frame=false;
		uint32_t width=0,height=0,pending_width=0,pending_height=0;
		std::vector<std::unique_ptr<Buffer>> buffers;
		// A surface a graphics driver renders to, stacked over the client area.
		wl_surface *child=nullptr;
		wl_subsurface *child_role=nullptr;
		void drop_child() {
			if (child_role) wl_subsurface_destroy(child_role);
			if (child) wl_surface_destroy(child);
			child_role=nullptr; child=nullptr;
		}
		~Surface() {
			drop_child();
			if (popup) xdg_popup_destroy(popup);
			if (role) xdg_toplevel_destroy(role);
			if (shell) xdg_surface_destroy(shell);
			if (proxy) wl_surface_destroy(proxy);
		}
	};
	wl_display *display=nullptr;
	wl_registry *registry=nullptr;
	wl_compositor *compositor=nullptr;
	wl_subcompositor *subcompositor=nullptr;
	wl_shm *shm=nullptr;
	xdg_wm_base *shell=nullptr;
	wl_seat *seat=nullptr;
	wl_pointer *pointer=nullptr;
	wl_keyboard *keyboard=nullptr;
	uint64_t pointer_window=0;
	uint64_t keyboard_window=0;
	int32_t pointer_x=0,pointer_y=0;
	bool input_failed=false;
	// Serial of the newest input event; popup grabs must quote one.
	uint32_t last_serial=0;
	const char *input_error="unsupported native input event or input queue exhaustion";
	std::vector<DesktopEvent> pending;
	// Host selection: text offered by other clients is fetched on demand, text from the guest is served to whoever asks.
	wl_data_device_manager *data_manager=nullptr;
	wl_data_device *data_device=nullptr;
	wl_data_source *data_source=nullptr;
	std::string source_text;
	std::map<wl_data_offer *,std::set<std::string>> offer_mimes;
	wl_data_offer *selection_offer=nullptr;
	uint64_t selection_counter=0;
	std::map<uint64_t,std::unique_ptr<Surface>> surfaces;

	~State() {
		surfaces.clear();
		if (data_source) wl_data_source_destroy(data_source);
		if (selection_offer) wl_data_offer_destroy(selection_offer);
		if (data_device) wl_data_device_destroy(data_device);
		if (data_manager) wl_data_device_manager_destroy(data_manager);
		if (pointer) wl_pointer_destroy(pointer);
		if (keyboard) wl_keyboard_destroy(keyboard);
		if (seat) wl_seat_destroy(seat);
		if (shell) xdg_wm_base_destroy(shell);
		if (shm) wl_shm_destroy(shm);
		if (subcompositor) wl_subcompositor_destroy(subcompositor);
		if (compositor) wl_compositor_destroy(compositor);
		if (registry) wl_registry_destroy(registry);
		if (display) { wl_display_flush(display); wl_display_disconnect(display); }
	}

	int64_t wheel_remainder=0,horizontal_remainder=0;

	void pointer_event(DesktopEventKind kind,uint32_t button=0,uint32_t pressed=0) {
		if (!pointer_window && kind==DesktopEventKind::pointer_motion) return;
		if (pending.size()>=10000) { input_failed=true; return; }
		try { pending.push_back({pointer_window,button,pressed,0,kind,pointer_x,pointer_y}); }
		catch (...) { input_failed=true; }
	}

	void keyboard_event(DesktopEvent event) {
		if (pending.size()>=10000) { input_failed=true; return; }
		try { pending.push_back(std::move(event)); } catch (...) { input_failed=true; }
	}

	void keymap_event(uint32_t format,int descriptor,uint32_t size) {
		struct stat info{};
		if (format!=WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 || !size || size>1024*1024 || fstat(descriptor,&info)<0 || info.st_size<size) {
			close(descriptor); input_failed=true; return;
		}
		const auto *mapping=static_cast<const char *>(mmap(nullptr,size,PROT_READ,MAP_PRIVATE,descriptor,0)); close(descriptor);
		if (mapping==MAP_FAILED) { input_failed=true; return; }
		try {
			size_t bytes=0; for (const auto &event : pending) bytes+=event.keymap.size();
			if (mapping[size-1] || bytes+size>4*1024*1024) input_failed=true;
			else { DesktopEvent event{0,0}; event.kind=DesktopEventKind::keymap; event.keymap.assign(mapping,size-1); keyboard_event(std::move(event)); }
		} catch (...) { input_failed=true; }
		munmap(const_cast<char *>(mapping),size);
	}

	static int32_t coordinate(wl_fixed_t value) {
		return value>=0 ? value/256 : int32_t(-((-int64_t(value)+255)/256));
	}

	static void capabilities(void *data,wl_seat *seat,uint32_t flags) {
		auto &state=*static_cast<State *>(data);
		if ((flags & WL_SEAT_CAPABILITY_POINTER) && !state.pointer) {
			state.pointer=wl_seat_get_pointer(seat);
			static const auto listener=[] {
				wl_pointer_listener value{};
				value.enter=[](void *data,wl_pointer *,uint32_t serial,wl_surface *surface,wl_fixed_t x,wl_fixed_t y) {
					auto &state=*static_cast<State *>(data); state.pointer_window=0; state.last_serial=serial;
					for (const auto &[handle,window] : state.surfaces) if (window->proxy==surface) state.pointer_window=handle;
					state.pointer_x=coordinate(x); state.pointer_y=coordinate(y); state.pointer_event(DesktopEventKind::pointer_motion);
				};
				value.leave=[](void *data,wl_pointer *,uint32_t,wl_surface *) { static_cast<State *>(data)->pointer_window=0; };
				value.motion=[](void *data,wl_pointer *,uint32_t,wl_fixed_t x,wl_fixed_t y) {
					auto &state=*static_cast<State *>(data); state.pointer_x=coordinate(x); state.pointer_y=coordinate(y);
					state.pointer_event(DesktopEventKind::pointer_motion);
				};
				value.button=[](void *data,wl_pointer *,uint32_t serial,uint32_t,uint32_t button,uint32_t pressed) {
					static_cast<State *>(data)->last_serial=serial;
					static_cast<State *>(data)->pointer_event(DesktopEventKind::pointer_button,button,pressed);
				};
				value.axis=[](void *data,wl_pointer *,uint32_t,uint32_t axis,wl_fixed_t amount) {
					auto &state=*static_cast<State *>(data);
					// A notch reports about ten units. Scrolling down is positive and becomes a negative wheel delta; scrolling right keeps its sign.
					const bool horizontal=axis==WL_POINTER_AXIS_HORIZONTAL_SCROLL;
					if ((!horizontal && axis!=WL_POINTER_AXIS_VERTICAL_SCROLL) || !state.pointer_window) return;
					auto &remainder=horizontal ? state.horizontal_remainder : state.wheel_remainder;
					remainder+=(horizontal ? 1 : -1)*int64_t(amount)*120/(10*256);
					const auto delta=int32_t(remainder/120)*120;
					remainder-=delta;
					if (delta) state.pointer_event(DesktopEventKind::pointer_wheel,uint32_t(delta),horizontal ? 1 : 0);
				};
				return value;
			}();
			wl_pointer_add_listener(state.pointer,&listener,&state);
		} else if (!(flags & WL_SEAT_CAPABILITY_POINTER) && state.pointer) {
			wl_pointer_destroy(state.pointer); state.pointer=nullptr; state.pointer_window=0;
		}
		if ((flags & WL_SEAT_CAPABILITY_KEYBOARD) && !state.keyboard) {
			state.keyboard=wl_seat_get_keyboard(seat);
			static const auto listener=[] {
				wl_keyboard_listener value{};
				value.keymap=[](void *data,wl_keyboard *,uint32_t format,int32_t descriptor,uint32_t size) {
					static_cast<State *>(data)->keymap_event(format,descriptor,size);
				};
				value.enter=[](void *data,wl_keyboard *,uint32_t,wl_surface *surface,wl_array *keys) {
					auto &state=*static_cast<State *>(data);
					if (keys->size%sizeof(uint32_t) || keys->size>256*sizeof(uint32_t) || (keys->size && !keys->data)) {
						state.input_error="invalid native keyboard focus key array"; state.input_failed=true; return;
					}
					state.keyboard_window=0;
					for (const auto &[handle,window] : state.surfaces) if (window->proxy==surface) state.keyboard_window=handle;
					if (!state.keyboard_window) { state.input_error="keyboard entered an unknown native surface"; state.input_failed=true; return; }
					DesktopEvent event{state.keyboard_window,0,0,0,DesktopEventKind::keyboard_focus};
					try {
						event.held_keys.resize(keys->size/sizeof(uint32_t));
						if (keys->size) std::memcpy(event.held_keys.data(),keys->data,keys->size);
					} catch (...) { state.input_error="cannot retain native keyboard focus keys"; state.input_failed=true; return; }
					state.keyboard_event(std::move(event));
				};
				value.leave=[](void *data,wl_keyboard *,uint32_t,wl_surface *) {
					auto &state=*static_cast<State *>(data); state.keyboard_window=0;
					state.keyboard_event({0,0,0,0,DesktopEventKind::keyboard_focus});
				};
				value.key=[](void *data,wl_keyboard *,uint32_t serial,uint32_t,uint32_t key,uint32_t pressed) {
					auto &state=*static_cast<State *>(data);
					state.last_serial=serial;
					state.keyboard_event({state.keyboard_window,key,pressed,0,DesktopEventKind::key});
				};
				value.modifiers=[](void *data,wl_keyboard *,uint32_t,uint32_t depressed,uint32_t latched,uint32_t locked,uint32_t group) {
					static_cast<State *>(data)->keyboard_event({0,depressed,latched,uint64_t(locked)|(uint64_t(group)<<32),DesktopEventKind::modifiers});
				};
				return value;
			}();
			wl_keyboard_add_listener(state.keyboard,&listener,&state);
		} else if (!(flags & WL_SEAT_CAPABILITY_KEYBOARD) && state.keyboard) {
			wl_keyboard_destroy(state.keyboard); state.keyboard=nullptr;
			state.keyboard_window=0;
			state.keyboard_event({0,0,0,0,DesktopEventKind::keyboard_focus});
			state.keyboard_event({0,0,0,0,DesktopEventKind::modifiers});
		}
	}

	static constexpr const char *text_mimes[]={"text/plain;charset=utf-8","text/plain;charset=UTF-8","UTF8_STRING","text/plain"};

	void make_data_device() {
		if (data_device || !data_manager || !seat) return;
		data_device=wl_data_device_manager_get_data_device(data_manager,seat);
		static const wl_data_device_listener listener{
			[](void *data,wl_data_device *,wl_data_offer *offer) {
				auto &state=*static_cast<State *>(data);
				state.offer_mimes[offer].clear();
				static const wl_data_offer_listener offers{[](void *data,wl_data_offer *offer,const char *mime) {
					static_cast<State *>(data)->offer_mimes[offer].insert(mime);
				},nullptr,nullptr};
				wl_data_offer_add_listener(offer,&offers,&state);
			},
			nullptr,nullptr,nullptr,nullptr,
			[](void *data,wl_data_device *,wl_data_offer *offer) {
				auto &state=*static_cast<State *>(data);
				if (state.selection_offer && state.selection_offer!=offer) { state.offer_mimes.erase(state.selection_offer); wl_data_offer_destroy(state.selection_offer); }
				state.selection_offer=offer; ++state.selection_counter;
			}};
		wl_data_device_add_listener(data_device,&listener,this);
	}

	void publish_text(std::string_view text) {
		if (!data_device || !data_manager) return;
		if (data_source) { wl_data_source_destroy(data_source); data_source=nullptr; }
		source_text.assign(text);
		data_source=wl_data_device_manager_create_data_source(data_manager);
		static const wl_data_source_listener listener{
			nullptr,
			[](void *data,wl_data_source *,const char *,int32_t descriptor) {
				auto &state=*static_cast<State *>(data);
				size_t done=0;
				while (done<state.source_text.size()) {
					const auto wrote=write(descriptor,state.source_text.data()+done,state.source_text.size()-done);
					if (wrote<=0) break;
					done+=size_t(wrote);
				}
				close(descriptor);
			},
			[](void *data,wl_data_source *source) {
				auto &state=*static_cast<State *>(data);
				if (state.data_source==source) state.data_source=nullptr;
				wl_data_source_destroy(source);
			},nullptr,nullptr,nullptr};
		wl_data_source_add_listener(data_source,&listener,this);
		for (const auto *mime : text_mimes) wl_data_source_offer(data_source,mime);
		wl_data_device_set_selection(data_device,data_source,last_serial);
		wl_display_flush(display);
	}

	std::optional<std::pair<uint64_t,std::string>> fetch_text() {
		if (!data_device || !selection_offer || data_source) return std::nullopt;
		const auto known=offer_mimes.find(selection_offer);
		if (known==offer_mimes.end()) return std::nullopt;
		const char *mime=nullptr;
		for (const auto *wanted : text_mimes) if (known->second.contains(wanted)) { mime=wanted; break; }
		if (!mime) return std::nullopt;
		int pipes[2];
		if (pipe2(pipes,O_CLOEXEC)<0) return std::nullopt;
		wl_data_offer_receive(selection_offer,mime,pipes[1]);
		close(pipes[1]);
		wl_display_flush(display);
		std::string text;
		const auto limit=std::chrono::steady_clock::now()+std::chrono::seconds(2);
		for (;;) {
			pollfd entry{pipes[0],POLLIN,0};
			const auto left=std::chrono::duration_cast<std::chrono::milliseconds>(limit-std::chrono::steady_clock::now()).count();
			if (left<=0 || ::poll(&entry,1,int(left))<=0) break;
			char buffer[4096];
			const auto count=read(pipes[0],buffer,sizeof buffer);
			if (count<=0) break;
			text.append(buffer,size_t(count));
			if (text.size()>(16U<<20)) break;
		}
		close(pipes[0]);
		return std::make_pair(selection_counter,std::move(text));
	}

	static void global(void *data,wl_registry *registry,uint32_t name,const char *interface,uint32_t version) {
		auto &state=*static_cast<State *>(data);
		if (!std::strcmp(interface,"wl_compositor")) state.compositor=static_cast<wl_compositor *>(wl_registry_bind(registry,name,&wl_compositor_interface,std::min(version,4U)));
		else if (!std::strcmp(interface,"wl_subcompositor")) state.subcompositor=static_cast<wl_subcompositor *>(wl_registry_bind(registry,name,&wl_subcompositor_interface,1));
		else if (!std::strcmp(interface,"wl_shm")) state.shm=static_cast<wl_shm *>(wl_registry_bind(registry,name,&wl_shm_interface,1));
		else if (!std::strcmp(interface,"wl_seat")) {
			if (state.seat) { state.input_failed=true; return; }
			state.seat=static_cast<wl_seat *>(wl_registry_bind(registry,name,&wl_seat_interface,1));
			static const wl_seat_listener listener{capabilities,nullptr};
			wl_seat_add_listener(state.seat,&listener,&state);
			state.make_data_device();
		}
		else if (!std::strcmp(interface,"wl_data_device_manager")) {
			state.data_manager=static_cast<wl_data_device_manager *>(wl_registry_bind(registry,name,&wl_data_device_manager_interface,std::min(version,3U)));
			state.make_data_device();
		}
		else if (!std::strcmp(interface,"xdg_wm_base")) {
			state.shell=static_cast<xdg_wm_base *>(wl_registry_bind(registry,name,&xdg_wm_base_interface,1));
			static const xdg_wm_base_listener listener{[](void *,xdg_wm_base *base,uint32_t serial) { xdg_wm_base_pong(base,serial); }};
			xdg_wm_base_add_listener(state.shell,&listener,nullptr);
		}
	}

	void events(std::chrono::milliseconds budget) {
		if (wl_display_dispatch_pending(display)<0) throw std::runtime_error("Wayland event dispatch failed");
		while (wl_display_prepare_read(display)!=0)
			if (wl_display_dispatch_pending(display)<0) throw std::runtime_error("Wayland pending events failed");
		const auto flushed=wl_display_flush(display);
		pollfd socket{wl_display_get_fd(display),short(POLLIN | (flushed<0 ? POLLOUT : 0)),0};
		const auto ready=poll(&socket,1,int(budget.count()));
		if (ready<=0 || !(socket.revents & POLLIN)) wl_display_cancel_read(display);
		else if (wl_display_read_events(display)<0) throw std::runtime_error("Wayland socket read failed");
		if (ready<0 || (socket.revents & (POLLERR|POLLHUP|POLLNVAL)) || wl_display_dispatch_pending(display)<0)
			throw std::runtime_error("Wayland connection failed");
		if (input_failed) throw std::runtime_error(input_error);
	}

	void sync() {
		bool complete=false;
		wl_callback *callback=wl_display_sync(display);
		static const wl_callback_listener listener{[](void *data,wl_callback *callback,uint32_t) {
			*static_cast<bool *>(data)=true; wl_callback_destroy(callback);
		}};
		wl_callback_add_listener(callback,&listener,&complete);
		const auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2);
		try {
			while (!complete && std::chrono::steady_clock::now()<end) events(std::chrono::milliseconds(20));
		} catch (...) { if (!complete) wl_callback_destroy(callback); throw; }
		if (!complete) { wl_callback_destroy(callback); throw std::runtime_error("Wayland synchronization timed out"); }
	}

	void connect() {
		if (display) {
			if (!compositor || !shm || !shell) throw std::runtime_error("Wayland presentation connection is incomplete");
			return;
		}
		display=wl_display_connect(nullptr);
		if (!display) throw std::runtime_error("cannot connect native Wayland presentation");
		registry=wl_display_get_registry(display);
		static const wl_registry_listener listener{global,[](void *,wl_registry *,uint32_t) {}};
		wl_registry_add_listener(registry,&listener,this);
		sync();
		if (!compositor || !shm || !shell) throw std::runtime_error("Wayland compositor lacks required presentation protocols");
	}

	void attach_frame(Surface &window,uint32_t width,uint32_t height,std::span<const uint8_t> pixels) {
		events(std::chrono::milliseconds(0));
		std::erase_if(window.buffers,[](const auto &buffer) { return buffer->released; });
		if (window.buffers.size()>=3) throw std::runtime_error("Wayland presentation buffer limit reached");
		size_t used=0;
		for (const auto &[key,surface] : surfaces)
			for (const auto &buffer : surface->buffers) used+=buffer->size;
		if (used+pixels.size()>256*1024*1024) throw std::runtime_error("Wayland presentation memory limit reached");
		auto buffer=std::make_unique<Buffer>(); buffer->size=pixels.size();
		const int descriptor=int(syscall(SYS_memfd_create,"raven-frame",MFD_CLOEXEC));
		if (descriptor<0) throw std::runtime_error("Wayland frame descriptor failed");
		if (ftruncate(descriptor,off_t(buffer->size))<0) { close(descriptor); throw std::runtime_error("Wayland frame sizing failed"); }
		buffer->pixels=mmap(nullptr,buffer->size,PROT_READ|PROT_WRITE,MAP_SHARED,descriptor,0);
		if (buffer->pixels==MAP_FAILED) { close(descriptor); throw std::runtime_error("Wayland frame mapping failed"); }
		std::memcpy(buffer->pixels,pixels.data(),pixels.size());
		wl_shm_pool *pool=wl_shm_create_pool(shm,descriptor,int32_t(buffer->size)); close(descriptor);
		buffer->proxy=wl_shm_pool_create_buffer(pool,0,int32_t(width),int32_t(height),int32_t(width*4),WL_SHM_FORMAT_XRGB8888);
		wl_shm_pool_destroy(pool);
		static const wl_buffer_listener buffer_listener{[](void *data,wl_buffer *) { static_cast<Buffer *>(data)->released=true; }};
		wl_buffer_add_listener(buffer->proxy,&buffer_listener,buffer.get());
		wl_surface_attach(window.proxy,buffer->proxy,0,0);
		wl_surface_damage(window.proxy,0,0,int32_t(width),int32_t(height));
		wl_surface_commit(window.proxy); window.buffers.push_back(std::move(buffer)); sync();
		if (window.closed) throw std::runtime_error("Wayland surface was closed during presentation");
	}

	void popup_surface(uint64_t handle,uint64_t parent,int32_t x,int32_t y,uint32_t width,uint32_t height,std::span<const uint8_t> pixels) {
		if (!handle || !width || !height || width>4096 || height>4096 || pixels.size()!=size_t(width)*height*4)
			throw std::runtime_error("invalid native Wayland popup frame");
		connect();
		auto found=surfaces.find(handle);
		if (found==surfaces.end()) {
			const auto owner=surfaces.find(parent);
			if (owner==surfaces.end()) throw std::runtime_error("Wayland popup has no presented parent surface");
			auto window=std::make_unique<Surface>();
			window->width=width; window->height=height; window->is_popup=true;
			window->proxy=wl_compositor_create_surface(compositor);
			window->shell=xdg_wm_base_get_xdg_surface(shell,window->proxy);
			xdg_positioner *positioner=xdg_wm_base_create_positioner(shell);
			xdg_positioner_set_size(positioner,int32_t(width),int32_t(height));
			xdg_positioner_set_anchor_rect(positioner,x,y,1,1);
			xdg_positioner_set_anchor(positioner,XDG_POSITIONER_ANCHOR_TOP_LEFT);
			xdg_positioner_set_gravity(positioner,XDG_POSITIONER_GRAVITY_BOTTOM_RIGHT);
			window->popup=xdg_surface_get_popup(window->shell,owner->second->shell,positioner);
			xdg_positioner_destroy(positioner);
			static const xdg_surface_listener surface_listener{[](void *data,xdg_surface *surface,uint32_t serial) {
				xdg_surface_ack_configure(surface,serial); static_cast<Surface *>(data)->configured=true;
			}};
			static const xdg_popup_listener popup_listener{
				[](void *,xdg_popup *,int32_t,int32_t,int32_t,int32_t) {},
				[](void *data,xdg_popup *) { static_cast<Surface *>(data)->closed=true; },
				nullptr};
			xdg_surface_add_listener(window->shell,&surface_listener,window.get());
			xdg_popup_add_listener(window->popup,&popup_listener,window.get());
			if (seat) xdg_popup_grab(window->popup,seat,last_serial);
			wl_surface_commit(window->proxy);
			const auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2);
			while (!window->configured && !window->closed && std::chrono::steady_clock::now()<end) events(std::chrono::milliseconds(20));
			if (!window->configured || window->closed) throw std::runtime_error("Wayland popup configuration failed");
			found=surfaces.emplace(handle,std::move(window)).first;
		}
		auto &window=*found->second;
		if (!window.is_popup || window.closed || window.width!=width || window.height!=height)
			throw std::runtime_error("Wayland popup cannot accept this frame");
		attach_frame(window,width,height,pixels);
	}

	std::optional<HostSurface> host_surface(uint64_t handle,int32_t x,int32_t y) {
		const auto found=surfaces.find(handle);
		if (found==surfaces.end() || found->second->is_popup || !subcompositor) return std::nullopt;
		auto &window=*found->second;
		if (!window.child) {
			window.child=wl_compositor_create_surface(compositor);
			window.child_role=wl_subcompositor_get_subsurface(subcompositor,window.child,window.proxy);
			wl_subsurface_set_desync(window.child_role);
			// Input stays with the window: the driver's surface takes none of it.
			wl_region *none=wl_compositor_create_region(compositor);
			wl_surface_set_input_region(window.child,none);
			wl_region_destroy(none);
		}
		wl_subsurface_set_position(window.child_role,x,y);
		wl_surface_commit(window.proxy);
		wl_display_flush(display);
		return HostSurface{display,window.child};
	}

	void present(uint64_t handle,std::string_view title,uint32_t width,uint32_t height,std::span<const uint8_t> pixels) {
		if (!handle || !width || !height || width>8192 || height>8192 || uint64_t(width)*height>16*1024*1024 || pixels.size()!=size_t(width)*height*4)
			throw std::runtime_error("invalid native Wayland frame");
		connect();
		auto found=surfaces.find(handle);
		if (found==surfaces.end()) {
			auto window=std::make_unique<Surface>();
			window->width=width; window->height=height;
			window->proxy=wl_compositor_create_surface(compositor);
			window->shell=xdg_wm_base_get_xdg_surface(shell,window->proxy);
			window->role=xdg_surface_get_toplevel(window->shell);
			static const xdg_surface_listener surface_listener{[](void *data,xdg_surface *surface,uint32_t serial) {
				xdg_surface_ack_configure(surface,serial); static_cast<Surface *>(data)->configured=true;
			}};
			static const xdg_toplevel_listener role_listener{
				[](void *data,xdg_toplevel *,int32_t width,int32_t height,wl_array *) {
					auto &window=*static_cast<Surface *>(data);
					if (width>0 && height>0 && (uint32_t(width)!=window.width || uint32_t(height)!=window.height)) {
						window.pending_width=uint32_t(width); window.pending_height=uint32_t(height); window.resized=true;
					}
				}, [](void *data,xdg_toplevel *) { static_cast<Surface *>(data)->closed=true; },nullptr,nullptr};
			xdg_surface_add_listener(window->shell,&surface_listener,window.get());
			xdg_toplevel_add_listener(window->role,&role_listener,window.get());
			xdg_toplevel_set_title(window->role,std::string(title).c_str());
			xdg_toplevel_set_app_id(window->role,"raven.native");
			// The first size is fixed so the compositor places the window; it is released once the first frame is shown.
			xdg_toplevel_set_min_size(window->role,int32_t(width),int32_t(height));
			xdg_toplevel_set_max_size(window->role,int32_t(width),int32_t(height));
			wl_surface_commit(window->proxy);
			const auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2);
			while (!window->configured && !window->closed && !window->resized && std::chrono::steady_clock::now()<end) events(std::chrono::milliseconds(20));
			window->resized=false;
			window->first_frame=true;
			if (!window->configured || window->closed) throw std::runtime_error("Wayland window configuration failed");
			found=surfaces.emplace(handle,std::move(window)).first;
		}
		auto &window=*found->second;
		xdg_toplevel_set_title(window.role,std::string(title).c_str());
		// A size the compositor refused to configure (a window larger than the output) is shown clipped rather than failing the frame.
		// A frame of another size is the guest's answer to a resize: the surface follows it.
		if (window.closed) throw std::runtime_error("Wayland surface cannot accept this frame");
		if (window.pending_width==width && window.pending_height==height) window.resized=false;
		window.width=width; window.height=height;
		attach_frame(window,width,height,pixels);
		if (window.first_frame) {
			window.first_frame=false;
			xdg_toplevel_set_min_size(window.role,0,0);
			xdg_toplevel_set_max_size(window.role,0,0);
			wl_surface_commit(window.proxy);
		}
	}
};

WaylandPresentation::WaylandPresentation() : state(std::make_unique<State>()) {}
WaylandPresentation::~WaylandPresentation()=default;

DesktopPresentation WaylandPresentation::callbacks()
{
	return {[this](uint64_t handle,std::string_view title,uint32_t width,uint32_t height,std::span<const uint8_t> pixels) {
		state->present(handle,title,width,height,pixels);
	},[this](uint64_t handle) {
		if (state->pointer_window==handle) state->pointer_window=0;
		if (state->keyboard_window==handle) state->keyboard_window=0;
		std::erase_if(state->pending,[&](const DesktopEvent &event) { return event.window==handle; });
		if (state->surfaces.erase(handle) && state->display) state->sync();
	},
	[this](std::chrono::milliseconds budget) {
		std::vector<DesktopEvent> events;
		if (!state->display) { if (budget.count()>0) ::poll(nullptr,0,int(budget.count())); return events; }
		state->events(budget);
		events.swap(state->pending);
		for (auto &[handle,surface] : state->surfaces) {
			if (surface->resized && !surface->is_popup) {
				events.push_back({handle,0,0,0,DesktopEventKind::resize,int32_t(surface->pending_width),int32_t(surface->pending_height)});
				surface->resized=false;
			}
			if (surface->closed && !surface->close_posted) {
				if (surface->is_popup) events.push_back({handle,0,0,0,DesktopEventKind::popup_done});
				else events.push_back({handle,0x10});
				surface->close_posted=true;
			}
		}
		return events;
	},[this](uint64_t handle,uint64_t parent,int32_t x,int32_t y,uint32_t width,uint32_t height,std::span<const uint8_t> pixels) {
		state->popup_surface(handle,parent,x,y,width,height,pixels);
	},[this](uint64_t handle,uint32_t action) {
		const auto found=state->surfaces.find(handle);
		if (found==state->surfaces.end() || !state->seat || found->second->is_popup || !found->second->role) return;
		if (action==0) xdg_toplevel_move(found->second->role,state->seat,state->last_serial);
		else xdg_toplevel_resize(found->second->role,state->seat,state->last_serial,action);
		wl_display_flush(state->display);
	},[this](std::string_view text) { state->publish_text(text); },
	[this]() { return state->fetch_text(); },
	[this](uint64_t handle,int32_t x,int32_t y,uint32_t,uint32_t) { return state->host_surface(handle,x,y); },
	[this](uint64_t handle) {
		const auto found=state->surfaces.find(handle);
		if (found==state->surfaces.end()) return;
		found->second->drop_child();
		if (state->display) wl_display_flush(state->display);
	}};
}

}
