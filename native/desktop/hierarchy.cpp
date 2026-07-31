#include "windows.h"

#include <algorithm>
#include <stdexcept>

namespace raven {

const DesktopWindow *DesktopObjects::window(uint64_t handle) const
{
	const auto found=objects.find(handle);
	return found==objects.end() ? nullptr : std::get_if<DesktopWindow>(&found->second);
}

uint64_t DesktopObjects::window_root(uint64_t handle) const
{
	for (unsigned depth=0;depth<64;++depth) {
		const auto *record=window(handle);
		if (!record) return 0;
		if (!record->parent) return handle;
		handle=record->parent;
	}
	throw std::runtime_error("window ancestry exceeds its owner limit");
}

std::vector<uint64_t> DesktopObjects::child_windows(uint64_t parent) const
{
	std::vector<std::pair<uint64_t,uint64_t>> found;
	for (const auto &[handle,object]:objects)
		if (const auto *record=std::get_if<DesktopWindow>(&object); record && record->parent==parent) found.emplace_back(record->order,handle);
	std::sort(found.begin(),found.end());
	std::vector<uint64_t> result;
	for (const auto &item:found) result.push_back(item.second);
	return result;
}

void DesktopObjects::restack(uint64_t handle,bool top)
{
	auto *record=window(handle);
	if (!record) return;
	const auto siblings=child_windows(record->parent);
	if (siblings.empty()) return;
	if (top) record->order=++next_order;
	else record->order=window(siblings.front())->order>0 ? window(siblings.front())->order-1 : 0;
	if (!top && record->order==0) for (const auto sibling:siblings) if (sibling!=handle) ++window(sibling)->order;
}

bool DesktopObjects::is_child(uint64_t parent,uint64_t child) const
{
	if (!parent || !child || parent==child) return false;
	for (unsigned depth=0;depth<64;++depth) {
		const auto *record=window(child);
		if (!record || !record->parent) return false;
		if (record->parent==parent) return true;
		child=record->parent;
	}
	throw std::runtime_error("window ancestry exceeds its owner limit");
}

bool DesktopObjects::window_visible(uint64_t handle) const
{
	for (unsigned depth=0;depth<64;++depth) {
		const auto *record=window(handle);
		if (!record || !record->visible) return false;
		if (!record->parent) return true;
		handle=record->parent;
	}
	throw std::runtime_error("window ancestry exceeds its owner limit");
}

void DesktopObjects::configure_window_dc(uint64_t handle,DesktopDC &device,bool frame) const
{
	const auto *record=window(handle),*root=window(window_root(handle));
	if (!record || !root) throw uint32_t(1400);
	device.window_frame=frame;
	if (record->parent && !window_visible(handle)) { device.bounds=DesktopRect{};return; }
	const auto x=frame ? record->outer.left : record->x,y=frame ? record->outer.top : record->y;
	const auto dx=int64_t(x)-root->outer.left,dy=int64_t(y)-root->outer.top;
	if (dx<INT32_MIN || dx>INT32_MAX || dy<INT32_MIN || dy>INT32_MAX) throw uint32_t(120);
	device.origin_x=int32_t(dx);device.origin_y=int32_t(dy);
	if (frame && !record->parent) { device.bounds.reset();return; }
	int64_t left=0,top=0,right=frame ? int64_t(record->outer.right)-x : record->width;
	int64_t bottom=frame ? int64_t(record->outer.bottom)-y : record->height;
	for (auto parent=record->parent;parent;) {
		const auto *ancestor=window(parent);if (!ancestor) throw uint32_t(1400);
		left=std::max(left,int64_t(ancestor->x)-x);top=std::max(top,int64_t(ancestor->y)-y);
		right=std::min(right,int64_t(ancestor->x)+ancestor->width-x);bottom=std::min(bottom,int64_t(ancestor->y)+ancestor->height-y);
		parent=ancestor->parent;
	}
	device.bounds=right<=left || bottom<=top ? DesktopRect{} : DesktopRect{int32_t(left),int32_t(top),int32_t(right),int32_t(bottom)};
}

bool NativeWindows::tree_dispatch(std::string_view name)
{
	if (name!="GetParent" && name!="GetDlgItem" && name!="GetDlgCtrlID" && name!="IsChild") return false;
	const auto args=process.api_arguments(name=="GetParent" || name=="GetDlgCtrlID" ? 1 : 2);
	uint64_t result=0;
	const auto *record=objects.window(args[0]);
	if (name=="IsChild") result=objects.is_child(args[0],args[1]);
	else if (!record) environment.set_last_error(1400);
	else if (name=="GetParent") result=record->parent;
	else if (name=="GetDlgCtrlID") result=uint32_t(record->child_id);
	else for (const auto child:objects.child_windows(args[0]))
		if (uint32_t(objects.window(child)->child_id)==uint32_t(args[1])) { result=child;break; }
	process.return_api(result);return true;
}

void NativeWindows::parent_notify(uint64_t handle,uint32_t message)
{
	const auto *record=objects.window(handle);
	if (!record || !record->parent || (record->ex_style & 4)) return;
	const auto parent=record->parent;
	if (!objects.window(parent) || objects.window(parent)->destroying) return;
	send(parent,0x210,message | (uint64_t(uint16_t(record->child_id))<<16),handle);
}

void NativeWindows::discard_tree(uint64_t handle)
{
	for (const auto child:objects.child_windows(handle)) discard_tree(child);
	release_surface(handle);objects.erase(handle);
}

void NativeWindows::reject_tree(uint64_t handle)
{
	auto *record=objects.window(handle);if (!record) return;
	record->destroying=true;record->visible=false;record->style&=~0x10000000U;
	for (const auto child:objects.child_windows(handle)) if (objects.window(child)) reject_tree(child);
	if (objects.window(handle)) send(handle,0x82,0,0);
	release_surface(handle);objects.erase(handle);
}

uint64_t NativeWindows::pointer_child(uint64_t handle,int32_t x,int32_t y)
{
	const auto *parent=objects.window(handle);if (!parent) return 0;
	if (x<parent->x || y<parent->y || int64_t(x)>=int64_t(parent->x)+parent->width || int64_t(y)>=int64_t(parent->y)+parent->height) return handle;
	const auto children=objects.child_windows(handle);
	for (auto child=children.rbegin();child!=children.rend();++child) {
		const auto *record=objects.window(*child);
		if (record && objects.window_visible(*child) && x>=record->outer.left && y>=record->outer.top && x<record->outer.right && y<record->outer.bottom)
			return pointer_child(*child,x,y);
	}
	return handle;
}

}
