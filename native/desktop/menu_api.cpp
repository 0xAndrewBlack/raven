#include "api.h"

#include <new>
#include <stdexcept>

namespace raven {

uint64_t NativeDesktop::menu_resource(uint64_t instance,uint64_t identifier)
{
	const auto view=resources.view(instance,4,identifier);
	if (!view || view->size>1024*1024) return 0;
	try {
		return objects.load_menu(decode_menu(process.read_memory(view->address,view->size)));
	} catch (const std::runtime_error &) {
		return 0;
	}
}

bool NativeDesktop::menu_dispatch(std::string_view name)
{
	const bool load=name=="LoadMenuW",count=name=="GetMenuItemCount",id=name=="GetMenuItemID",sub=name=="GetSubMenu";
	if (!load && !count && !id && !sub && name!="DestroyMenu" && name!="IsMenu") return false;
	const auto args=process.api_arguments(load || id || sub ? 2 : 1);
	uint64_t result=count || id ? UINT32_MAX : 0;
	try {
		if (load) {
			const auto view=resources.view(args[0],4,args[1]);
			if (view) {
				if (view->size>1024*1024) throw uint32_t(120);
				const auto bytes=process.read_memory(view->address,view->size);
				MenuTemplate definition;
				try { definition=decode_menu(bytes); }
				catch (const std::runtime_error &) { throw uint32_t(13); }
				result=objects.load_menu(definition);
			}
		} else {
			const auto *menu=objects.menu(args[0]);
			if (name=="IsMenu") result=menu!=nullptr;
			else if (menu && count) result=menu->items.size();
			else if (menu && name=="DestroyMenu") {
				// Attached submenu mutation needs the parent-item transition contract.
				if (menu->parent) throw uint32_t(120);
				result=objects.erase(args[0]);
			} else if (menu) {
				const auto position=int32_t(uint32_t(args[1]));
				if (position>=0 && size_t(position)<menu->items.size()) {
					const auto &item=menu->items[size_t(position)];
					result=sub ? item.submenu : item.submenu ? UINT32_MAX : item.id;
				}
			}
		}
	} catch (uint32_t error) { environment.set_last_error(error); }
	catch (const std::bad_alloc &) { environment.set_last_error(8); }
	process.return_api(result);
	return true;
}

}
