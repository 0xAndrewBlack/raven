#pragma once
#include "region.h"

namespace raven {

struct DesktopMetrics {
	int32_t border_x=1,border_y=1,dialog_x=3,dialog_y=3,frame_x=4,frame_y=4;
	int32_t caption=26,small_caption=18,menu=19;
	int32_t button_x=18,button_y=25,small_button_x=17,small_button_y=17;
	int32_t get(int32_t index) const;
};

DesktopRect adjust_window_rect(const DesktopMetrics &metrics,DesktopRect rect,uint32_t style,bool menu,uint32_t ex_style);

}
