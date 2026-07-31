#pragma once

#include "presentation.h"
#include <memory>

namespace raven {

class WaylandPresentation {
public:
	WaylandPresentation();
	~WaylandPresentation();
	WaylandPresentation(const WaylandPresentation &)=delete;
	WaylandPresentation &operator=(const WaylandPresentation &)=delete;
	DesktopPresentation callbacks();

private:
	struct State;
	std::unique_ptr<State> state;
};

}
