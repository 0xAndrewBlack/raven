#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

namespace raven {

class NativeProcess;
struct GpuMapping { uint64_t address, base; };

std::optional<GpuMapping> map_gpu_memory(NativeProcess &process, void *host, size_t size);

}
