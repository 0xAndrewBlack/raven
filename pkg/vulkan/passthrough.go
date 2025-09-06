package vulkan

import (
	"fmt"

	"github.com/mirkobrombin/go-vm/pkg/mmu"
	"github.com/mirkobrombin/go-vm/pkg/ntapi"
)

// Passthrough manages Vulkan API call forwarding from guest to host.
// Guest applications call into our synthetic vulkan-1.dll, which triggers
// vmcall traps. The passthrough layer serializes the Vulkan calls and
// forwards them to the real host Vulkan implementation.
//
// Status: Skeleton implementation. Full Vulkan passthrough requires ~200
// entry points with deeply nested struct serialization. This provides the
// infrastructure for future expansion.
type Passthrough struct {
	mem     *mmu.MMU
	handles *ntapi.HandleTable
	trace   bool

	// Instance/device tracking
	instances map[uint64]bool
	devices   map[uint64]bool
}

// New creates a Vulkan passthrough manager.
func New(mem *mmu.MMU, handles *ntapi.HandleTable) *Passthrough {
	return &Passthrough{
		mem:       mem,
		handles:   handles,
		instances: make(map[uint64]bool),
		devices:   make(map[uint64]bool),
	}
}

// SetTrace enables/disables Vulkan call tracing.
func (p *Passthrough) SetTrace(t bool) {
	p.trace = t
}

// RegisterHandlers registers Vulkan passthrough handlers with the NTAPI dispatcher.
// These would be registered via a synthetic vulkan-1.dll in the future.
func (p *Passthrough) RegisterHandlers(d *ntapi.Dispatcher) {
	// Vulkan uses its own synthetic DLL, not win32u.
	// For now, we register placeholder handlers for the most critical calls.
	// Full implementation would generate a synthetic vulkan-1.dll with ~200 exports.
	if p.trace {
		fmt.Println("[vulkan] Passthrough handlers registered (skeleton)")
	}
}

// HandleVkCreateInstance handles vkCreateInstance.
func (p *Passthrough) HandleVkCreateInstance(ctx *ntapi.TrapContext) uint32 {
	if p.trace {
		fmt.Println("[vulkan] vkCreateInstance")
	}
	// VK_SUCCESS = 0
	// In a full implementation:
	// 1. Read VkInstanceCreateInfo from guest memory
	// 2. Call real vkCreateInstance on host via CGO
	// 3. Write VkInstance handle back to guest memory
	ctx.CPU.SetSyscallReturn(0) // VK_SUCCESS
	return 0
}

// HandleVkCreateDevice handles vkCreateDevice.
func (p *Passthrough) HandleVkCreateDevice(ctx *ntapi.TrapContext) uint32 {
	if p.trace {
		fmt.Println("[vulkan] vkCreateDevice")
	}
	ctx.CPU.SetSyscallReturn(0) // VK_SUCCESS
	return 0
}

// HandleVkEnumeratePhysicalDevices handles vkEnumeratePhysicalDevices.
func (p *Passthrough) HandleVkEnumeratePhysicalDevices(ctx *ntapi.TrapContext) uint32 {
	if p.trace {
		fmt.Println("[vulkan] vkEnumeratePhysicalDevices")
	}
	// Return 0 physical devices for now
	countPtr := ctx.Arg(1)
	if countPtr != 0 {
		ctx.Mem.Write32(countPtr, 0)
	}
	ctx.CPU.SetSyscallReturn(0) // VK_SUCCESS
	return 0
}
