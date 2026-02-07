//go:build guest_windows

package vk

import "unsafe"

type (
	VkFlags      uint32
	VkBool32     uint32
	VkDeviceSize uint64
	VkSampleMask uint32

	VkResult                           int32
	VkStructureType                    int32
	VkPhysicalDeviceType               int32
	VkFormat                           int32
	VkImageLayout                      int32
	VkImageType                        int32
	VkImageViewType                    int32
	VkImageTiling                      int32
	VkPrimitiveTopology                int32
	VkSharingMode                      int32
	VkCommandBufferLevel               int32
	VkPipelineBindPoint                int32
	VkDescriptorType                   int32
	VkShaderStageFlagBits              uint32
	VkDynamicState                     int32
	VkPolygonMode                      int32
	VkCullModeFlags                    VkFlags
	VkFrontFace                        int32
	VkCompareOp                        int32
	VkStencilOp                        int32
	VkBlendFactor                      int32
	VkBlendOp                          int32
	VkLogicOp                          int32
	VkVertexInputRate                  int32
	VkAttachmentLoadOp                 int32
	VkAttachmentStoreOp                int32
	VkSubpassContents                  int32
	VkSampleCountFlagBits              int32
	VkComponentSwizzle                 int32
	VkIndexType                        int32
	VkExternalMemoryHandleTypeFlagBits int32

	VkCommandBufferUsageFlags               VkFlags
	VkCommandBufferResetFlags               VkFlags
	VkCommandPoolCreateFlags                VkFlags
	VkFenceCreateFlags                      VkFlags
	VkSemaphoreCreateFlags                  VkFlags
	VkBufferUsageFlags                      VkFlags
	VkImageUsageFlags                       VkFlags
	VkMemoryPropertyFlags                   VkFlags
	VkImageAspectFlags                      VkFlags
	VkQueueFlags                            VkFlags
	VkPipelineStageFlags                    VkFlags
	VkAccessFlags                           VkFlags
	VkDependencyFlags                       VkFlags
	VkColorComponentFlags                   VkFlags
	VkShaderStageFlags                      VkFlags
	VkInstanceCreateFlags                   VkFlags
	VkDeviceQueueCreateFlags                VkFlags
	VkDeviceCreateFlags                     VkFlags
	VkBufferCreateFlags                     VkFlags
	VkImageCreateFlags                      VkFlags
	VkImageViewCreateFlags                  VkFlags
	VkPipelineCreateFlags                   VkFlags
	VkPipelineShaderStageCreateFlags        VkFlags
	VkPipelineVertexInputStateCreateFlags   VkFlags
	VkPipelineInputAssemblyStateCreateFlags VkFlags
	VkPipelineViewportStateCreateFlags      VkFlags
	VkPipelineRasterizationStateCreateFlags VkFlags
	VkPipelineMultisampleStateCreateFlags   VkFlags
	VkPipelineColorBlendStateCreateFlags    VkFlags
	VkPipelineDepthStencilStateCreateFlags  VkFlags
	VkPipelineDynamicStateCreateFlags       VkFlags
	VkPipelineLayoutCreateFlags             VkFlags
	VkRenderPassCreateFlags                 VkFlags
	VkFramebufferCreateFlags                VkFlags
	VkAttachmentDescriptionFlags            VkFlags
	VkSubpassDescriptionFlags               VkFlags
	VkMemoryHeapFlags                       VkFlags
	VkQueryControlFlags                     VkFlags
	VkQueryPipelineStatisticFlags           VkFlags
	VkDescriptorPoolCreateFlags             VkFlags
	VkDescriptorSetLayoutCreateFlags        VkFlags
	VkExternalMemoryHandleTypeFlags         VkFlags
)

type (
	VkInstance            uintptr
	VkPhysicalDevice      uintptr
	VkDevice              uintptr
	VkQueue               uintptr
	VkCommandPool         uintptr
	VkCommandBuffer       uintptr
	VkRenderPass          uintptr
	VkFramebuffer         uintptr
	VkPipeline            uintptr
	VkPipelineLayout      uintptr
	VkImage               uintptr
	VkImageView           uintptr
	VkBuffer              uintptr
	VkDeviceMemory        uintptr
	VkFence               uintptr
	VkSemaphore           uintptr
	VkShaderModule        uintptr
	VkDescriptorSetLayout uintptr
	VkDescriptorPool      uintptr
	VkDescriptorSet       uintptr
	VkSampler             uintptr
	VkSurfaceKHR          uintptr
	VkSwapchainKHR        uintptr
)

const (
	VK_FALSE                         VkBool32     = 0
	VK_TRUE                          VkBool32     = 1
	VK_QUEUE_FAMILY_IGNORED                       = ^uint32(0)
	VK_REMAINING_ARRAY_LAYERS                     = ^uint32(0)
	VK_REMAINING_MIP_LEVELS                       = ^uint32(0)
	VK_SUBPASS_EXTERNAL                           = ^uint32(0)
	VK_WHOLE_SIZE                    VkDeviceSize = ^VkDeviceSize(0)
	VK_MAX_MEMORY_TYPES                           = 32
	VK_MAX_MEMORY_HEAPS                           = 16
	VK_MAX_PHYSICAL_DEVICE_NAME_SIZE              = 256
	VK_UUID_SIZE                                  = 16
	VK_MAX_EXTENSION_NAME_SIZE                    = 256
	VK_MAX_DESCRIPTION_SIZE                       = 256
)

const (
	VK_SUCCESS                     VkResult = 0
	VK_NOT_READY                   VkResult = 1
	VK_TIMEOUT                     VkResult = 2
	VK_EVENT_SET                   VkResult = 3
	VK_EVENT_RESET                 VkResult = 4
	VK_INCOMPLETE                  VkResult = 5
	VK_ERROR_OUT_OF_HOST_MEMORY    VkResult = -1
	VK_ERROR_OUT_OF_DEVICE_MEMORY  VkResult = -2
	VK_ERROR_INITIALIZATION_FAILED VkResult = -3
	VK_ERROR_DEVICE_LOST           VkResult = -4
	VK_ERROR_MEMORY_MAP_FAILED     VkResult = -5
	VK_ERROR_LAYER_NOT_PRESENT     VkResult = -6
	VK_ERROR_EXTENSION_NOT_PRESENT VkResult = -7
	VK_ERROR_FEATURE_NOT_PRESENT   VkResult = -8
	VK_ERROR_INCOMPATIBLE_DRIVER   VkResult = -9
	VK_ERROR_TOO_MANY_OBJECTS      VkResult = -10
	VK_ERROR_FORMAT_NOT_SUPPORTED  VkResult = -11
	VK_ERROR_FRAGMENTED_POOL       VkResult = -12
	VK_ERROR_UNKNOWN               VkResult = -13
	VK_SUBOPTIMAL_KHR              VkResult = 1000001003
	VK_ERROR_OUT_OF_DATE_KHR       VkResult = -1000001004
)

const (
	VK_STRUCTURE_TYPE_APPLICATION_INFO                          VkStructureType = 0
	VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO                      VkStructureType = 1
	VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO                  VkStructureType = 2
	VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO                        VkStructureType = 3
	VK_STRUCTURE_TYPE_SUBMIT_INFO                               VkStructureType = 4
	VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO                      VkStructureType = 5
	VK_STRUCTURE_TYPE_FENCE_CREATE_INFO                         VkStructureType = 8
	VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO                     VkStructureType = 9
	VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO                        VkStructureType = 12
	VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO                         VkStructureType = 14
	VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO                    VkStructureType = 15
	VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO                 VkStructureType = 16
	VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO         VkStructureType = 18
	VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO   VkStructureType = 19
	VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO VkStructureType = 20
	VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO       VkStructureType = 22
	VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO  VkStructureType = 23
	VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO    VkStructureType = 24
	VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO  VkStructureType = 25
	VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO    VkStructureType = 26
	VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO        VkStructureType = 27
	VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO             VkStructureType = 28
	VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO               VkStructureType = 30
	VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET                      VkStructureType = 35
	VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO                   VkStructureType = 37
	VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO                   VkStructureType = 38
	VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO                  VkStructureType = 39
	VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO              VkStructureType = 40
	VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO                 VkStructureType = 42
	VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO                    VkStructureType = 43
	VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER                      VkStructureType = 45
	VK_STRUCTURE_TYPE_PRESENT_INFO_KHR                          VkStructureType = 1000001001
	VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_IMAGE_CREATE_INFO         VkStructureType = 1000072001
	VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO               VkStructureType = 1000072002
	VK_STRUCTURE_TYPE_MEMORY_GET_FD_INFO_KHR                    VkStructureType = 1000074002
)

const (
	VK_PHYSICAL_DEVICE_TYPE_OTHER          VkPhysicalDeviceType = 0
	VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU VkPhysicalDeviceType = 1
	VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU   VkPhysicalDeviceType = 2
	VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU    VkPhysicalDeviceType = 3
	VK_PHYSICAL_DEVICE_TYPE_CPU            VkPhysicalDeviceType = 4
)

const (
	VK_FORMAT_UNDEFINED           VkFormat = 0
	VK_FORMAT_R8G8B8A8_UNORM      VkFormat = 37
	VK_FORMAT_B8G8R8A8_UNORM      VkFormat = 44
	VK_FORMAT_R32_SFLOAT          VkFormat = 100
	VK_FORMAT_R32G32_SFLOAT       VkFormat = 103
	VK_FORMAT_R32G32B32_SFLOAT    VkFormat = 106
	VK_FORMAT_R32G32B32A32_SFLOAT VkFormat = 109
	VK_FORMAT_D32_SFLOAT          VkFormat = 126
	VK_FORMAT_D24_UNORM_S8_UINT   VkFormat = 129
	VK_FORMAT_D32_SFLOAT_S8_UINT  VkFormat = 130
)

const (
	VK_IMAGE_LAYOUT_UNDEFINED                        VkImageLayout = 0
	VK_IMAGE_LAYOUT_GENERAL                          VkImageLayout = 1
	VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL         VkImageLayout = 2
	VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL VkImageLayout = 3
	VK_IMAGE_LAYOUT_DEPTH_STENCIL_READ_ONLY_OPTIMAL  VkImageLayout = 4
	VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL         VkImageLayout = 5
	VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL             VkImageLayout = 6
	VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL             VkImageLayout = 7
	VK_IMAGE_LAYOUT_PREINITIALIZED                   VkImageLayout = 8
	VK_IMAGE_LAYOUT_PRESENT_SRC_KHR                  VkImageLayout = 1000001002
)

const (
	VK_IMAGE_USAGE_TRANSFER_SRC_BIT             VkImageUsageFlags = 0x00000001
	VK_IMAGE_USAGE_TRANSFER_DST_BIT             VkImageUsageFlags = 0x00000002
	VK_IMAGE_USAGE_SAMPLED_BIT                  VkImageUsageFlags = 0x00000004
	VK_IMAGE_USAGE_STORAGE_BIT                  VkImageUsageFlags = 0x00000008
	VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT         VkImageUsageFlags = 0x00000010
	VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT VkImageUsageFlags = 0x00000020
	VK_IMAGE_USAGE_TRANSIENT_ATTACHMENT_BIT     VkImageUsageFlags = 0x00000040
	VK_IMAGE_USAGE_INPUT_ATTACHMENT_BIT         VkImageUsageFlags = 0x00000080
)

const (
	VK_BUFFER_USAGE_TRANSFER_SRC_BIT         VkBufferUsageFlags = 0x00000001
	VK_BUFFER_USAGE_TRANSFER_DST_BIT         VkBufferUsageFlags = 0x00000002
	VK_BUFFER_USAGE_UNIFORM_TEXEL_BUFFER_BIT VkBufferUsageFlags = 0x00000004
	VK_BUFFER_USAGE_STORAGE_TEXEL_BUFFER_BIT VkBufferUsageFlags = 0x00000008
	VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT       VkBufferUsageFlags = 0x00000010
	VK_BUFFER_USAGE_STORAGE_BUFFER_BIT       VkBufferUsageFlags = 0x00000020
	VK_BUFFER_USAGE_INDEX_BUFFER_BIT         VkBufferUsageFlags = 0x00000040
	VK_BUFFER_USAGE_VERTEX_BUFFER_BIT        VkBufferUsageFlags = 0x00000080
)

const (
	VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT  VkMemoryPropertyFlags = 0x00000001
	VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT  VkMemoryPropertyFlags = 0x00000002
	VK_MEMORY_PROPERTY_HOST_COHERENT_BIT VkMemoryPropertyFlags = 0x00000004
	VK_MEMORY_PROPERTY_HOST_CACHED_BIT   VkMemoryPropertyFlags = 0x00000008
)

const (
	VK_EXTERNAL_MEMORY_HANDLE_TYPE_OPAQUE_FD_BIT   VkExternalMemoryHandleTypeFlagBits = 0x00000001
	VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT VkExternalMemoryHandleTypeFlagBits = 0x00000200
)

const (
	VK_PRIMITIVE_TOPOLOGY_POINT_LIST     VkPrimitiveTopology = 0
	VK_PRIMITIVE_TOPOLOGY_LINE_LIST      VkPrimitiveTopology = 1
	VK_PRIMITIVE_TOPOLOGY_LINE_STRIP     VkPrimitiveTopology = 2
	VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST  VkPrimitiveTopology = 3
	VK_PRIMITIVE_TOPOLOGY_TRIANGLE_STRIP VkPrimitiveTopology = 4
	VK_PRIMITIVE_TOPOLOGY_TRIANGLE_FAN   VkPrimitiveTopology = 5
)

const (
	VK_SHADER_STAGE_VERTEX_BIT   VkShaderStageFlagBits = 0x00000001
	VK_SHADER_STAGE_FRAGMENT_BIT VkShaderStageFlagBits = 0x00000010
)

const (
	VK_QUEUE_GRAPHICS_BIT VkQueueFlags = 0x00000001
)

const (
	VK_COMMAND_POOL_CREATE_TRANSIENT_BIT            VkCommandPoolCreateFlags = 0x00000001
	VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT VkCommandPoolCreateFlags = 0x00000002
)

const (
	VK_COMMAND_BUFFER_LEVEL_PRIMARY VkCommandBufferLevel = 0
)

const (
	VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT VkCommandBufferUsageFlags = 0x00000001
)

const (
	VK_COMMAND_BUFFER_RESET_RELEASE_RESOURCES_BIT VkCommandBufferResetFlags = 0x00000001
)

const (
	VK_FENCE_CREATE_SIGNALED_BIT VkFenceCreateFlags = 0x00000001
)

const (
	VK_IMAGE_ASPECT_COLOR_BIT   VkImageAspectFlags = 0x00000001
	VK_IMAGE_ASPECT_DEPTH_BIT   VkImageAspectFlags = 0x00000002
	VK_IMAGE_ASPECT_STENCIL_BIT VkImageAspectFlags = 0x00000004
)

const (
	VK_PIPELINE_BIND_POINT_GRAPHICS VkPipelineBindPoint = 0
)

const (
	VK_ATTACHMENT_LOAD_OP_LOAD      VkAttachmentLoadOp = 0
	VK_ATTACHMENT_LOAD_OP_CLEAR     VkAttachmentLoadOp = 1
	VK_ATTACHMENT_LOAD_OP_DONT_CARE VkAttachmentLoadOp = 2
)

const (
	VK_ATTACHMENT_STORE_OP_STORE     VkAttachmentStoreOp = 0
	VK_ATTACHMENT_STORE_OP_DONT_CARE VkAttachmentStoreOp = 1
)

const (
	VK_SUBPASS_CONTENTS_INLINE VkSubpassContents = 0
)

const (
	VK_SAMPLE_COUNT_1_BIT VkSampleCountFlagBits = 0x00000001
)

const (
	VK_SHARING_MODE_EXCLUSIVE  VkSharingMode = 0
	VK_SHARING_MODE_CONCURRENT VkSharingMode = 1
)

const (
	VK_IMAGE_TYPE_1D VkImageType = 0
	VK_IMAGE_TYPE_2D VkImageType = 1
	VK_IMAGE_TYPE_3D VkImageType = 2
)

const (
	VK_IMAGE_TILING_OPTIMAL VkImageTiling = 0
	VK_IMAGE_TILING_LINEAR  VkImageTiling = 1
)

const (
	VK_IMAGE_VIEW_TYPE_1D VkImageViewType = 0
	VK_IMAGE_VIEW_TYPE_2D VkImageViewType = 1
)

const (
	VK_DYNAMIC_STATE_VIEWPORT VkDynamicState = 0
	VK_DYNAMIC_STATE_SCISSOR  VkDynamicState = 1
)

const (
	VK_POLYGON_MODE_FILL  VkPolygonMode = 0
	VK_POLYGON_MODE_LINE  VkPolygonMode = 1
	VK_POLYGON_MODE_POINT VkPolygonMode = 2
)

const (
	VK_CULL_MODE_NONE      VkCullModeFlags = 0
	VK_CULL_MODE_FRONT_BIT VkCullModeFlags = 0x00000001
	VK_CULL_MODE_BACK_BIT  VkCullModeFlags = 0x00000002
)

const (
	VK_FRONT_FACE_COUNTER_CLOCKWISE VkFrontFace = 0
	VK_FRONT_FACE_CLOCKWISE         VkFrontFace = 1
)

const (
	VK_COMPARE_OP_NEVER            VkCompareOp = 0
	VK_COMPARE_OP_LESS             VkCompareOp = 1
	VK_COMPARE_OP_EQUAL            VkCompareOp = 2
	VK_COMPARE_OP_LESS_OR_EQUAL    VkCompareOp = 3
	VK_COMPARE_OP_GREATER          VkCompareOp = 4
	VK_COMPARE_OP_NOT_EQUAL        VkCompareOp = 5
	VK_COMPARE_OP_GREATER_OR_EQUAL VkCompareOp = 6
	VK_COMPARE_OP_ALWAYS           VkCompareOp = 7
)

const (
	VK_STENCIL_OP_KEEP VkStencilOp = 0
)

const (
	VK_BLEND_FACTOR_ZERO                VkBlendFactor = 0
	VK_BLEND_FACTOR_ONE                 VkBlendFactor = 1
	VK_BLEND_FACTOR_SRC_COLOR           VkBlendFactor = 2
	VK_BLEND_FACTOR_ONE_MINUS_SRC_COLOR VkBlendFactor = 3
	VK_BLEND_FACTOR_DST_COLOR           VkBlendFactor = 4
	VK_BLEND_FACTOR_ONE_MINUS_DST_COLOR VkBlendFactor = 5
	VK_BLEND_FACTOR_SRC_ALPHA           VkBlendFactor = 6
	VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA VkBlendFactor = 7
	VK_BLEND_FACTOR_DST_ALPHA           VkBlendFactor = 8
	VK_BLEND_FACTOR_ONE_MINUS_DST_ALPHA VkBlendFactor = 9
	VK_BLEND_FACTOR_SRC_ALPHA_SATURATE  VkBlendFactor = 10
)

const (
	VK_BLEND_OP_ADD              VkBlendOp = 0
	VK_BLEND_OP_SUBTRACT         VkBlendOp = 1
	VK_BLEND_OP_REVERSE_SUBTRACT VkBlendOp = 2
	VK_BLEND_OP_MIN              VkBlendOp = 3
	VK_BLEND_OP_MAX              VkBlendOp = 4
)

const (
	VK_LOGIC_OP_COPY VkLogicOp = 3
)

const (
	VK_VERTEX_INPUT_RATE_VERTEX   VkVertexInputRate = 0
	VK_VERTEX_INPUT_RATE_INSTANCE VkVertexInputRate = 1
)

const (
	VK_DESCRIPTOR_TYPE_SAMPLER                VkDescriptorType = 0
	VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER VkDescriptorType = 1
	VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE          VkDescriptorType = 2
	VK_DESCRIPTOR_TYPE_STORAGE_IMAGE          VkDescriptorType = 3
	VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER   VkDescriptorType = 4
	VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER   VkDescriptorType = 5
	VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER         VkDescriptorType = 6
	VK_DESCRIPTOR_TYPE_STORAGE_BUFFER         VkDescriptorType = 7
)

const (
	VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT             VkPipelineStageFlags = 0x00000001
	VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT    VkPipelineStageFlags = 0x00000100
	VK_PIPELINE_STAGE_LATE_FRAGMENT_TESTS_BIT     VkPipelineStageFlags = 0x00000200
	VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT VkPipelineStageFlags = 0x00000400
	VK_PIPELINE_STAGE_TRANSFER_BIT                VkPipelineStageFlags = 0x00001000
	VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT          VkPipelineStageFlags = 0x00002000
)

const (
	VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT         VkAccessFlags = 0x00000100
	VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT VkAccessFlags = 0x00000400
	VK_ACCESS_TRANSFER_READ_BIT                  VkAccessFlags = 0x00000800
	VK_ACCESS_TRANSFER_WRITE_BIT                 VkAccessFlags = 0x00001000
	VK_ACCESS_MEMORY_READ_BIT                    VkAccessFlags = 0x00008000
)

const (
	VK_COLOR_COMPONENT_R_BIT VkColorComponentFlags = 0x00000001
	VK_COLOR_COMPONENT_G_BIT VkColorComponentFlags = 0x00000002
	VK_COLOR_COMPONENT_B_BIT VkColorComponentFlags = 0x00000004
	VK_COLOR_COMPONENT_A_BIT VkColorComponentFlags = 0x00000008
)

const (
	VK_COMPONENT_SWIZZLE_IDENTITY VkComponentSwizzle = 0
)

const (
	VK_KHR_SWAPCHAIN_EXTENSION_NAME                    = "VK_KHR_swapchain"
	VK_KHR_EXTERNAL_MEMORY_CAPABILITIES_EXTENSION_NAME = "VK_KHR_external_memory_capabilities"
	VK_KHR_EXTERNAL_MEMORY_EXTENSION_NAME              = "VK_KHR_external_memory"
	VK_KHR_EXTERNAL_MEMORY_FD_EXTENSION_NAME           = "VK_KHR_external_memory_fd"
	VK_EXT_EXTERNAL_MEMORY_DMA_BUF_EXTENSION_NAME      = "VK_EXT_external_memory_dma_buf"
)

type VkAllocationCallbacks struct{ _ [0]byte }

type VkExtent2D struct {
	Width  uint32
	Height uint32
}

type VkExtent3D struct {
	Width  uint32
	Height uint32
	Depth  uint32
}

type VkOffset2D struct {
	X int32
	Y int32
}

type VkOffset3D struct {
	X int32
	Y int32
	Z int32
}

type VkRect2D struct {
	Offset VkOffset2D
	Extent VkExtent2D
}

type VkApplicationInfo struct {
	SType              VkStructureType
	PNext              unsafe.Pointer
	PApplicationName   *byte
	ApplicationVersion uint32
	PEngineName        *byte
	EngineVersion      uint32
	APIVersion         uint32
}

type VkInstanceCreateInfo struct {
	SType                   VkStructureType
	PNext                   unsafe.Pointer
	Flags                   VkInstanceCreateFlags
	PApplicationInfo        *VkApplicationInfo
	EnabledLayerCount       uint32
	PPEnabledLayerNames     **byte
	EnabledExtensionCount   uint32
	PPEnabledExtensionNames **byte
}

type VkLayerProperties struct {
	LayerName             [VK_MAX_EXTENSION_NAME_SIZE]byte
	SpecVersion           uint32
	ImplementationVersion uint32
	Description           [VK_MAX_DESCRIPTION_SIZE]byte
}

type VkExtensionProperties struct {
	ExtensionName [VK_MAX_EXTENSION_NAME_SIZE]byte
	SpecVersion   uint32
}

type VkMemoryHeap struct {
	Size  VkDeviceSize
	Flags VkMemoryHeapFlags
}

type VkMemoryType struct {
	PropertyFlags VkMemoryPropertyFlags
	HeapIndex     uint32
}

type VkPhysicalDeviceMemoryProperties struct {
	MemoryTypeCount uint32
	MemoryTypes     [VK_MAX_MEMORY_TYPES]VkMemoryType
	MemoryHeapCount uint32
	MemoryHeaps     [VK_MAX_MEMORY_HEAPS]VkMemoryHeap
}

type VkQueueFamilyProperties struct {
	QueueFlags                  VkQueueFlags
	QueueCount                  uint32
	TimestampValidBits          uint32
	MinImageTransferGranularity VkExtent3D
}

type VkDeviceQueueCreateInfo struct {
	SType            VkStructureType
	PNext            unsafe.Pointer
	Flags            VkDeviceQueueCreateFlags
	QueueFamilyIndex uint32
	QueueCount       uint32
	PQueuePriorities *float32
}

type VkDeviceCreateInfo struct {
	SType                   VkStructureType
	PNext                   unsafe.Pointer
	Flags                   VkDeviceCreateFlags
	QueueCreateInfoCount    uint32
	PQueueCreateInfos       *VkDeviceQueueCreateInfo
	EnabledLayerCount       uint32
	PPEnabledLayerNames     **byte
	EnabledExtensionCount   uint32
	PPEnabledExtensionNames **byte
	PEnabledFeatures        unsafe.Pointer
}

type VkCommandPoolCreateInfo struct {
	SType            VkStructureType
	PNext            unsafe.Pointer
	Flags            VkCommandPoolCreateFlags
	QueueFamilyIndex uint32
}

type VkCommandBufferAllocateInfo struct {
	SType              VkStructureType
	PNext              unsafe.Pointer
	CommandPool        VkCommandPool
	Level              VkCommandBufferLevel
	CommandBufferCount uint32
}

type VkCommandBufferInheritanceInfo struct {
	SType                VkStructureType
	PNext                unsafe.Pointer
	RenderPass           VkRenderPass
	Subpass              uint32
	Framebuffer          VkFramebuffer
	OcclusionQueryEnable VkBool32
	QueryFlags           VkQueryControlFlags
	PipelineStatistics   VkQueryPipelineStatisticFlags
}

type VkCommandBufferBeginInfo struct {
	SType            VkStructureType
	PNext            unsafe.Pointer
	Flags            VkCommandBufferUsageFlags
	PInheritanceInfo *VkCommandBufferInheritanceInfo
}

type VkAttachmentDescription struct {
	Flags          VkAttachmentDescriptionFlags
	Format         VkFormat
	Samples        VkSampleCountFlagBits
	LoadOp         VkAttachmentLoadOp
	StoreOp        VkAttachmentStoreOp
	StencilLoadOp  VkAttachmentLoadOp
	StencilStoreOp VkAttachmentStoreOp
	InitialLayout  VkImageLayout
	FinalLayout    VkImageLayout
}

type VkAttachmentReference struct {
	Attachment uint32
	Layout     VkImageLayout
}

type VkSubpassDescription struct {
	Flags                   VkSubpassDescriptionFlags
	PipelineBindPoint       VkPipelineBindPoint
	InputAttachmentCount    uint32
	PInputAttachments       *VkAttachmentReference
	ColorAttachmentCount    uint32
	PColorAttachments       *VkAttachmentReference
	PResolveAttachments     *VkAttachmentReference
	PDepthStencilAttachment *VkAttachmentReference
	PreserveAttachmentCount uint32
	PPreserveAttachments    *uint32
}

type VkSubpassDependency struct {
	SrcSubpass      uint32
	DstSubpass      uint32
	SrcStageMask    VkPipelineStageFlags
	DstStageMask    VkPipelineStageFlags
	SrcAccessMask   VkAccessFlags
	DstAccessMask   VkAccessFlags
	DependencyFlags VkDependencyFlags
}

type VkRenderPassCreateInfo struct {
	SType           VkStructureType
	PNext           unsafe.Pointer
	Flags           VkRenderPassCreateFlags
	AttachmentCount uint32
	PAttachments    *VkAttachmentDescription
	SubpassCount    uint32
	PSubpasses      *VkSubpassDescription
	DependencyCount uint32
	PDependencies   *VkSubpassDependency
}

type VkFramebufferCreateInfo struct {
	SType           VkStructureType
	PNext           unsafe.Pointer
	Flags           VkFramebufferCreateFlags
	RenderPass      VkRenderPass
	AttachmentCount uint32
	PAttachments    *VkImageView
	Width           uint32
	Height          uint32
	Layers          uint32
}

type VkSpecializationMapEntry struct {
	ConstantID uint32
	Offset     uint32
	Size       uintptr
}

type VkSpecializationInfo struct {
	MapEntryCount uint32
	PMapEntries   *VkSpecializationMapEntry
	DataSize      uintptr
	PData         unsafe.Pointer
}

type VkPipelineShaderStageCreateInfo struct {
	SType               VkStructureType
	PNext               unsafe.Pointer
	Flags               VkPipelineShaderStageCreateFlags
	Stage               VkShaderStageFlagBits
	Module              VkShaderModule
	PName               *byte
	PSpecializationInfo *VkSpecializationInfo
}

type VkVertexInputBindingDescription struct {
	Binding   uint32
	Stride    uint32
	InputRate VkVertexInputRate
}

type VkVertexInputAttributeDescription struct {
	Location uint32
	Binding  uint32
	Format   VkFormat
	Offset   uint32
}

type VkPipelineVertexInputStateCreateInfo struct {
	SType                           VkStructureType
	PNext                           unsafe.Pointer
	Flags                           VkPipelineVertexInputStateCreateFlags
	VertexBindingDescriptionCount   uint32
	PVertexBindingDescriptions      *VkVertexInputBindingDescription
	VertexAttributeDescriptionCount uint32
	PVertexAttributeDescriptions    *VkVertexInputAttributeDescription
}

type VkPipelineInputAssemblyStateCreateInfo struct {
	SType                  VkStructureType
	PNext                  unsafe.Pointer
	Flags                  VkPipelineInputAssemblyStateCreateFlags
	Topology               VkPrimitiveTopology
	PrimitiveRestartEnable VkBool32
}

type VkViewport struct {
	X        float32
	Y        float32
	Width    float32
	Height   float32
	MinDepth float32
	MaxDepth float32
}

type VkPipelineViewportStateCreateInfo struct {
	SType         VkStructureType
	PNext         unsafe.Pointer
	Flags         VkPipelineViewportStateCreateFlags
	ViewportCount uint32
	PViewports    *VkViewport
	ScissorCount  uint32
	PScissors     *VkRect2D
}

type VkPipelineRasterizationStateCreateInfo struct {
	SType                   VkStructureType
	PNext                   unsafe.Pointer
	Flags                   VkPipelineRasterizationStateCreateFlags
	DepthClampEnable        VkBool32
	RasterizerDiscardEnable VkBool32
	PolygonMode             VkPolygonMode
	CullMode                VkCullModeFlags
	FrontFace               VkFrontFace
	DepthBiasEnable         VkBool32
	DepthBiasConstantFactor float32
	DepthBiasClamp          float32
	DepthBiasSlopeFactor    float32
	LineWidth               float32
}

type VkPipelineMultisampleStateCreateInfo struct {
	SType                 VkStructureType
	PNext                 unsafe.Pointer
	Flags                 VkPipelineMultisampleStateCreateFlags
	RasterizationSamples  VkSampleCountFlagBits
	SampleShadingEnable   VkBool32
	MinSampleShading      float32
	PSampleMask           *VkSampleMask
	AlphaToCoverageEnable VkBool32
	AlphaToOneEnable      VkBool32
}

type VkPipelineColorBlendAttachmentState struct {
	BlendEnable         VkBool32
	SrcColorBlendFactor VkBlendFactor
	DstColorBlendFactor VkBlendFactor
	ColorBlendOp        VkBlendOp
	SrcAlphaBlendFactor VkBlendFactor
	DstAlphaBlendFactor VkBlendFactor
	AlphaBlendOp        VkBlendOp
	ColorWriteMask      VkColorComponentFlags
}

type VkPipelineColorBlendStateCreateInfo struct {
	SType           VkStructureType
	PNext           unsafe.Pointer
	Flags           VkPipelineColorBlendStateCreateFlags
	LogicOpEnable   VkBool32
	LogicOp         VkLogicOp
	AttachmentCount uint32
	PAttachments    *VkPipelineColorBlendAttachmentState
	BlendConstants  [4]float32
}

type VkStencilOpState struct {
	FailOp      VkStencilOp
	PassOp      VkStencilOp
	DepthFailOp VkStencilOp
	CompareOp   VkCompareOp
	CompareMask uint32
	WriteMask   uint32
	Reference   uint32
}

type VkPipelineDepthStencilStateCreateInfo struct {
	SType                 VkStructureType
	PNext                 unsafe.Pointer
	Flags                 VkPipelineDepthStencilStateCreateFlags
	DepthTestEnable       VkBool32
	DepthWriteEnable      VkBool32
	DepthCompareOp        VkCompareOp
	DepthBoundsTestEnable VkBool32
	StencilTestEnable     VkBool32
	Front                 VkStencilOpState
	Back                  VkStencilOpState
	MinDepthBounds        float32
	MaxDepthBounds        float32
}

type VkPipelineDynamicStateCreateInfo struct {
	SType             VkStructureType
	PNext             unsafe.Pointer
	Flags             VkPipelineDynamicStateCreateFlags
	DynamicStateCount uint32
	PDynamicStates    *VkDynamicState
}

type VkPushConstantRange struct {
	StageFlags VkShaderStageFlags
	Offset     uint32
	Size       uint32
}

type VkPipelineLayoutCreateInfo struct {
	SType                  VkStructureType
	PNext                  unsafe.Pointer
	Flags                  VkPipelineLayoutCreateFlags
	SetLayoutCount         uint32
	PSetLayouts            *VkDescriptorSetLayout
	PushConstantRangeCount uint32
	PPushConstantRanges    *VkPushConstantRange
}

type VkGraphicsPipelineCreateInfo struct {
	SType               VkStructureType
	PNext               unsafe.Pointer
	Flags               VkPipelineCreateFlags
	StageCount          uint32
	PStages             *VkPipelineShaderStageCreateInfo
	PVertexInputState   *VkPipelineVertexInputStateCreateInfo
	PInputAssemblyState *VkPipelineInputAssemblyStateCreateInfo
	PTessellationState  unsafe.Pointer
	PViewportState      *VkPipelineViewportStateCreateInfo
	PRasterizationState *VkPipelineRasterizationStateCreateInfo
	PMultisampleState   *VkPipelineMultisampleStateCreateInfo
	PDepthStencilState  *VkPipelineDepthStencilStateCreateInfo
	PColorBlendState    *VkPipelineColorBlendStateCreateInfo
	PDynamicState       *VkPipelineDynamicStateCreateInfo
	Layout              VkPipelineLayout
	RenderPass          VkRenderPass
	Subpass             uint32
	BasePipelineHandle  VkPipeline
	BasePipelineIndex   int32
}

type VkShaderModuleCreateInfo struct {
	SType    VkStructureType
	PNext    unsafe.Pointer
	Flags    VkFlags
	CodeSize uintptr
	PCode    *uint32
}

type VkBufferCreateInfo struct {
	SType                 VkStructureType
	PNext                 unsafe.Pointer
	Flags                 VkBufferCreateFlags
	Size                  VkDeviceSize
	Usage                 VkBufferUsageFlags
	SharingMode           VkSharingMode
	QueueFamilyIndexCount uint32
	PQueueFamilyIndices   *uint32
}

type VkMemoryAllocateInfo struct {
	SType           VkStructureType
	PNext           unsafe.Pointer
	AllocationSize  VkDeviceSize
	MemoryTypeIndex uint32
}

type VkExternalMemoryImageCreateInfo struct {
	SType       VkStructureType
	PNext       unsafe.Pointer
	HandleTypes VkExternalMemoryHandleTypeFlags
}

type VkExportMemoryAllocateInfo struct {
	SType       VkStructureType
	PNext       unsafe.Pointer
	HandleTypes VkExternalMemoryHandleTypeFlags
}

type VkMemoryGetFdInfoKHR struct {
	SType      VkStructureType
	PNext      unsafe.Pointer
	Memory     VkDeviceMemory
	HandleType VkExternalMemoryHandleTypeFlagBits
}

type VkFenceCreateInfo struct {
	SType VkStructureType
	PNext unsafe.Pointer
	Flags VkFenceCreateFlags
}

type VkSemaphoreCreateInfo struct {
	SType VkStructureType
	PNext unsafe.Pointer
	Flags VkSemaphoreCreateFlags
}

type VkMemoryRequirements struct {
	Size           VkDeviceSize
	Alignment      VkDeviceSize
	MemoryTypeBits uint32
}

type VkImageCreateInfo struct {
	SType                 VkStructureType
	PNext                 unsafe.Pointer
	Flags                 VkImageCreateFlags
	ImageType             VkImageType
	Format                VkFormat
	Extent                VkExtent3D
	MipLevels             uint32
	ArrayLayers           uint32
	Samples               VkSampleCountFlagBits
	Tiling                VkImageTiling
	Usage                 VkImageUsageFlags
	SharingMode           VkSharingMode
	QueueFamilyIndexCount uint32
	PQueueFamilyIndices   *uint32
	InitialLayout         VkImageLayout
}

type VkComponentMapping struct {
	R VkComponentSwizzle
	G VkComponentSwizzle
	B VkComponentSwizzle
	A VkComponentSwizzle
}

type VkImageSubresourceRange struct {
	AspectMask     VkImageAspectFlags
	BaseMipLevel   uint32
	LevelCount     uint32
	BaseArrayLayer uint32
	LayerCount     uint32
}

type VkImageSubresourceLayers struct {
	AspectMask     VkImageAspectFlags
	MipLevel       uint32
	BaseArrayLayer uint32
	LayerCount     uint32
}

type VkImageViewCreateInfo struct {
	SType            VkStructureType
	PNext            unsafe.Pointer
	Flags            VkImageViewCreateFlags
	Image            VkImage
	ViewType         VkImageViewType
	Format           VkFormat
	Components       VkComponentMapping
	SubresourceRange VkImageSubresourceRange
}

type VkDescriptorImageInfo struct {
	Sampler     VkSampler
	ImageView   VkImageView
	ImageLayout VkImageLayout
}

type VkDescriptorBufferInfo struct {
	Buffer VkBuffer
	Offset VkDeviceSize
	Range  VkDeviceSize
}

type VkWriteDescriptorSet struct {
	SType            VkStructureType
	PNext            unsafe.Pointer
	DstSet           VkDescriptorSet
	DstBinding       uint32
	DstArrayElement  uint32
	DescriptorCount  uint32
	DescriptorType   VkDescriptorType
	PImageInfo       *VkDescriptorImageInfo
	PBufferInfo      *VkDescriptorBufferInfo
	PTexelBufferView unsafe.Pointer
}

type VkSubmitInfo struct {
	SType                VkStructureType
	PNext                unsafe.Pointer
	WaitSemaphoreCount   uint32
	PWaitSemaphores      *VkSemaphore
	PWaitDstStageMask    *VkPipelineStageFlags
	CommandBufferCount   uint32
	PCommandBuffers      *VkCommandBuffer
	SignalSemaphoreCount uint32
	PSignalSemaphores    *VkSemaphore
}

type VkPresentInfoKHR struct {
	SType              VkStructureType
	PNext              unsafe.Pointer
	WaitSemaphoreCount uint32
	PWaitSemaphores    *VkSemaphore
	SwapchainCount     uint32
	PSwapchains        *VkSwapchainKHR
	PImageIndices      *uint32
	PResults           *VkResult
}

type VkClearValue struct {
	Uint32 [4]uint32
}

type VkImageSubresource struct {
	AspectMask VkImageAspectFlags
	MipLevel   uint32
	ArrayLayer uint32
}

type VkSubresourceLayout struct {
	Offset     VkDeviceSize
	Size       VkDeviceSize
	RowPitch   VkDeviceSize
	ArrayPitch VkDeviceSize
	DepthPitch VkDeviceSize
}

type VkImageCopy struct {
	SrcSubresource VkImageSubresourceLayers
	SrcOffset      VkOffset3D
	DstSubresource VkImageSubresourceLayers
	DstOffset      VkOffset3D
	Extent         VkExtent3D
}

type VkBufferImageCopy struct {
	BufferOffset      VkDeviceSize
	BufferRowLength   uint32
	BufferImageHeight uint32
	ImageSubresource  VkImageSubresourceLayers
	ImageOffset       VkOffset3D
	ImageExtent       VkExtent3D
}

type VkImageMemoryBarrier struct {
	SType               VkStructureType
	PNext               unsafe.Pointer
	SrcAccessMask       VkAccessFlags
	DstAccessMask       VkAccessFlags
	OldLayout           VkImageLayout
	NewLayout           VkImageLayout
	SrcQueueFamilyIndex uint32
	DstQueueFamilyIndex uint32
	Image               VkImage
	SubresourceRange    VkImageSubresourceRange
}

type VkRenderPassBeginInfo struct {
	SType           VkStructureType
	PNext           unsafe.Pointer
	RenderPass      VkRenderPass
	Framebuffer     VkFramebuffer
	RenderArea      VkRect2D
	ClearValueCount uint32
	PClearValues    *VkClearValue
}

func MakeAPIVersion(variant, major, minor, patch uint32) uint32 {
	return (variant << 29) | (major << 22) | (minor << 12) | patch
}

const (
	VK_INDEX_TYPE_UINT16 VkIndexType = 0
	VK_INDEX_TYPE_UINT32 VkIndexType = 1
)
