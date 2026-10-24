#include "vulkan_bridge.h"
#include "desktop/foreign_surface.h"
#include "desktop/shared_pixels.h"

#include <algorithm>
#include <cstring>

namespace raven {

struct VulkanBridge::ForeignSwapchain {
	uint64_t device_token=0,window=0;
	VkDevice device=VK_NULL_HANDLE;
	VkSwapchainKHR swapchain=VK_NULL_HANDLE;
	VkFormat format=VK_FORMAT_UNDEFINED;
	uint32_t width=0,height=0,family=UINT32_MAX;
	VkBuffer buffer=VK_NULL_HANDLE;
	VkDeviceMemory memory=VK_NULL_HANDLE;
	void *mapped=nullptr;
	VkCommandPool pool=VK_NULL_HANDLE;
	VkCommandBuffer command=VK_NULL_HANDLE;
	std::vector<VkImage> images;
	std::shared_ptr<ForeignSurface> surface;
	~ForeignSwapchain()
	{
		if (pool) vkDestroyCommandPool(device,pool,nullptr);
		if (mapped) vkUnmapMemory(device,memory);
		if (buffer) vkDestroyBuffer(device,buffer,nullptr);
		if (memory) vkFreeMemory(device,memory,nullptr);
	}
};

VkResult VulkanBridge::prepare_foreign_swapchain(uint64_t token,uint64_t device_token,VkSwapchainKHR swapchain,
	const VkSwapchainCreateInfoKHR &info,uint64_t window)
{
	if (info.imageFormat!=VK_FORMAT_B8G8R8A8_UNORM && info.imageFormat!=VK_FORMAT_B8G8R8A8_SRGB &&
		info.imageFormat!=VK_FORMAT_R8G8B8A8_UNORM && info.imageFormat!=VK_FORMAT_R8G8B8A8_SRGB)
		return VK_ERROR_FORMAT_NOT_SUPPORTED;
	const auto size=foreign_window_size(window);
	if (!size) return VK_ERROR_SURFACE_LOST_KHR;
	if (size->first!=info.imageExtent.width || size->second!=info.imageExtent.height) return VK_ERROR_OUT_OF_DATE_KHR;
	const uint64_t bytes=uint64_t(info.imageExtent.width)*info.imageExtent.height*4;
	if (!bytes || bytes>256ULL*1024*1024 || info.imageArrayLayers!=1) return VK_ERROR_OUT_OF_DEVICE_MEMORY;
	auto target=std::make_shared<ForeignSwapchain>();
	target->device_token=device_token; target->window=window; target->device=devices.at(device_token).handle;
	target->swapchain=swapchain; target->format=info.imageFormat;
	target->width=info.imageExtent.width; target->height=info.imageExtent.height;
	target->surface=ForeignSurface::open_for_drawing(window,target->width,target->height);
	if (!target->surface) return VK_ERROR_OUT_OF_HOST_MEMORY;
	uint32_t count=0;
	VkResult result=vkGetSwapchainImagesKHR(target->device,swapchain,&count,nullptr);
	if (result!=VK_SUCCESS) return result;
	target->images.resize(count);
	result=vkGetSwapchainImagesKHR(target->device,swapchain,&count,target->images.data());
	if (result!=VK_SUCCESS) return result;
	VkBufferCreateInfo buffer{VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO};
	buffer.size=bytes; buffer.usage=VK_BUFFER_USAGE_TRANSFER_DST_BIT;
	buffer.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
	result=vkCreateBuffer(target->device,&buffer,nullptr,&target->buffer);
	if (result!=VK_SUCCESS) return result;
	VkMemoryRequirements requirements{};
	vkGetBufferMemoryRequirements(target->device,target->buffer,&requirements);
	VkPhysicalDeviceMemoryProperties memory{};
	vkGetPhysicalDeviceMemoryProperties(physical.at(devices.at(device_token).physical).handle,&memory);
	uint32_t type=0;
	const auto flags=VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
	for (;type<memory.memoryTypeCount;++type)
		if ((requirements.memoryTypeBits & (1U<<type)) && (memory.memoryTypes[type].propertyFlags & flags)==flags) break;
	if (type==memory.memoryTypeCount) return VK_ERROR_MEMORY_MAP_FAILED;
	VkMemoryAllocateInfo allocate{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,nullptr,requirements.size,type};
	result=vkAllocateMemory(target->device,&allocate,nullptr,&target->memory);
	if (result!=VK_SUCCESS) return result;
	result=vkBindBufferMemory(target->device,target->buffer,target->memory,0);
	if (result!=VK_SUCCESS) return result;
	result=vkMapMemory(target->device,target->memory,0,VK_WHOLE_SIZE,0,&target->mapped);
	if (result!=VK_SUCCESS) return result;
	foreign_swapchains.emplace(token,std::move(target));
	return VK_SUCCESS;
}

void VulkanBridge::release_foreign_swapchains(uint64_t device)
{
	std::erase_if(foreign_swapchains,[&](const auto &item) { return item.second->device_token==device; });
}

std::optional<VkResult> VulkanBridge::present_foreign(uint64_t queue_token,const VkPresentInfoKHR &info)
{
	struct Frame { std::shared_ptr<ForeignSwapchain> target; uint32_t index; };
	std::vector<Frame> frames;
	for (uint32_t i=0;i<info.swapchainCount;++i)
		for (const auto &[token,target]:foreign_swapchains)
			if (target->swapchain==info.pSwapchains[i]) {
				if (info.pImageIndices[i]>=target->images.size()) return VK_ERROR_OUT_OF_DATE_KHR;
				frames.push_back({target,info.pImageIndices[i]});
				break;
			}
	if (frames.empty()) return std::nullopt;
	const auto queue=queues.at(queue_token);
	// The copy consumes the present's waits once, including waits shared with local swapchains in the same present.
	// The host present follows the completed copies without waiting on those binary semaphores a second time.
	bool presented=false;
	const auto status=detached([&]() -> VkResult {
		std::vector<VkCommandBuffer> commands;
		for (const auto &frame:frames) {
			auto &target=*frame.target;
			if (target.device_token!=queue.device) return VK_ERROR_DEVICE_LOST;
			if (!target.pool || target.family!=queue.family) {
				if (target.pool) vkDestroyCommandPool(target.device,target.pool,nullptr);
				target.pool=VK_NULL_HANDLE;
				VkCommandPoolCreateInfo pool{VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,nullptr,VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,queue.family};
				auto result=vkCreateCommandPool(target.device,&pool,nullptr,&target.pool);
				if (result!=VK_SUCCESS) return result;
				VkCommandBufferAllocateInfo allocate{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,nullptr,target.pool,VK_COMMAND_BUFFER_LEVEL_PRIMARY,1};
				result=vkAllocateCommandBuffers(target.device,&allocate,&target.command);
				if (result!=VK_SUCCESS) return result;
				target.family=queue.family;
			}
			auto result=vkResetCommandBuffer(target.command,0);
			if (result!=VK_SUCCESS) return result;
			VkCommandBufferBeginInfo begin{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,nullptr,VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};
			result=vkBeginCommandBuffer(target.command,&begin);
			if (result!=VK_SUCCESS) return result;
			VkImageMemoryBarrier image{VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,nullptr,VK_ACCESS_MEMORY_WRITE_BIT,VK_ACCESS_TRANSFER_READ_BIT,
				VK_IMAGE_LAYOUT_PRESENT_SRC_KHR,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,VK_QUEUE_FAMILY_IGNORED,VK_QUEUE_FAMILY_IGNORED,
				target.images[frame.index],{VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
			vkCmdPipelineBarrier(target.command,VK_PIPELINE_STAGE_ALL_COMMANDS_BIT,VK_PIPELINE_STAGE_TRANSFER_BIT,0,0,nullptr,0,nullptr,1,&image);
			VkBufferImageCopy copy{};
			copy.imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1}; copy.imageExtent={target.width,target.height,1};
			vkCmdCopyImageToBuffer(target.command,target.images[frame.index],VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,target.buffer,1,&copy);
			image.srcAccessMask=VK_ACCESS_TRANSFER_READ_BIT; image.dstAccessMask=0;
			image.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL; image.newLayout=VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;
			vkCmdPipelineBarrier(target.command,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,0,0,nullptr,0,nullptr,1,&image);
			VkMemoryBarrier host{VK_STRUCTURE_TYPE_MEMORY_BARRIER,nullptr,VK_ACCESS_TRANSFER_WRITE_BIT,VK_ACCESS_HOST_READ_BIT};
			vkCmdPipelineBarrier(target.command,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_HOST_BIT,0,1,&host,0,nullptr,0,nullptr);
			result=vkEndCommandBuffer(target.command);
			if (result!=VK_SUCCESS) return result;
			commands.push_back(target.command);
		}
		std::vector<VkPipelineStageFlags> stages(info.waitSemaphoreCount,VK_PIPELINE_STAGE_ALL_COMMANDS_BIT);
		VkSubmitInfo submit{VK_STRUCTURE_TYPE_SUBMIT_INFO,nullptr,info.waitSemaphoreCount,info.pWaitSemaphores,stages.data(),
			uint32_t(commands.size()),commands.data(),0,nullptr};
		auto result=vkQueueSubmit(queue.handle,1,&submit,VK_NULL_HANDLE);
		if (result!=VK_SUCCESS) return result;
		result=vkQueueWaitIdle(queue.handle);
		if (result!=VK_SUCCESS) return result;
		for (const auto &frame:frames) {
			auto &target=*frame.target;
			const auto *source=static_cast<const uint8_t *>(target.mapped);
			auto *destination=target.surface->pixels->data();
			const size_t bytes=size_t(target.width)*target.height*4;
			if (target.format==VK_FORMAT_R8G8B8A8_UNORM || target.format==VK_FORMAT_R8G8B8A8_SRGB)
				for (size_t i=0;i<bytes;i+=4) {
					destination[i]=source[i+2]; destination[i+1]=source[i+1];
					destination[i+2]=source[i]; destination[i+3]=source[i+3];
				}
			else std::memcpy(destination,source,bytes);
			target.surface->publish_frame();
		}
		VkPresentInfoKHR present=info;
		present.waitSemaphoreCount=0; present.pWaitSemaphores=nullptr;
		presented=true;
		return vkQueuePresentKHR(queue.handle,&present);
	});
	if (!presented && info.pResults) std::fill_n(info.pResults,info.swapchainCount,status);
	return status;
}

}
