//go:build guest_windows

package vk

import "unsafe"

// CreateDescriptorSetLayout creates a layout with a single uniform-buffer
// binding at binding 0, visible to the vertex stage. This matches the SPIR-V
// emitted by the D3D9 vertex-shader translator (constants live in a uniform
// block at set 0, binding 0).
func CreateDescriptorSetLayout(device VkDevice) (VkDescriptorSetLayout, VkResult) {
	binding := VkDescriptorSetLayoutBinding{
		Binding:         0,
		DescriptorType:  VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,
		DescriptorCount: 1,
		StageFlags:      VkShaderStageFlags(VK_SHADER_STAGE_VERTEX_BIT),
	}
	ci := VkDescriptorSetLayoutCreateInfo{
		SType:        VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
		BindingCount: 1,
		PBindings:    &binding,
	}
	var layout VkDescriptorSetLayout
	res := callResult(procs.vkCreateDescriptorSetLayout, uintptr(device), uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&layout)))
	return layout, res
}

func DestroyDescriptorSetLayout(device VkDevice, layout VkDescriptorSetLayout) {
	if layout != 0 {
		callVoid(procs.vkDestroyDescriptorSetLayout, uintptr(device), uintptr(layout), 0)
	}
}

// CreateDescriptorPool creates a pool able to allocate maxSets descriptor sets,
// each with one uniform-buffer descriptor.
func CreateDescriptorPool(device VkDevice, maxSets uint32) (VkDescriptorPool, VkResult) {
	if maxSets == 0 {
		maxSets = 1
	}
	poolSize := VkDescriptorPoolSize{
		Type:            VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,
		DescriptorCount: maxSets,
	}
	ci := VkDescriptorPoolCreateInfo{
		SType:         VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
		MaxSets:       maxSets,
		PoolSizeCount: 1,
		PPoolSizes:    &poolSize,
	}
	var pool VkDescriptorPool
	res := callResult(procs.vkCreateDescriptorPool, uintptr(device), uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&pool)))
	return pool, res
}

func DestroyDescriptorPool(device VkDevice, pool VkDescriptorPool) {
	if pool != 0 {
		callVoid(procs.vkDestroyDescriptorPool, uintptr(device), uintptr(pool), 0)
	}
}

// AllocateDescriptorSet allocates a single descriptor set from pool using layout.
func AllocateDescriptorSet(device VkDevice, pool VkDescriptorPool, layout VkDescriptorSetLayout) (VkDescriptorSet, VkResult) {
	setLayout := layout
	ci := VkDescriptorSetAllocateInfo{
		SType:              VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
		DescriptorPool:     pool,
		DescriptorSetCount: 1,
		PSetLayouts:        &setLayout,
	}
	var set VkDescriptorSet
	res := callResult(procs.vkAllocateDescriptorSets, uintptr(device), uintptr(unsafe.Pointer(&ci)), uintptr(unsafe.Pointer(&set)))
	return set, res
}

// UpdateDescriptorSetUniformBuffer writes buffer (range bytes from offset) into
// binding 0 of set as a uniform buffer.
func UpdateDescriptorSetUniformBuffer(device VkDevice, set VkDescriptorSet, buffer VkBuffer, offset, size VkDeviceSize) {
	bufferInfo := VkDescriptorBufferInfo{
		Buffer: buffer,
		Offset: offset,
		Range:  size,
	}
	write := VkWriteDescriptorSet{
		SType:           VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
		DstSet:          set,
		DstBinding:      0,
		DstArrayElement: 0,
		DescriptorCount: 1,
		DescriptorType:  VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,
		PBufferInfo:     &bufferInfo,
	}
	callVoid(procs.vkUpdateDescriptorSets, uintptr(device), 1, uintptr(unsafe.Pointer(&write)), 0, 0)
}

// CmdBindDescriptorSets binds a single descriptor set at firstSet for the given
// bind point and pipeline layout.
func CmdBindDescriptorSets(cb VkCommandBuffer, bindPoint VkPipelineBindPoint, layout VkPipelineLayout, firstSet uint32, set VkDescriptorSet) {
	descriptorSet := set
	callVoid(procs.vkCmdBindDescriptorSets,
		uintptr(cb),
		uintptr(bindPoint),
		uintptr(layout),
		uintptr(firstSet),
		1, uintptr(unsafe.Pointer(&descriptorSet)),
		0, 0)
}
