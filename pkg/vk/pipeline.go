package vk

import (
	"runtime"
	"unsafe"
)

type GraphicsPipelineOptions struct {
	Topology            VkPrimitiveTopology
	VertexBindings      []VkVertexInputBindingDescription
	VertexAttributes    []VkVertexInputAttributeDescription
	PolygonMode         VkPolygonMode
	CullMode            VkCullModeFlags
	FrontFace           VkFrontFace
	BlendEnable         bool
	SrcColorBlendFactor VkBlendFactor
	DstColorBlendFactor VkBlendFactor
	ColorBlendOp        VkBlendOp
	SrcAlphaBlendFactor VkBlendFactor
	DstAlphaBlendFactor VkBlendFactor
	AlphaBlendOp        VkBlendOp
	DepthTestEnable     bool
	DepthWriteEnable    bool
	DepthCompareOp      VkCompareOp
}

func CreateShaderModule(device VkDevice, spirvCode []byte) (VkShaderModule, VkResult) {
	if len(spirvCode) == 0 || len(spirvCode)%4 != 0 {
		return 0, VK_ERROR_INITIALIZATION_FAILED
	}
	ci := VkShaderModuleCreateInfo{
		SType:    VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
		CodeSize: uintptr(len(spirvCode)),
		PCode:    (*uint32)(unsafe.Pointer(&spirvCode[0])),
	}
	var shader VkShaderModule
	res := callResult(procs.vkCreateShaderModule, uintptr(device), uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&shader)))
	runtime.KeepAlive(spirvCode)
	return shader, res
}

func CreatePipelineLayout(device VkDevice, setLayouts []VkDescriptorSetLayout, pushConstantRanges []VkPushConstantRange) (VkPipelineLayout, VkResult) {
	ci := VkPipelineLayoutCreateInfo{
		SType:                  VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
		SetLayoutCount:         uint32(len(setLayouts)),
		PushConstantRangeCount: uint32(len(pushConstantRanges)),
	}
	if len(setLayouts) != 0 {
		ci.PSetLayouts = &setLayouts[0]
	}
	if len(pushConstantRanges) != 0 {
		ci.PPushConstantRanges = &pushConstantRanges[0]
	}
	var layout VkPipelineLayout
	res := callResult(procs.vkCreatePipelineLayout, uintptr(device), uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&layout)))
	return layout, res
}

func CreateGraphicsPipeline(device VkDevice, renderPass VkRenderPass, layout VkPipelineLayout, vertShader, fragShader VkShaderModule, vertexBindings []VkVertexInputBindingDescription, vertexAttribs []VkVertexInputAttributeDescription, topology VkPrimitiveTopology) (VkPipeline, VkResult) {
	return CreateGraphicsPipelineWithOptions(device, renderPass, layout, vertShader, fragShader, GraphicsPipelineOptions{
		Topology:            topology,
		VertexBindings:      vertexBindings,
		VertexAttributes:    vertexAttribs,
		PolygonMode:         VK_POLYGON_MODE_FILL,
		CullMode:            VK_CULL_MODE_NONE,
		FrontFace:           VK_FRONT_FACE_COUNTER_CLOCKWISE,
		SrcColorBlendFactor: VK_BLEND_FACTOR_ONE,
		DstColorBlendFactor: VK_BLEND_FACTOR_ZERO,
		ColorBlendOp:        VK_BLEND_OP_ADD,
		SrcAlphaBlendFactor: VK_BLEND_FACTOR_ONE,
		DstAlphaBlendFactor: VK_BLEND_FACTOR_ZERO,
		AlphaBlendOp:        VK_BLEND_OP_ADD,
		DepthCompareOp:      VK_COMPARE_OP_LESS_OR_EQUAL,
	})
}

func CreateGraphicsPipelineWithOptions(device VkDevice, renderPass VkRenderPass, layout VkPipelineLayout, vertShader, fragShader VkShaderModule, options GraphicsPipelineOptions) (VkPipeline, VkResult) {
	entry := cString("main")
	stages := []VkPipelineShaderStageCreateInfo{
		{
			SType:  VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
			Stage:  VK_SHADER_STAGE_VERTEX_BIT,
			Module: vertShader,
			PName:  &entry[0],
		},
		{
			SType:  VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
			Stage:  VK_SHADER_STAGE_FRAGMENT_BIT,
			Module: fragShader,
			PName:  &entry[0],
		},
	}

	vertexInput := VkPipelineVertexInputStateCreateInfo{
		SType:                           VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO,
		VertexBindingDescriptionCount:   uint32(len(options.VertexBindings)),
		VertexAttributeDescriptionCount: uint32(len(options.VertexAttributes)),
	}
	if len(options.VertexBindings) != 0 {
		vertexInput.PVertexBindingDescriptions = &options.VertexBindings[0]
	}
	if len(options.VertexAttributes) != 0 {
		vertexInput.PVertexAttributeDescriptions = &options.VertexAttributes[0]
	}

	inputAssembly := VkPipelineInputAssemblyStateCreateInfo{
		SType:    VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO,
		Topology: options.Topology,
	}
	viewportState := VkPipelineViewportStateCreateInfo{
		SType:         VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO,
		ViewportCount: 1,
		ScissorCount:  1,
	}
	raster := VkPipelineRasterizationStateCreateInfo{
		SType:       VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO,
		PolygonMode: options.PolygonMode,
		CullMode:    options.CullMode,
		FrontFace:   options.FrontFace,
		LineWidth:   1,
	}
	multisample := VkPipelineMultisampleStateCreateInfo{
		SType:                VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO,
		RasterizationSamples: VK_SAMPLE_COUNT_1_BIT,
	}
	blendAttachment := VkPipelineColorBlendAttachmentState{
		BlendEnable:         boolToVkBool(options.BlendEnable),
		SrcColorBlendFactor: options.SrcColorBlendFactor,
		DstColorBlendFactor: options.DstColorBlendFactor,
		ColorBlendOp:        options.ColorBlendOp,
		SrcAlphaBlendFactor: options.SrcAlphaBlendFactor,
		DstAlphaBlendFactor: options.DstAlphaBlendFactor,
		AlphaBlendOp:        options.AlphaBlendOp,
		ColorWriteMask:      VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT | VK_COLOR_COMPONENT_B_BIT | VK_COLOR_COMPONENT_A_BIT,
	}
	blend := VkPipelineColorBlendStateCreateInfo{
		SType:           VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO,
		AttachmentCount: 1,
		PAttachments:    &blendAttachment,
	}
	depthStencil := VkPipelineDepthStencilStateCreateInfo{
		SType:            VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO,
		DepthTestEnable:  boolToVkBool(options.DepthTestEnable),
		DepthWriteEnable: boolToVkBool(options.DepthWriteEnable),
		DepthCompareOp:   options.DepthCompareOp,
		Front:            VkStencilOpState{FailOp: VK_STENCIL_OP_KEEP, PassOp: VK_STENCIL_OP_KEEP, DepthFailOp: VK_STENCIL_OP_KEEP, CompareOp: VK_COMPARE_OP_ALWAYS},
		Back:             VkStencilOpState{FailOp: VK_STENCIL_OP_KEEP, PassOp: VK_STENCIL_OP_KEEP, DepthFailOp: VK_STENCIL_OP_KEEP, CompareOp: VK_COMPARE_OP_ALWAYS},
	}
	dynamicStates := []VkDynamicState{VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR}
	dynamic := VkPipelineDynamicStateCreateInfo{
		SType:             VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO,
		DynamicStateCount: uint32(len(dynamicStates)),
		PDynamicStates:    &dynamicStates[0],
	}
	ci := VkGraphicsPipelineCreateInfo{
		SType:               VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO,
		StageCount:          uint32(len(stages)),
		PStages:             &stages[0],
		PVertexInputState:   &vertexInput,
		PInputAssemblyState: &inputAssembly,
		PViewportState:      &viewportState,
		PRasterizationState: &raster,
		PMultisampleState:   &multisample,
		PDepthStencilState:  &depthStencil,
		PColorBlendState:    &blend,
		PDynamicState:       &dynamic,
		Layout:              layout,
		RenderPass:          renderPass,
		Subpass:             0,
	}
	var pipeline VkPipeline
	res := callResult(procs.vkCreateGraphicsPipelines, uintptr(device), 0, 1, uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&pipeline)))
	runtime.KeepAlive(entry)
	return pipeline, res
}
