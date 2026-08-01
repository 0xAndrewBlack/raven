/* Direct3D 12 workload: the scene of the Direct3D 11 textured test with Direct3D 12 resource binding. An 8 by 8 texture is uploaded through an
 * upload buffer and bound with a descriptor table, a point sampler with a second table, the tint travels as root constants and a depth buffer
 * hides the far quad. The pixels are read back into C:\textured12.raw; C:\textured12.txt holds OK or the first failing step. The shaders are
 * ../d3d11/tex.hlsl compiled for vs_5_0 and ps_5_0. */
#define COBJMACROS
#include <windows.h>
#include <d3d12.h>
#include "tex5_shaders.h"

#define SIZE 256

struct vertex { float x, y, z, u, v; };

static void write_file(const wchar_t *path, const void *data, DWORD size)
{
	HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD n;
	WriteFile(f, data, size, &n, NULL);
	CloseHandle(f);
}

static void fail(const char *step, HRESULT hr)
{
	char text[96];
	int length = 0;
	const char *prefix = "FAIL ";
	while (*prefix)
		text[length++] = *prefix++;
	while (*step && length < 70)
		text[length++] = *step++;
	text[length++] = ' ';
	for (int shift = 28; shift >= 0; shift -= 4)
		text[length++] = "0123456789abcdef"[((unsigned)hr >> shift) & 15];
	write_file(L"C:\\textured12.txt", text, (DWORD)length);
	ExitProcess(1);
}

#define CHECK(step, call) do { HRESULT result_ = (call); if (FAILED(result_)) fail(step, result_); } while (0)

static void quad(struct vertex *out, float x0, float y0, float x1, float y1, float z)
{
	const struct vertex corners[4] = {{x0, y1, z, 0, 0}, {x1, y1, z, 1, 0}, {x1, y0, z, 1, 1}, {x0, y0, z, 0, 1}};
	const int order[6] = {0, 1, 2, 0, 2, 3};
	for (int index = 0; index < 6; ++index)
		out[index] = corners[order[index]];
}

static void barrier(ID3D12GraphicsCommandList *list, ID3D12Resource *resource, D3D12_RESOURCE_STATES before, D3D12_RESOURCE_STATES after)
{
	D3D12_RESOURCE_BARRIER item = {D3D12_RESOURCE_BARRIER_TYPE_TRANSITION, D3D12_RESOURCE_BARRIER_FLAG_NONE};
	item.Transition.pResource = resource;
	item.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
	item.Transition.StateBefore = before;
	item.Transition.StateAfter = after;
	ID3D12GraphicsCommandList_ResourceBarrier(list, 1, &item);
}

static ID3D12DescriptorHeap *heap_of(ID3D12Device *device, D3D12_DESCRIPTOR_HEAP_TYPE type, D3D12_DESCRIPTOR_HEAP_FLAGS flags, const char *step)
{
	D3D12_DESCRIPTOR_HEAP_DESC desc = {type, 1, flags, 0};
	ID3D12DescriptorHeap *heap = NULL;
	CHECK(step, ID3D12Device_CreateDescriptorHeap(device, &desc, &IID_ID3D12DescriptorHeap, (void **)&heap));
	return heap;
}

void __stdcall entry(void)
{
	ID3D12Device *device = NULL;
	CHECK("device", D3D12CreateDevice(NULL, D3D_FEATURE_LEVEL_11_0, &IID_ID3D12Device, (void **)&device));
	D3D12_COMMAND_QUEUE_DESC queue_desc = {D3D12_COMMAND_LIST_TYPE_DIRECT, 0, D3D12_COMMAND_QUEUE_FLAG_NONE, 0};
	ID3D12CommandQueue *queue = NULL;
	CHECK("queue", ID3D12Device_CreateCommandQueue(device, &queue_desc, &IID_ID3D12CommandQueue, (void **)&queue));
	ID3D12CommandAllocator *allocator = NULL;
	CHECK("allocator", ID3D12Device_CreateCommandAllocator(device, D3D12_COMMAND_LIST_TYPE_DIRECT, &IID_ID3D12CommandAllocator, (void **)&allocator));

	/* Root signature: a table with the texture, a table with the sampler and four root constants for the tint. */
	D3D12_DESCRIPTOR_RANGE srv_range = {D3D12_DESCRIPTOR_RANGE_TYPE_SRV, 1, 0, 0, D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND};
	D3D12_DESCRIPTOR_RANGE sampler_range = {D3D12_DESCRIPTOR_RANGE_TYPE_SAMPLER, 1, 0, 0, D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND};
	D3D12_ROOT_PARAMETER parameters[3] = {0};
	parameters[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
	parameters[0].DescriptorTable.NumDescriptorRanges = 1;
	parameters[0].DescriptorTable.pDescriptorRanges = &srv_range;
	parameters[0].ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;
	parameters[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
	parameters[1].DescriptorTable.NumDescriptorRanges = 1;
	parameters[1].DescriptorTable.pDescriptorRanges = &sampler_range;
	parameters[1].ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;
	parameters[2].ParameterType = D3D12_ROOT_PARAMETER_TYPE_32BIT_CONSTANTS;
	parameters[2].Constants.ShaderRegister = 0;
	parameters[2].Constants.RegisterSpace = 0;
	parameters[2].Constants.Num32BitValues = 4;
	parameters[2].ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;
	D3D12_ROOT_SIGNATURE_DESC root_desc = {3, parameters, 0, NULL, D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT};
	ID3DBlob *serialized = NULL, *errors = NULL;
	CHECK("serialize root signature", D3D12SerializeRootSignature(&root_desc, D3D_ROOT_SIGNATURE_VERSION_1, &serialized, &errors));
	ID3D12RootSignature *root = NULL;
	CHECK("root signature", ID3D12Device_CreateRootSignature(device, 0, ID3D10Blob_GetBufferPointer(serialized), ID3D10Blob_GetBufferSize(serialized),
		&IID_ID3D12RootSignature, (void **)&root));

	D3D12_INPUT_ELEMENT_DESC elements[] = {
		{"POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
		{"TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 12, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
	};
	D3D12_GRAPHICS_PIPELINE_STATE_DESC pipeline = {0};
	pipeline.pRootSignature = root;
	pipeline.VS.pShaderBytecode = tex5_vs;
	pipeline.VS.BytecodeLength = sizeof(tex5_vs);
	pipeline.PS.pShaderBytecode = tex5_ps;
	pipeline.PS.BytecodeLength = sizeof(tex5_ps);
	pipeline.BlendState.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;
	pipeline.SampleMask = 0xffffffffu;
	pipeline.RasterizerState.FillMode = D3D12_FILL_MODE_SOLID;
	pipeline.RasterizerState.CullMode = D3D12_CULL_MODE_NONE;
	pipeline.RasterizerState.DepthClipEnable = TRUE;
	pipeline.DepthStencilState.DepthEnable = TRUE;
	pipeline.DepthStencilState.DepthWriteMask = D3D12_DEPTH_WRITE_MASK_ALL;
	pipeline.DepthStencilState.DepthFunc = D3D12_COMPARISON_FUNC_LESS;
	pipeline.InputLayout.pInputElementDescs = elements;
	pipeline.InputLayout.NumElements = 2;
	pipeline.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
	pipeline.NumRenderTargets = 1;
	pipeline.RTVFormats[0] = DXGI_FORMAT_R8G8B8A8_UNORM;
	pipeline.DSVFormat = DXGI_FORMAT_D32_FLOAT;
	pipeline.SampleDesc.Count = 1;
	ID3D12PipelineState *state = NULL;
	CHECK("pipeline", ID3D12Device_CreateGraphicsPipelineState(device, &pipeline, &IID_ID3D12PipelineState, (void **)&state));
	ID3D12GraphicsCommandList *list = NULL;
	CHECK("list", ID3D12Device_CreateCommandList(device, 0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator, state, &IID_ID3D12GraphicsCommandList, (void **)&list));

	D3D12_HEAP_PROPERTIES default_heap = {D3D12_HEAP_TYPE_DEFAULT, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};
	D3D12_HEAP_PROPERTIES upload_heap = {D3D12_HEAP_TYPE_UPLOAD, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};
	D3D12_HEAP_PROPERTIES readback_heap = {D3D12_HEAP_TYPE_READBACK, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};

	D3D12_RESOURCE_DESC target_desc = {D3D12_RESOURCE_DIMENSION_TEXTURE2D, 0, SIZE, SIZE, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0},
		D3D12_TEXTURE_LAYOUT_UNKNOWN, D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET};
	const float color[4] = {0.1f, 0.1f, 0.3f, 1.0f};
	D3D12_CLEAR_VALUE target_clear = {DXGI_FORMAT_R8G8B8A8_UNORM, {{color[0], color[1], color[2], color[3]}}};
	ID3D12Resource *target = NULL;
	CHECK("target", ID3D12Device_CreateCommittedResource(device, &default_heap, D3D12_HEAP_FLAG_NONE, &target_desc, D3D12_RESOURCE_STATE_RENDER_TARGET,
		&target_clear, &IID_ID3D12Resource, (void **)&target));
	D3D12_RESOURCE_DESC depth_desc = {D3D12_RESOURCE_DIMENSION_TEXTURE2D, 0, SIZE, SIZE, 1, 1, DXGI_FORMAT_D32_FLOAT, {1, 0},
		D3D12_TEXTURE_LAYOUT_UNKNOWN, D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL};
	D3D12_CLEAR_VALUE depth_clear = {DXGI_FORMAT_D32_FLOAT};
	depth_clear.DepthStencil.Depth = 1.0f;
	ID3D12Resource *depth = NULL;
	CHECK("depth", ID3D12Device_CreateCommittedResource(device, &default_heap, D3D12_HEAP_FLAG_NONE, &depth_desc, D3D12_RESOURCE_STATE_DEPTH_WRITE,
		&depth_clear, &IID_ID3D12Resource, (void **)&depth));

	/* The checkerboard texture, filled through an upload buffer whose rows are 256 bytes apart. */
	D3D12_RESOURCE_DESC texture_desc = {D3D12_RESOURCE_DIMENSION_TEXTURE2D, 0, 8, 8, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0},
		D3D12_TEXTURE_LAYOUT_UNKNOWN, D3D12_RESOURCE_FLAG_NONE};
	ID3D12Resource *texture = NULL;
	CHECK("texture", ID3D12Device_CreateCommittedResource(device, &default_heap, D3D12_HEAP_FLAG_NONE, &texture_desc, D3D12_RESOURCE_STATE_COPY_DEST,
		NULL, &IID_ID3D12Resource, (void **)&texture));
	D3D12_RESOURCE_DESC staging_desc = {D3D12_RESOURCE_DIMENSION_BUFFER, 0, 256 * 8, 1, 1, 1, DXGI_FORMAT_UNKNOWN, {1, 0},
		D3D12_TEXTURE_LAYOUT_ROW_MAJOR, D3D12_RESOURCE_FLAG_NONE};
	ID3D12Resource *texture_upload = NULL;
	CHECK("texture upload", ID3D12Device_CreateCommittedResource(device, &upload_heap, D3D12_HEAP_FLAG_NONE, &staging_desc, D3D12_RESOURCE_STATE_GENERIC_READ,
		NULL, &IID_ID3D12Resource, (void **)&texture_upload));
	BYTE *mapped_texels = NULL;
	CHECK("map texture upload", ID3D12Resource_Map(texture_upload, 0, NULL, (void **)&mapped_texels));
	for (int row = 0; row < 8; ++row)
		for (int column = 0; column < 8; ++column) {
			BYTE *texel = mapped_texels + row * 256 + column * 4;
			const int red = ((row + column) & 1) == 0;
			texel[0] = red ? 255 : 240;
			texel[1] = red ? 64 : 240;
			texel[2] = red ? 64 : 240;
			texel[3] = 255;
		}
	ID3D12Resource_Unmap(texture_upload, 0, NULL);

	struct vertex vertices[12];
	quad(vertices, -0.6f, -0.4f, 0.2f, 0.6f, 0.2f);
	quad(vertices + 6, -0.2f, -0.7f, 0.7f, 0.3f, 0.7f);
	D3D12_RESOURCE_DESC vertex_desc = {D3D12_RESOURCE_DIMENSION_BUFFER, 0, sizeof vertices, 1, 1, 1, DXGI_FORMAT_UNKNOWN, {1, 0},
		D3D12_TEXTURE_LAYOUT_ROW_MAJOR, D3D12_RESOURCE_FLAG_NONE};
	ID3D12Resource *vertex_upload = NULL;
	CHECK("vertex buffer", ID3D12Device_CreateCommittedResource(device, &upload_heap, D3D12_HEAP_FLAG_NONE, &vertex_desc, D3D12_RESOURCE_STATE_GENERIC_READ,
		NULL, &IID_ID3D12Resource, (void **)&vertex_upload));
	void *mapped_vertices = NULL;
	CHECK("map vertices", ID3D12Resource_Map(vertex_upload, 0, NULL, &mapped_vertices));
	for (unsigned index = 0; index < sizeof vertices; ++index)
		((BYTE *)mapped_vertices)[index] = ((const BYTE *)vertices)[index];
	ID3D12Resource_Unmap(vertex_upload, 0, NULL);

	const UINT pitch = SIZE * 4;
	D3D12_RESOURCE_DESC readback_desc = {D3D12_RESOURCE_DIMENSION_BUFFER, 0, (UINT64)pitch * SIZE, 1, 1, 1, DXGI_FORMAT_UNKNOWN, {1, 0},
		D3D12_TEXTURE_LAYOUT_ROW_MAJOR, D3D12_RESOURCE_FLAG_NONE};
	ID3D12Resource *readback = NULL;
	CHECK("readback", ID3D12Device_CreateCommittedResource(device, &readback_heap, D3D12_HEAP_FLAG_NONE, &readback_desc, D3D12_RESOURCE_STATE_COPY_DEST,
		NULL, &IID_ID3D12Resource, (void **)&readback));

	ID3D12DescriptorHeap *rtv_heap = heap_of(device, D3D12_DESCRIPTOR_HEAP_TYPE_RTV, D3D12_DESCRIPTOR_HEAP_FLAG_NONE, "rtv heap");
	ID3D12DescriptorHeap *dsv_heap = heap_of(device, D3D12_DESCRIPTOR_HEAP_TYPE_DSV, D3D12_DESCRIPTOR_HEAP_FLAG_NONE, "dsv heap");
	ID3D12DescriptorHeap *srv_heap = heap_of(device, D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV, D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE, "srv heap");
	ID3D12DescriptorHeap *sampler_heap = heap_of(device, D3D12_DESCRIPTOR_HEAP_TYPE_SAMPLER, D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE, "sampler heap");
	D3D12_CPU_DESCRIPTOR_HANDLE rtv, dsv, srv, sampler;
	rtv_heap->lpVtbl->GetCPUDescriptorHandleForHeapStart(rtv_heap, &rtv);
	dsv_heap->lpVtbl->GetCPUDescriptorHandleForHeapStart(dsv_heap, &dsv);
	srv_heap->lpVtbl->GetCPUDescriptorHandleForHeapStart(srv_heap, &srv);
	sampler_heap->lpVtbl->GetCPUDescriptorHandleForHeapStart(sampler_heap, &sampler);
	D3D12_GPU_DESCRIPTOR_HANDLE srv_gpu, sampler_gpu;
	srv_heap->lpVtbl->GetGPUDescriptorHandleForHeapStart(srv_heap, &srv_gpu);
	sampler_heap->lpVtbl->GetGPUDescriptorHandleForHeapStart(sampler_heap, &sampler_gpu);
	ID3D12Device_CreateRenderTargetView(device, target, NULL, rtv);
	ID3D12Device_CreateDepthStencilView(device, depth, NULL, dsv);
	D3D12_SHADER_RESOURCE_VIEW_DESC srv_desc = {DXGI_FORMAT_R8G8B8A8_UNORM, D3D12_SRV_DIMENSION_TEXTURE2D, D3D12_ENCODE_SHADER_4_COMPONENT_MAPPING(0, 1, 2, 3)};
	srv_desc.Texture2D.MipLevels = 1;
	ID3D12Device_CreateShaderResourceView(device, texture, &srv_desc, srv);
	D3D12_SAMPLER_DESC sampler_desc = {D3D12_FILTER_MIN_MAG_MIP_POINT, D3D12_TEXTURE_ADDRESS_MODE_CLAMP, D3D12_TEXTURE_ADDRESS_MODE_CLAMP,
		D3D12_TEXTURE_ADDRESS_MODE_CLAMP, 0, 1, D3D12_COMPARISON_FUNC_NEVER, {0, 0, 0, 0}, 0, D3D12_FLOAT32_MAX};
	ID3D12Device_CreateSampler(device, &sampler_desc, sampler);

	/* Upload the texture, then draw both quads. */
	D3D12_TEXTURE_COPY_LOCATION texture_destination = {texture, D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX};
	D3D12_TEXTURE_COPY_LOCATION texture_source = {texture_upload, D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT};
	texture_source.PlacedFootprint.Footprint.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	texture_source.PlacedFootprint.Footprint.Width = 8;
	texture_source.PlacedFootprint.Footprint.Height = 8;
	texture_source.PlacedFootprint.Footprint.Depth = 1;
	texture_source.PlacedFootprint.Footprint.RowPitch = 256;
	ID3D12GraphicsCommandList_CopyTextureRegion(list, &texture_destination, 0, 0, 0, &texture_source, NULL);
	barrier(list, texture, D3D12_RESOURCE_STATE_COPY_DEST, D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE);

	D3D12_VIEWPORT viewport = {0, 0, SIZE, SIZE, 0, 1};
	D3D12_RECT scissor = {0, 0, SIZE, SIZE};
	D3D12_VERTEX_BUFFER_VIEW view = {ID3D12Resource_GetGPUVirtualAddress(vertex_upload), sizeof vertices, sizeof(struct vertex)};
	ID3D12DescriptorHeap *heaps[] = {srv_heap, sampler_heap};
	ID3D12GraphicsCommandList_SetDescriptorHeaps(list, 2, heaps);
	ID3D12GraphicsCommandList_SetGraphicsRootSignature(list, root);
	ID3D12GraphicsCommandList_SetGraphicsRootDescriptorTable(list, 0, srv_gpu);
	ID3D12GraphicsCommandList_SetGraphicsRootDescriptorTable(list, 1, sampler_gpu);
	ID3D12GraphicsCommandList_RSSetViewports(list, 1, &viewport);
	ID3D12GraphicsCommandList_RSSetScissorRects(list, 1, &scissor);
	ID3D12GraphicsCommandList_OMSetRenderTargets(list, 1, &rtv, FALSE, &dsv);
	ID3D12GraphicsCommandList_ClearRenderTargetView(list, rtv, color, 0, NULL);
	ID3D12GraphicsCommandList_ClearDepthStencilView(list, dsv, D3D12_CLEAR_FLAG_DEPTH, 1.0f, 0, 0, NULL);
	ID3D12GraphicsCommandList_IASetPrimitiveTopology(list, D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
	ID3D12GraphicsCommandList_IASetVertexBuffers(list, 0, 1, &view);
	const float near_tint[4] = {1.0f, 1.0f, 1.0f, 1.0f};
	const float far_tint[4] = {0.3f, 0.8f, 1.0f, 1.0f};
	ID3D12GraphicsCommandList_SetGraphicsRoot32BitConstants(list, 2, 4, near_tint, 0);
	ID3D12GraphicsCommandList_DrawInstanced(list, 6, 1, 0, 0);
	ID3D12GraphicsCommandList_SetGraphicsRoot32BitConstants(list, 2, 4, far_tint, 0);
	ID3D12GraphicsCommandList_DrawInstanced(list, 6, 1, 6, 0);

	barrier(list, target, D3D12_RESOURCE_STATE_RENDER_TARGET, D3D12_RESOURCE_STATE_COPY_SOURCE);
	D3D12_TEXTURE_COPY_LOCATION destination = {readback, D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT};
	destination.PlacedFootprint.Footprint.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	destination.PlacedFootprint.Footprint.Width = SIZE;
	destination.PlacedFootprint.Footprint.Height = SIZE;
	destination.PlacedFootprint.Footprint.Depth = 1;
	destination.PlacedFootprint.Footprint.RowPitch = pitch;
	D3D12_TEXTURE_COPY_LOCATION source = {target, D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX};
	ID3D12GraphicsCommandList_CopyTextureRegion(list, &destination, 0, 0, 0, &source, NULL);
	CHECK("close", ID3D12GraphicsCommandList_Close(list));

	ID3D12Fence *fence = NULL;
	CHECK("fence", ID3D12Device_CreateFence(device, 0, D3D12_FENCE_FLAG_NONE, &IID_ID3D12Fence, (void **)&fence));
	ID3D12CommandList *lists[] = {(ID3D12CommandList *)list};
	ID3D12CommandQueue_ExecuteCommandLists(queue, 1, lists);
	CHECK("signal", ID3D12CommandQueue_Signal(queue, fence, 1));
	HANDLE event = CreateEventW(NULL, FALSE, FALSE, NULL);
	CHECK("completion", ID3D12Fence_SetEventOnCompletion(fence, 1, event));
	if (WaitForSingleObject(event, 20000) != WAIT_OBJECT_0)
		fail("wait", 0);

	void *mapped = NULL;
	D3D12_RANGE range = {0, (SIZE_T)pitch * SIZE};
	CHECK("map", ID3D12Resource_Map(readback, 0, &range, &mapped));
	write_file(L"C:\\textured12.raw", mapped, pitch * SIZE);
	D3D12_RANGE none = {0, 0};
	ID3D12Resource_Unmap(readback, 0, &none);
	write_file(L"C:\\textured12.txt", "OK", 2);
	ExitProcess(0);
}
