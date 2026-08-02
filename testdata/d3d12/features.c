/* Direct3D 12 workload for what the other workloads leave out: an indirect draw (ExecuteIndirect with a command signature) of two instanced
 * quads built from the vertex number, two render targets of which the first is blended over its clear colour, root constants that carry the
 * quad colours, and an occlusion query resolved into a read-back buffer. The targets are copied to read-back buffers and written to
 * C:\features12_0.raw and C:\features12_1.raw as RGBA bytes; the samples that passed are written to C:\features12_samples.raw as a 64-bit value;
 * C:\features12.txt holds OK or the first failing step. The shaders are features12.hlsl compiled for vs_5_0 and ps_5_0. */
#define COBJMACROS
#include <windows.h>
#include <d3d12.h>
#include "features12_shaders.h"

#define SIZE 256

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
	write_file(L"C:\\features12.txt", text, (DWORD)length);
	ExitProcess(1);
}

#define CHECK(step, call) do { HRESULT result_ = (call); if (FAILED(result_)) fail(step, result_); } while (0)

static ID3D12Resource *buffer_of(ID3D12Device *device, D3D12_HEAP_TYPE type, UINT64 size, D3D12_RESOURCE_STATES state)
{
	D3D12_HEAP_PROPERTIES heap = {type, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};
	D3D12_RESOURCE_DESC desc = {D3D12_RESOURCE_DIMENSION_BUFFER, 0, size, 1, 1, 1, DXGI_FORMAT_UNKNOWN, {1, 0}, D3D12_TEXTURE_LAYOUT_ROW_MAJOR,
		D3D12_RESOURCE_FLAG_NONE};
	ID3D12Resource *buffer = NULL;
	CHECK("buffer", ID3D12Device_CreateCommittedResource(device, &heap, D3D12_HEAP_FLAG_NONE, &desc, state, NULL, &IID_ID3D12Resource, (void **)&buffer));
	return buffer;
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

	/* Eight 32-bit constants for the pixel shader: two colours. */
	D3D12_ROOT_PARAMETER parameter = {D3D12_ROOT_PARAMETER_TYPE_32BIT_CONSTANTS};
	parameter.Constants.ShaderRegister = 0;
	parameter.Constants.RegisterSpace = 0;
	parameter.Constants.Num32BitValues = 8;
	parameter.ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;
	D3D12_ROOT_SIGNATURE_DESC root_desc = {1, &parameter, 0, NULL, D3D12_ROOT_SIGNATURE_FLAG_NONE};
	ID3DBlob *serialized = NULL, *errors = NULL;
	CHECK("serialize root signature", D3D12SerializeRootSignature(&root_desc, D3D_ROOT_SIGNATURE_VERSION_1, &serialized, &errors));
	ID3D12RootSignature *root = NULL;
	CHECK("root signature", ID3D12Device_CreateRootSignature(device, 0, ID3D10Blob_GetBufferPointer(serialized), ID3D10Blob_GetBufferSize(serialized),
		&IID_ID3D12RootSignature, (void **)&root));

	D3D12_GRAPHICS_PIPELINE_STATE_DESC pipeline = {0};
	pipeline.pRootSignature = root;
	pipeline.VS.pShaderBytecode = features12_vs;
	pipeline.VS.BytecodeLength = sizeof(features12_vs);
	pipeline.PS.pShaderBytecode = features12_ps;
	pipeline.PS.BytecodeLength = sizeof(features12_ps);
	pipeline.BlendState.IndependentBlendEnable = TRUE;
	pipeline.BlendState.RenderTarget[0].BlendEnable = TRUE;
	pipeline.BlendState.RenderTarget[0].SrcBlend = D3D12_BLEND_SRC_ALPHA;
	pipeline.BlendState.RenderTarget[0].DestBlend = D3D12_BLEND_INV_SRC_ALPHA;
	pipeline.BlendState.RenderTarget[0].BlendOp = D3D12_BLEND_OP_ADD;
	pipeline.BlendState.RenderTarget[0].SrcBlendAlpha = D3D12_BLEND_ONE;
	pipeline.BlendState.RenderTarget[0].DestBlendAlpha = D3D12_BLEND_ZERO;
	pipeline.BlendState.RenderTarget[0].BlendOpAlpha = D3D12_BLEND_OP_ADD;
	pipeline.BlendState.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;
	pipeline.BlendState.RenderTarget[1].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;
	pipeline.SampleMask = 0xffffffffu;
	pipeline.RasterizerState.FillMode = D3D12_FILL_MODE_SOLID;
	pipeline.RasterizerState.CullMode = D3D12_CULL_MODE_NONE;
	pipeline.RasterizerState.DepthClipEnable = TRUE;
	pipeline.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
	pipeline.NumRenderTargets = 2;
	pipeline.RTVFormats[0] = DXGI_FORMAT_R8G8B8A8_UNORM;
	pipeline.RTVFormats[1] = DXGI_FORMAT_R8G8B8A8_UNORM;
	pipeline.SampleDesc.Count = 1;
	ID3D12PipelineState *state = NULL;
	CHECK("pipeline", ID3D12Device_CreateGraphicsPipelineState(device, &pipeline, &IID_ID3D12PipelineState, (void **)&state));

	D3D12_INDIRECT_ARGUMENT_DESC argument = {D3D12_INDIRECT_ARGUMENT_TYPE_DRAW};
	D3D12_COMMAND_SIGNATURE_DESC signature_desc = {sizeof(UINT) * 4, 1, &argument, 0};
	ID3D12CommandSignature *signature = NULL;
	CHECK("command signature", ID3D12Device_CreateCommandSignature(device, &signature_desc, NULL, &IID_ID3D12CommandSignature, (void **)&signature));
	ID3D12Resource *arguments = buffer_of(device, D3D12_HEAP_TYPE_UPLOAD, 16, D3D12_RESOURCE_STATE_GENERIC_READ);
	void *mapped_arguments = NULL;
	CHECK("map arguments", ID3D12Resource_Map(arguments, 0, NULL, &mapped_arguments));
	{
		UINT *values = mapped_arguments;
		values[0] = 4;
		values[1] = 2;
		values[2] = 0;
		values[3] = 0;
	}
	ID3D12Resource_Unmap(arguments, 0, NULL);

	D3D12_QUERY_HEAP_DESC query_desc = {D3D12_QUERY_HEAP_TYPE_OCCLUSION, 1, 0};
	ID3D12QueryHeap *query_heap = NULL;
	CHECK("query heap", ID3D12Device_CreateQueryHeap(device, &query_desc, &IID_ID3D12QueryHeap, (void **)&query_heap));
	ID3D12Resource *query_result = buffer_of(device, D3D12_HEAP_TYPE_READBACK, 8, D3D12_RESOURCE_STATE_COPY_DEST);

	ID3D12GraphicsCommandList *list = NULL;
	CHECK("list", ID3D12Device_CreateCommandList(device, 0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator, state, &IID_ID3D12GraphicsCommandList, (void **)&list));

	D3D12_HEAP_PROPERTIES default_heap = {D3D12_HEAP_TYPE_DEFAULT, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};
	D3D12_RESOURCE_DESC texture = {D3D12_RESOURCE_DIMENSION_TEXTURE2D, 0, SIZE, SIZE, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0},
		D3D12_TEXTURE_LAYOUT_UNKNOWN, D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET};
	const float black[4] = {0.0f, 0.0f, 0.0f, 1.0f}, grey[4] = {0.2f, 0.2f, 0.2f, 1.0f};
	const float *clears[2] = {black, grey};
	ID3D12Resource *targets[2] = {NULL, NULL};
	D3D12_DESCRIPTOR_HEAP_DESC heap_desc = {D3D12_DESCRIPTOR_HEAP_TYPE_RTV, 2, D3D12_DESCRIPTOR_HEAP_FLAG_NONE, 0};
	ID3D12DescriptorHeap *heap = NULL;
	CHECK("rtv heap", ID3D12Device_CreateDescriptorHeap(device, &heap_desc, &IID_ID3D12DescriptorHeap, (void **)&heap));
	D3D12_CPU_DESCRIPTOR_HANDLE rtvs[2];
	heap->lpVtbl->GetCPUDescriptorHandleForHeapStart(heap, &rtvs[0]);
	const UINT step = ID3D12Device_GetDescriptorHandleIncrementSize(device, D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
	rtvs[1].ptr = rtvs[0].ptr + step;
	for (int index = 0; index < 2; ++index) {
		D3D12_CLEAR_VALUE clear = {DXGI_FORMAT_R8G8B8A8_UNORM, {{clears[index][0], clears[index][1], clears[index][2], clears[index][3]}}};
		CHECK("target", ID3D12Device_CreateCommittedResource(device, &default_heap, D3D12_HEAP_FLAG_NONE, &texture, D3D12_RESOURCE_STATE_RENDER_TARGET,
			&clear, &IID_ID3D12Resource, (void **)&targets[index]));
		ID3D12Device_CreateRenderTargetView(device, targets[index], NULL, rtvs[index]);
	}

	const UINT pitch = SIZE * 4;
	ID3D12Resource *readbacks[2];
	for (int index = 0; index < 2; ++index)
		readbacks[index] = buffer_of(device, D3D12_HEAP_TYPE_READBACK, (UINT64)pitch * SIZE, D3D12_RESOURCE_STATE_COPY_DEST);

	const float constants[8] = {1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f, 1.0f};
	D3D12_VIEWPORT viewport = {0, 0, SIZE, SIZE, 0, 1};
	D3D12_RECT scissor = {0, 0, SIZE, SIZE};
	ID3D12GraphicsCommandList_SetGraphicsRootSignature(list, root);
	ID3D12GraphicsCommandList_RSSetViewports(list, 1, &viewport);
	ID3D12GraphicsCommandList_RSSetScissorRects(list, 1, &scissor);
	ID3D12GraphicsCommandList_OMSetRenderTargets(list, 2, rtvs, FALSE, NULL);
	ID3D12GraphicsCommandList_ClearRenderTargetView(list, rtvs[0], black, 0, NULL);
	ID3D12GraphicsCommandList_ClearRenderTargetView(list, rtvs[1], grey, 0, NULL);
	ID3D12GraphicsCommandList_SetGraphicsRoot32BitConstants(list, 0, 8, constants, 0);
	ID3D12GraphicsCommandList_IASetPrimitiveTopology(list, D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
	ID3D12GraphicsCommandList_BeginQuery(list, query_heap, D3D12_QUERY_TYPE_OCCLUSION, 0);
	ID3D12GraphicsCommandList_ExecuteIndirect(list, signature, 1, arguments, 0, NULL, 0);
	ID3D12GraphicsCommandList_EndQuery(list, query_heap, D3D12_QUERY_TYPE_OCCLUSION, 0);
	ID3D12GraphicsCommandList_ResolveQueryData(list, query_heap, D3D12_QUERY_TYPE_OCCLUSION, 0, 1, query_result, 0);

	for (int index = 0; index < 2; ++index) {
		D3D12_RESOURCE_BARRIER barrier = {D3D12_RESOURCE_BARRIER_TYPE_TRANSITION, D3D12_RESOURCE_BARRIER_FLAG_NONE};
		barrier.Transition.pResource = targets[index];
		barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
		barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
		barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_SOURCE;
		ID3D12GraphicsCommandList_ResourceBarrier(list, 1, &barrier);
		D3D12_TEXTURE_COPY_LOCATION destination = {readbacks[index], D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT};
		destination.PlacedFootprint.Footprint.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
		destination.PlacedFootprint.Footprint.Width = SIZE;
		destination.PlacedFootprint.Footprint.Height = SIZE;
		destination.PlacedFootprint.Footprint.Depth = 1;
		destination.PlacedFootprint.Footprint.RowPitch = pitch;
		D3D12_TEXTURE_COPY_LOCATION source = {targets[index], D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX};
		ID3D12GraphicsCommandList_CopyTextureRegion(list, &destination, 0, 0, 0, &source, NULL);
	}
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

	const wchar_t *names[2] = {L"C:\\features12_0.raw", L"C:\\features12_1.raw"};
	for (int index = 0; index < 2; ++index) {
		void *mapped = NULL;
		D3D12_RANGE range = {0, (SIZE_T)pitch * SIZE};
		CHECK("map", ID3D12Resource_Map(readbacks[index], 0, &range, &mapped));
		write_file(names[index], mapped, pitch * SIZE);
		D3D12_RANGE none = {0, 0};
		ID3D12Resource_Unmap(readbacks[index], 0, &none);
	}
	void *mapped_samples = NULL;
	D3D12_RANGE samples_range = {0, 8};
	CHECK("map query", ID3D12Resource_Map(query_result, 0, &samples_range, &mapped_samples));
	write_file(L"C:\\features12_samples.raw", mapped_samples, 8);
	D3D12_RANGE none = {0, 0};
	ID3D12Resource_Unmap(query_result, 0, &none);
	write_file(L"C:\\features12.txt", "OK", 2);
	ExitProcess(0);
}
