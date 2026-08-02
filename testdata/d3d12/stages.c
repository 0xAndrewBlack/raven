/* Direct3D 12 workload with more pipeline stages: draws one vertex-coloured triangle like draw.c, but the pipeline also has the hand
 * assembled stages of the Direct3D 11 workloads, which halve the triangle: a geometry shader (built with -DGEOMETRY) or a hull and domain
 * shader pair that tessellate a three control point patch (built with -DTESSELLATION). The pixels go to C:\stages.raw and C:\stages.txt
 * holds OK or the first failing step. The shaders are ../d3d11/tri.hlsl compiled for vs_5_0 and ps_5_0. */
#define COBJMACROS
#include <windows.h>
#include <d3d12.h>
#include "tri5_shaders.h"
#include "../d3d11/gs_shaders.h"
#include "../d3d11/tess_shaders.h"

#define SIZE 256

struct vertex { float x, y; float r, g, b, a; };

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
	write_file(L"C:\\stages.txt", text, (DWORD)length);
	ExitProcess(1);
}

#define CHECK(step, call) do { HRESULT result_ = (call); if (FAILED(result_)) fail(step, result_); } while (0)

void __stdcall entry(void)
{
	ID3D12Device *device = NULL;
	CHECK("device", D3D12CreateDevice(NULL, D3D_FEATURE_LEVEL_11_0, &IID_ID3D12Device, (void **)&device));
	D3D12_COMMAND_QUEUE_DESC queue_desc = {D3D12_COMMAND_LIST_TYPE_DIRECT, 0, D3D12_COMMAND_QUEUE_FLAG_NONE, 0};
	ID3D12CommandQueue *queue = NULL;
	CHECK("queue", ID3D12Device_CreateCommandQueue(device, &queue_desc, &IID_ID3D12CommandQueue, (void **)&queue));
	ID3D12CommandAllocator *allocator = NULL;
	CHECK("allocator", ID3D12Device_CreateCommandAllocator(device, D3D12_COMMAND_LIST_TYPE_DIRECT, &IID_ID3D12CommandAllocator, (void **)&allocator));

	/* An empty root signature that only allows the input assembler. */
	D3D12_ROOT_SIGNATURE_DESC root_desc = {0, NULL, 0, NULL, D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT};
	ID3DBlob *serialized = NULL, *errors = NULL;
	CHECK("serialize root signature", D3D12SerializeRootSignature(&root_desc, D3D_ROOT_SIGNATURE_VERSION_1, &serialized, &errors));
	ID3D12RootSignature *root = NULL;
	CHECK("root signature", ID3D12Device_CreateRootSignature(device, 0, ID3D10Blob_GetBufferPointer(serialized), ID3D10Blob_GetBufferSize(serialized),
		&IID_ID3D12RootSignature, (void **)&root));

	D3D12_INPUT_ELEMENT_DESC elements[] = {
		{"POSITION", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 0, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
		{"COLOR", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 8, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
	};
	D3D12_GRAPHICS_PIPELINE_STATE_DESC pipeline = {0};
	pipeline.pRootSignature = root;
	pipeline.VS.pShaderBytecode = tri5_vs;
	pipeline.VS.BytecodeLength = sizeof(tri5_vs);
	pipeline.PS.pShaderBytecode = tri5_ps;
	pipeline.PS.BytecodeLength = sizeof(tri5_ps);
	pipeline.BlendState.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;
	pipeline.SampleMask = 0xffffffffu;
	pipeline.RasterizerState.FillMode = D3D12_FILL_MODE_SOLID;
	pipeline.RasterizerState.CullMode = D3D12_CULL_MODE_NONE;
	pipeline.RasterizerState.DepthClipEnable = TRUE;
	pipeline.InputLayout.pInputElementDescs = elements;
	pipeline.InputLayout.NumElements = 2;
#if defined(GEOMETRY)
	pipeline.GS.pShaderBytecode = tri_gs;
	pipeline.GS.BytecodeLength = sizeof(tri_gs);
	pipeline.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
#elif defined(TESSELLATION)
	pipeline.HS.pShaderBytecode = tri_hs;
	pipeline.HS.BytecodeLength = sizeof(tri_hs);
	pipeline.DS.pShaderBytecode = tri_ds;
	pipeline.DS.BytecodeLength = sizeof(tri_ds);
	pipeline.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_PATCH;
#endif
	pipeline.NumRenderTargets = 1;
	pipeline.RTVFormats[0] = DXGI_FORMAT_R8G8B8A8_UNORM;
	pipeline.SampleDesc.Count = 1;
	ID3D12PipelineState *state = NULL;
	CHECK("pipeline", ID3D12Device_CreateGraphicsPipelineState(device, &pipeline, &IID_ID3D12PipelineState, (void **)&state));

	ID3D12GraphicsCommandList *list = NULL;
	CHECK("list", ID3D12Device_CreateCommandList(device, 0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator, state, &IID_ID3D12GraphicsCommandList, (void **)&list));

	D3D12_HEAP_PROPERTIES default_heap = {D3D12_HEAP_TYPE_DEFAULT, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};
	D3D12_RESOURCE_DESC texture = {D3D12_RESOURCE_DIMENSION_TEXTURE2D, 0, SIZE, SIZE, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0},
		D3D12_TEXTURE_LAYOUT_UNKNOWN, D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET};
	const float color[4] = {0.1f, 0.1f, 0.3f, 1.0f};
	D3D12_CLEAR_VALUE clear = {DXGI_FORMAT_R8G8B8A8_UNORM, {{color[0], color[1], color[2], color[3]}}};
	ID3D12Resource *target = NULL;
	CHECK("target", ID3D12Device_CreateCommittedResource(device, &default_heap, D3D12_HEAP_FLAG_NONE, &texture, D3D12_RESOURCE_STATE_RENDER_TARGET,
		&clear, &IID_ID3D12Resource, (void **)&target));
	D3D12_DESCRIPTOR_HEAP_DESC heap_desc = {D3D12_DESCRIPTOR_HEAP_TYPE_RTV, 1, D3D12_DESCRIPTOR_HEAP_FLAG_NONE, 0};
	ID3D12DescriptorHeap *heap = NULL;
	CHECK("rtv heap", ID3D12Device_CreateDescriptorHeap(device, &heap_desc, &IID_ID3D12DescriptorHeap, (void **)&heap));
	D3D12_CPU_DESCRIPTOR_HANDLE rtv;
	heap->lpVtbl->GetCPUDescriptorHandleForHeapStart(heap, &rtv);
	ID3D12Device_CreateRenderTargetView(device, target, NULL, rtv);

	/* Clockwise or not, the pipeline culls nothing; the vertices are those of the Direct3D 11 workload. */
	struct vertex vertices[3] = {{-0.8f, -0.8f, 1, 0, 0, 1}, {0.0f, 0.8f, 0, 0, 1, 1}, {0.8f, -0.8f, 0, 1, 0, 1}};
	D3D12_HEAP_PROPERTIES upload_heap = {D3D12_HEAP_TYPE_UPLOAD, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};
	D3D12_RESOURCE_DESC vertex_buffer = {D3D12_RESOURCE_DIMENSION_BUFFER, 0, sizeof vertices, 1, 1, 1, DXGI_FORMAT_UNKNOWN, {1, 0},
		D3D12_TEXTURE_LAYOUT_ROW_MAJOR, D3D12_RESOURCE_FLAG_NONE};
	ID3D12Resource *upload = NULL;
	CHECK("vertex buffer", ID3D12Device_CreateCommittedResource(device, &upload_heap, D3D12_HEAP_FLAG_NONE, &vertex_buffer,
		D3D12_RESOURCE_STATE_GENERIC_READ, NULL, &IID_ID3D12Resource, (void **)&upload));
	void *mapped_vertices = NULL;
	CHECK("map vertices", ID3D12Resource_Map(upload, 0, NULL, &mapped_vertices));
	for (unsigned index = 0; index < sizeof vertices; ++index)
		((BYTE *)mapped_vertices)[index] = ((const BYTE *)vertices)[index];
	ID3D12Resource_Unmap(upload, 0, NULL);

	const UINT pitch = SIZE * 4;
	D3D12_HEAP_PROPERTIES readback_heap = {D3D12_HEAP_TYPE_READBACK, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};
	D3D12_RESOURCE_DESC buffer = {D3D12_RESOURCE_DIMENSION_BUFFER, 0, (UINT64)pitch * SIZE, 1, 1, 1, DXGI_FORMAT_UNKNOWN, {1, 0},
		D3D12_TEXTURE_LAYOUT_ROW_MAJOR, D3D12_RESOURCE_FLAG_NONE};
	ID3D12Resource *readback = NULL;
	CHECK("readback", ID3D12Device_CreateCommittedResource(device, &readback_heap, D3D12_HEAP_FLAG_NONE, &buffer, D3D12_RESOURCE_STATE_COPY_DEST,
		NULL, &IID_ID3D12Resource, (void **)&readback));

	D3D12_VIEWPORT viewport = {0, 0, SIZE, SIZE, 0, 1};
	D3D12_RECT scissor = {0, 0, SIZE, SIZE};
	D3D12_VERTEX_BUFFER_VIEW view = {ID3D12Resource_GetGPUVirtualAddress(upload), sizeof vertices, sizeof(struct vertex)};
	ID3D12GraphicsCommandList_SetGraphicsRootSignature(list, root);
	ID3D12GraphicsCommandList_RSSetViewports(list, 1, &viewport);
	ID3D12GraphicsCommandList_RSSetScissorRects(list, 1, &scissor);
	ID3D12GraphicsCommandList_OMSetRenderTargets(list, 1, &rtv, FALSE, NULL);
	ID3D12GraphicsCommandList_ClearRenderTargetView(list, rtv, color, 0, NULL);
#if defined(TESSELLATION)
	ID3D12GraphicsCommandList_IASetPrimitiveTopology(list, D3D_PRIMITIVE_TOPOLOGY_3_CONTROL_POINT_PATCHLIST);
#else
	ID3D12GraphicsCommandList_IASetPrimitiveTopology(list, D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
#endif
	ID3D12GraphicsCommandList_IASetVertexBuffers(list, 0, 1, &view);
	ID3D12GraphicsCommandList_DrawInstanced(list, 3, 1, 0, 0);

	D3D12_RESOURCE_BARRIER barrier = {D3D12_RESOURCE_BARRIER_TYPE_TRANSITION, D3D12_RESOURCE_BARRIER_FLAG_NONE};
	barrier.Transition.pResource = target;
	barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
	barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
	barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_SOURCE;
	ID3D12GraphicsCommandList_ResourceBarrier(list, 1, &barrier);
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
	write_file(L"C:\\stages.raw", mapped, pitch * SIZE);
	D3D12_RANGE none = {0, 0};
	ID3D12Resource_Unmap(readback, 0, &none);
	write_file(L"C:\\stages.txt", "OK", 2);
	ExitProcess(0);
}
