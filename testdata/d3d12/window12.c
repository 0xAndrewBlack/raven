/* Direct3D 12 workload with a window: draws the vertex-coloured triangle into the back buffers of a DXGI swap chain on a direct queue and
 * presents sixty frames. The last frame is also copied into a read-back buffer (C:\\window12_last.raw) before it is presented. C:\\window12.txt
 * holds OK once all frames are presented, or the first failing step. The program then keeps presenting the last picture for a capture. */
#define COBJMACROS
#include <windows.h>
#include <d3d12.h>
#include <dxgi1_4.h>
#include "tri5_shaders.h"

#define SIZE 256
#define FRAMES 60
#define BUFFERS 2

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
	write_file(L"C:\\window12.txt", text, (DWORD)length);
	ExitProcess(1);
}

#define CHECK(step, call) do { HRESULT result_ = (call); if (FAILED(result_)) fail(step, result_); } while (0)

static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
	if (message == WM_DESTROY) {
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProcW(window, message, wparam, lparam);
}

static void pump(void)
{
	MSG message;
	while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE)) {
		TranslateMessage(&message);
		DispatchMessageW(&message);
	}
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

void __stdcall entry(void)
{
	HINSTANCE instance = GetModuleHandleW(NULL);
	WNDCLASSEXW class_info = {sizeof class_info, 0, procedure, 0, 0, instance, NULL, LoadCursorW(NULL, (LPCWSTR)IDC_ARROW), (HBRUSH)(COLOR_WINDOW + 1), NULL, L"RavenD3D12", NULL};
	RegisterClassExW(&class_info);
	RECT frame = {0, 0, SIZE, SIZE};
	AdjustWindowRect(&frame, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE);
	HWND window = CreateWindowExW(0, L"RavenD3D12", L"Direct3D 12 frame", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, 100, 100,
		frame.right - frame.left, frame.bottom - frame.top, NULL, NULL, instance, NULL);
	if (!window)
		fail("window", 0);
	ShowWindow(window, SW_SHOW);
	UpdateWindow(window);
	pump();

	ID3D12Device *device = NULL;
	CHECK("device", D3D12CreateDevice(NULL, D3D_FEATURE_LEVEL_11_0, &IID_ID3D12Device, (void **)&device));
	D3D12_COMMAND_QUEUE_DESC queue_desc = {D3D12_COMMAND_LIST_TYPE_DIRECT, 0, D3D12_COMMAND_QUEUE_FLAG_NONE, 0};
	ID3D12CommandQueue *queue = NULL;
	CHECK("queue", ID3D12Device_CreateCommandQueue(device, &queue_desc, &IID_ID3D12CommandQueue, (void **)&queue));

	IDXGIFactory4 *factory = NULL;
	CHECK("factory", CreateDXGIFactory1(&IID_IDXGIFactory4, (void **)&factory));
	DXGI_SWAP_CHAIN_DESC1 swap_desc = {SIZE, SIZE, DXGI_FORMAT_R8G8B8A8_UNORM, FALSE, {1, 0}, DXGI_USAGE_RENDER_TARGET_OUTPUT, BUFFERS,
		DXGI_SCALING_STRETCH, DXGI_SWAP_EFFECT_FLIP_DISCARD, DXGI_ALPHA_MODE_UNSPECIFIED, 0};
	IDXGISwapChain1 *swap1 = NULL;
	CHECK("swap chain", IDXGIFactory4_CreateSwapChainForHwnd(factory, (IUnknown *)queue, window, &swap_desc, NULL, NULL, &swap1));
	IDXGISwapChain3 *swap = NULL;
	CHECK("swap chain 3", IDXGISwapChain1_QueryInterface(swap1, &IID_IDXGISwapChain3, (void **)&swap));

	D3D12_DESCRIPTOR_HEAP_DESC heap_desc = {D3D12_DESCRIPTOR_HEAP_TYPE_RTV, BUFFERS, D3D12_DESCRIPTOR_HEAP_FLAG_NONE, 0};
	ID3D12DescriptorHeap *heap = NULL;
	CHECK("rtv heap", ID3D12Device_CreateDescriptorHeap(device, &heap_desc, &IID_ID3D12DescriptorHeap, (void **)&heap));
	D3D12_CPU_DESCRIPTOR_HANDLE rtv[BUFFERS];
	heap->lpVtbl->GetCPUDescriptorHandleForHeapStart(heap, &rtv[0]);
	const UINT step = ID3D12Device_GetDescriptorHandleIncrementSize(device, D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
	rtv[1].ptr = rtv[0].ptr + step;
	ID3D12Resource *back[BUFFERS];
	for (UINT index = 0; index < BUFFERS; ++index) {
		CHECK("buffer", IDXGISwapChain3_GetBuffer(swap, index, &IID_ID3D12Resource, (void **)&back[index]));
		ID3D12Device_CreateRenderTargetView(device, back[index], NULL, rtv[index]);
	}

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
	pipeline.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
	pipeline.NumRenderTargets = 1;
	pipeline.RTVFormats[0] = DXGI_FORMAT_R8G8B8A8_UNORM;
	pipeline.SampleDesc.Count = 1;
	ID3D12PipelineState *state = NULL;
	CHECK("pipeline", ID3D12Device_CreateGraphicsPipelineState(device, &pipeline, &IID_ID3D12PipelineState, (void **)&state));

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

	ID3D12CommandAllocator *allocator = NULL;
	CHECK("allocator", ID3D12Device_CreateCommandAllocator(device, D3D12_COMMAND_LIST_TYPE_DIRECT, &IID_ID3D12CommandAllocator, (void **)&allocator));
	ID3D12GraphicsCommandList *list = NULL;
	CHECK("list", ID3D12Device_CreateCommandList(device, 0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator, state, &IID_ID3D12GraphicsCommandList, (void **)&list));
	CHECK("close first", ID3D12GraphicsCommandList_Close(list));
	ID3D12Fence *fence = NULL;
	CHECK("fence", ID3D12Device_CreateFence(device, 0, D3D12_FENCE_FLAG_NONE, &IID_ID3D12Fence, (void **)&fence));
	HANDLE event = CreateEventW(NULL, FALSE, FALSE, NULL);
	UINT64 fence_value = 0;

	D3D12_VIEWPORT viewport = {0, 0, SIZE, SIZE, 0, 1};
	D3D12_RECT scissor = {0, 0, SIZE, SIZE};
	D3D12_VERTEX_BUFFER_VIEW view = {ID3D12Resource_GetGPUVirtualAddress(upload), sizeof vertices, sizeof(struct vertex)};
	const int total = FRAMES + 150;
	for (int frame_number = 0; frame_number < total; ++frame_number) {
		/* The last counted frame clears to the colour the Direct3D 11 workload uses; earlier frames ramp towards it. */
		const int counted = frame_number < FRAMES ? frame_number : FRAMES - 1;
		const float ramp = (float)(FRAMES - 1 - counted) / (FRAMES - 1);
		const float color[4] = {0.1f + 0.5f * ramp, 0.1f, 0.3f, 1.0f};
		const UINT index = IDXGISwapChain3_GetCurrentBackBufferIndex(swap);
		CHECK("reset allocator", ID3D12CommandAllocator_Reset(allocator));
		CHECK("reset list", ID3D12GraphicsCommandList_Reset(list, allocator, state));
		barrier(list, back[index], D3D12_RESOURCE_STATE_PRESENT, D3D12_RESOURCE_STATE_RENDER_TARGET);
		ID3D12GraphicsCommandList_SetGraphicsRootSignature(list, root);
		ID3D12GraphicsCommandList_RSSetViewports(list, 1, &viewport);
		ID3D12GraphicsCommandList_RSSetScissorRects(list, 1, &scissor);
		ID3D12GraphicsCommandList_OMSetRenderTargets(list, 1, &rtv[index], FALSE, NULL);
		ID3D12GraphicsCommandList_ClearRenderTargetView(list, rtv[index], color, 0, NULL);
		ID3D12GraphicsCommandList_IASetPrimitiveTopology(list, D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
		ID3D12GraphicsCommandList_IASetVertexBuffers(list, 0, 1, &view);
		ID3D12GraphicsCommandList_DrawInstanced(list, 3, 1, 0, 0);
		if (frame_number == FRAMES - 1) {
			barrier(list, back[index], D3D12_RESOURCE_STATE_RENDER_TARGET, D3D12_RESOURCE_STATE_COPY_SOURCE);
			D3D12_TEXTURE_COPY_LOCATION destination = {readback, D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT};
			destination.PlacedFootprint.Footprint.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
			destination.PlacedFootprint.Footprint.Width = SIZE;
			destination.PlacedFootprint.Footprint.Height = SIZE;
			destination.PlacedFootprint.Footprint.Depth = 1;
			destination.PlacedFootprint.Footprint.RowPitch = pitch;
			D3D12_TEXTURE_COPY_LOCATION source = {back[index], D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX};
			ID3D12GraphicsCommandList_CopyTextureRegion(list, &destination, 0, 0, 0, &source, NULL);
			barrier(list, back[index], D3D12_RESOURCE_STATE_COPY_SOURCE, D3D12_RESOURCE_STATE_PRESENT);
		} else {
			barrier(list, back[index], D3D12_RESOURCE_STATE_RENDER_TARGET, D3D12_RESOURCE_STATE_PRESENT);
		}
		CHECK("close", ID3D12GraphicsCommandList_Close(list));
		ID3D12CommandList *lists[] = {(ID3D12CommandList *)list};
		ID3D12CommandQueue_ExecuteCommandLists(queue, 1, lists);
		CHECK("present", IDXGISwapChain3_Present(swap, 0, 0));
		++fence_value;
		CHECK("signal", ID3D12CommandQueue_Signal(queue, fence, fence_value));
		CHECK("completion", ID3D12Fence_SetEventOnCompletion(fence, fence_value, event));
		if (WaitForSingleObject(event, 20000) != WAIT_OBJECT_0)
			fail("wait", 0);
		if (frame_number == FRAMES - 1) {
			void *mapped = NULL;
			D3D12_RANGE range = {0, (SIZE_T)pitch * SIZE};
			CHECK("map", ID3D12Resource_Map(readback, 0, &range, &mapped));
			write_file(L"C:\\window12_last.raw", mapped, pitch * SIZE);
			D3D12_RANGE none = {0, 0};
			ID3D12Resource_Unmap(readback, 0, &none);
			write_file(L"C:\\window12.txt", "OK", 2);
		}
		pump();
		if (frame_number >= FRAMES)
			Sleep(100);
	}
	ExitProcess(0);
}
