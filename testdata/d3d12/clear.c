/* Direct3D 12 workload: clears a render target on the GPU, copies it into a read-back buffer, waits on a fence and writes the pixels to
 * C:\clear.raw. C:\clear.txt holds OK or the first step that failed with its result code. */
#define COBJMACROS
#include <windows.h>
#include <d3d12.h>

#define SIZE 64

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
	write_file(L"C:\\clear.txt", text, (DWORD)length);
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
	ID3D12GraphicsCommandList *list = NULL;
	CHECK("list", ID3D12Device_CreateCommandList(device, 0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator, NULL, &IID_ID3D12GraphicsCommandList, (void **)&list));

	D3D12_HEAP_PROPERTIES default_heap = {D3D12_HEAP_TYPE_DEFAULT, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};
	D3D12_RESOURCE_DESC texture = {D3D12_RESOURCE_DIMENSION_TEXTURE2D, 0, SIZE, SIZE, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0},
		D3D12_TEXTURE_LAYOUT_UNKNOWN, D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET};
	const float color[4] = {0.2f, 0.4f, 0.6f, 1.0f};
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

	/* The read-back buffer holds SIZE rows of a 256 byte aligned pitch. */
	const UINT pitch = 256;
	D3D12_HEAP_PROPERTIES readback_heap = {D3D12_HEAP_TYPE_READBACK, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};
	D3D12_RESOURCE_DESC buffer = {D3D12_RESOURCE_DIMENSION_BUFFER, 0, (UINT64)pitch * SIZE, 1, 1, 1, DXGI_FORMAT_UNKNOWN, {1, 0},
		D3D12_TEXTURE_LAYOUT_ROW_MAJOR, D3D12_RESOURCE_FLAG_NONE};
	ID3D12Resource *readback = NULL;
	CHECK("readback", ID3D12Device_CreateCommittedResource(device, &readback_heap, D3D12_HEAP_FLAG_NONE, &buffer, D3D12_RESOURCE_STATE_COPY_DEST,
		NULL, &IID_ID3D12Resource, (void **)&readback));

	ID3D12GraphicsCommandList_ClearRenderTargetView(list, rtv, color, 0, NULL);
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
	source.SubresourceIndex = 0;
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
	if (ID3D12Fence_GetCompletedValue(fence) < 1)
		fail("completed value", 0);

	void *mapped = NULL;
	D3D12_RANGE range = {0, (SIZE_T)pitch * SIZE};
	CHECK("map", ID3D12Resource_Map(readback, 0, &range, &mapped));
	/* Write only the SIZE pixels of each row, tightly packed. */
	HANDLE f = CreateFileW(L"C:\\clear.raw", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD n;
	for (int row = 0; row < SIZE; ++row)
		WriteFile(f, (const BYTE *)mapped + (size_t)row * pitch, SIZE * 4, &n, NULL);
	CloseHandle(f);
	D3D12_RANGE none = {0, 0};
	ID3D12Resource_Unmap(readback, 0, &none);
	write_file(L"C:\\clear.txt", "OK", 2);
	ExitProcess(0);
}
