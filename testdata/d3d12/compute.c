/* Direct3D 12 compute workload: the dispatch of the Direct3D 11 compute test with Direct3D 12 binding. A texture is read with Load through
 * a shader resource view and a typed buffer is written through an unordered access view, both in one descriptor table; the buffer is copied
 * into a read-back buffer and written to C:\compute12.raw as 256 32-bit values. C:\compute12.txt holds OK or the first failing step. */
#define COBJMACROS
#include <windows.h>
#include <d3d12.h>
#include "compute5_shader.h"

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
	write_file(L"C:\\compute12.txt", text, (DWORD)length);
	ExitProcess(1);
}

#define CHECK(step, call) do { HRESULT result_ = (call); if (FAILED(result_)) fail(step, result_); } while (0)

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
	ID3D12Device *device = NULL;
	CHECK("device", D3D12CreateDevice(NULL, D3D_FEATURE_LEVEL_11_0, &IID_ID3D12Device, (void **)&device));
	D3D12_COMMAND_QUEUE_DESC queue_desc = {D3D12_COMMAND_LIST_TYPE_DIRECT, 0, D3D12_COMMAND_QUEUE_FLAG_NONE, 0};
	ID3D12CommandQueue *queue = NULL;
	CHECK("queue", ID3D12Device_CreateCommandQueue(device, &queue_desc, &IID_ID3D12CommandQueue, (void **)&queue));
	ID3D12CommandAllocator *allocator = NULL;
	CHECK("allocator", ID3D12Device_CreateCommandAllocator(device, D3D12_COMMAND_LIST_TYPE_DIRECT, &IID_ID3D12CommandAllocator, (void **)&allocator));

	D3D12_DESCRIPTOR_RANGE ranges[2] = {
		{D3D12_DESCRIPTOR_RANGE_TYPE_SRV, 1, 0, 0, D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND},
		{D3D12_DESCRIPTOR_RANGE_TYPE_UAV, 1, 0, 0, D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND},
	};
	D3D12_ROOT_PARAMETER parameter = {0};
	parameter.ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
	parameter.DescriptorTable.NumDescriptorRanges = 2;
	parameter.DescriptorTable.pDescriptorRanges = ranges;
	parameter.ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
	D3D12_ROOT_SIGNATURE_DESC root_desc = {1, &parameter, 0, NULL, D3D12_ROOT_SIGNATURE_FLAG_NONE};
	ID3DBlob *serialized = NULL, *errors = NULL;
	CHECK("serialize root signature", D3D12SerializeRootSignature(&root_desc, D3D_ROOT_SIGNATURE_VERSION_1, &serialized, &errors));
	ID3D12RootSignature *root = NULL;
	CHECK("root signature", ID3D12Device_CreateRootSignature(device, 0, ID3D10Blob_GetBufferPointer(serialized), ID3D10Blob_GetBufferSize(serialized),
		&IID_ID3D12RootSignature, (void **)&root));
	D3D12_COMPUTE_PIPELINE_STATE_DESC pipeline = {0};
	pipeline.pRootSignature = root;
	pipeline.CS.pShaderBytecode = compute5_cs;
	pipeline.CS.BytecodeLength = sizeof(compute5_cs);
	ID3D12PipelineState *state = NULL;
	CHECK("compute pipeline", ID3D12Device_CreateComputePipelineState(device, &pipeline, &IID_ID3D12PipelineState, (void **)&state));
	ID3D12GraphicsCommandList *list = NULL;
	CHECK("list", ID3D12Device_CreateCommandList(device, 0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator, state, &IID_ID3D12GraphicsCommandList, (void **)&list));

	D3D12_HEAP_PROPERTIES default_heap = {D3D12_HEAP_TYPE_DEFAULT, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};
	D3D12_HEAP_PROPERTIES upload_heap = {D3D12_HEAP_TYPE_UPLOAD, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};
	D3D12_HEAP_PROPERTIES readback_heap = {D3D12_HEAP_TYPE_READBACK, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};

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

	D3D12_RESOURCE_DESC output_desc = {D3D12_RESOURCE_DIMENSION_BUFFER, 0, 256 * 4, 1, 1, 1, DXGI_FORMAT_UNKNOWN, {1, 0},
		D3D12_TEXTURE_LAYOUT_ROW_MAJOR, D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS};
	ID3D12Resource *output = NULL;
	CHECK("output", ID3D12Device_CreateCommittedResource(device, &default_heap, D3D12_HEAP_FLAG_NONE, &output_desc, D3D12_RESOURCE_STATE_UNORDERED_ACCESS,
		NULL, &IID_ID3D12Resource, (void **)&output));
	D3D12_RESOURCE_DESC readback_desc = {D3D12_RESOURCE_DIMENSION_BUFFER, 0, 256 * 4, 1, 1, 1, DXGI_FORMAT_UNKNOWN, {1, 0},
		D3D12_TEXTURE_LAYOUT_ROW_MAJOR, D3D12_RESOURCE_FLAG_NONE};
	ID3D12Resource *readback = NULL;
	CHECK("readback", ID3D12Device_CreateCommittedResource(device, &readback_heap, D3D12_HEAP_FLAG_NONE, &readback_desc, D3D12_RESOURCE_STATE_COPY_DEST,
		NULL, &IID_ID3D12Resource, (void **)&readback));

	D3D12_DESCRIPTOR_HEAP_DESC heap_desc = {D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV, 2, D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE, 0};
	ID3D12DescriptorHeap *heap = NULL;
	CHECK("descriptor heap", ID3D12Device_CreateDescriptorHeap(device, &heap_desc, &IID_ID3D12DescriptorHeap, (void **)&heap));
	D3D12_CPU_DESCRIPTOR_HANDLE srv, uav;
	heap->lpVtbl->GetCPUDescriptorHandleForHeapStart(heap, &srv);
	uav.ptr = srv.ptr + ID3D12Device_GetDescriptorHandleIncrementSize(device, D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
	D3D12_GPU_DESCRIPTOR_HANDLE table;
	heap->lpVtbl->GetGPUDescriptorHandleForHeapStart(heap, &table);
	D3D12_SHADER_RESOURCE_VIEW_DESC srv_desc = {DXGI_FORMAT_R8G8B8A8_UNORM, D3D12_SRV_DIMENSION_TEXTURE2D, D3D12_ENCODE_SHADER_4_COMPONENT_MAPPING(0, 1, 2, 3)};
	srv_desc.Texture2D.MipLevels = 1;
	ID3D12Device_CreateShaderResourceView(device, texture, &srv_desc, srv);
	D3D12_UNORDERED_ACCESS_VIEW_DESC uav_desc = {DXGI_FORMAT_R32_UINT, D3D12_UAV_DIMENSION_BUFFER};
	uav_desc.Buffer.FirstElement = 0;
	uav_desc.Buffer.NumElements = 256;
	ID3D12Device_CreateUnorderedAccessView(device, output, NULL, &uav_desc, uav);

	D3D12_TEXTURE_COPY_LOCATION texture_destination = {texture, D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX};
	D3D12_TEXTURE_COPY_LOCATION texture_source = {texture_upload, D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT};
	texture_source.PlacedFootprint.Footprint.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	texture_source.PlacedFootprint.Footprint.Width = 8;
	texture_source.PlacedFootprint.Footprint.Height = 8;
	texture_source.PlacedFootprint.Footprint.Depth = 1;
	texture_source.PlacedFootprint.Footprint.RowPitch = 256;
	ID3D12GraphicsCommandList_CopyTextureRegion(list, &texture_destination, 0, 0, 0, &texture_source, NULL);
	barrier(list, texture, D3D12_RESOURCE_STATE_COPY_DEST, D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE);

	ID3D12GraphicsCommandList_SetDescriptorHeaps(list, 1, &heap);
	ID3D12GraphicsCommandList_SetComputeRootSignature(list, root);
	ID3D12GraphicsCommandList_SetComputeRootDescriptorTable(list, 0, table);
	ID3D12GraphicsCommandList_Dispatch(list, 4, 1, 1);
	barrier(list, output, D3D12_RESOURCE_STATE_UNORDERED_ACCESS, D3D12_RESOURCE_STATE_COPY_SOURCE);
	ID3D12GraphicsCommandList_CopyBufferRegion(list, readback, 0, output, 0, 256 * 4);
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
	D3D12_RANGE range = {0, 256 * 4};
	CHECK("map", ID3D12Resource_Map(readback, 0, &range, &mapped));
	write_file(L"C:\\compute12.raw", mapped, 256 * 4);
	D3D12_RANGE none = {0, 0};
	ID3D12Resource_Unmap(readback, 0, &none);
	write_file(L"C:\\compute12.txt", "OK", 2);
	ExitProcess(0);
}
