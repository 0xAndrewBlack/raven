/* Direct3D 12 shader model 6 workload: runs a cs_6_0 compute shader (wave.hlsl, DXIL) that checks identities of the wave intrinsics and writes
 * two words per thread into a UAV buffer: a mask of the identities that held, and the wave size. The buffer goes to C:\wave.raw. C:\wave.txt
 * holds OK, SKIP when the device has no shader model 6 or wave operations, or the first failing step. */
#define COBJMACROS
#include <windows.h>
#include <d3d12.h>
#include "wave_shaders.h"

#define GROUPS 4
#define THREADS 64
#define WORDS (GROUPS * THREADS * 2)

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
	write_file(L"C:\\wave.txt", text, (DWORD)length);
	ExitProcess(1);
}

#define CHECK(step, call) do { HRESULT result_ = (call); if (FAILED(result_)) fail(step, result_); } while (0)

static ID3D12Device *device;

static ID3D12Resource *make_buffer(D3D12_HEAP_TYPE heap_type, UINT64 size, D3D12_RESOURCE_FLAGS flags, D3D12_RESOURCE_STATES state, const char *step)
{
	D3D12_HEAP_PROPERTIES heap = {heap_type, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};
	D3D12_RESOURCE_DESC desc = {D3D12_RESOURCE_DIMENSION_BUFFER, 0, size, 1, 1, 1, DXGI_FORMAT_UNKNOWN, {1, 0}, D3D12_TEXTURE_LAYOUT_ROW_MAJOR, flags};
	ID3D12Resource *buffer = NULL;
	CHECK(step, ID3D12Device_CreateCommittedResource(device, &heap, D3D12_HEAP_FLAG_NONE, &desc, state, NULL, &IID_ID3D12Resource, (void **)&buffer));
	return buffer;
}

void __stdcall entry(void)
{
	CHECK("device", D3D12CreateDevice(NULL, D3D_FEATURE_LEVEL_11_0, &IID_ID3D12Device, (void **)&device));
	D3D12_FEATURE_DATA_SHADER_MODEL model = {D3D_SHADER_MODEL_6_0};
	D3D12_FEATURE_DATA_D3D12_OPTIONS1 options1 = {0};
	if (FAILED(ID3D12Device_CheckFeatureSupport(device, D3D12_FEATURE_SHADER_MODEL, &model, sizeof model)) || model.HighestShaderModel < D3D_SHADER_MODEL_6_0 ||
		FAILED(ID3D12Device_CheckFeatureSupport(device, D3D12_FEATURE_D3D12_OPTIONS1, &options1, sizeof options1)) || !options1.WaveOps) {
		write_file(L"C:\\wave.txt", "SKIP no wave operations", 23);
		ExitProcess(0);
	}

	D3D12_COMMAND_QUEUE_DESC queue_desc = {D3D12_COMMAND_LIST_TYPE_DIRECT, 0, D3D12_COMMAND_QUEUE_FLAG_NONE, 0};
	ID3D12CommandQueue *queue = NULL;
	CHECK("queue", ID3D12Device_CreateCommandQueue(device, &queue_desc, &IID_ID3D12CommandQueue, (void **)&queue));
	ID3D12CommandAllocator *allocator = NULL;
	CHECK("allocator", ID3D12Device_CreateCommandAllocator(device, D3D12_COMMAND_LIST_TYPE_DIRECT, &IID_ID3D12CommandAllocator, (void **)&allocator));

	D3D12_ROOT_PARAMETER parameter = {D3D12_ROOT_PARAMETER_TYPE_UAV};
	parameter.Descriptor.ShaderRegister = 0;
	parameter.ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
	D3D12_ROOT_SIGNATURE_DESC root_desc = {1, &parameter, 0, NULL, D3D12_ROOT_SIGNATURE_FLAG_NONE};
	ID3DBlob *serialized = NULL, *errors = NULL;
	CHECK("serialize root signature", D3D12SerializeRootSignature(&root_desc, D3D_ROOT_SIGNATURE_VERSION_1, &serialized, &errors));
	ID3D12RootSignature *root = NULL;
	CHECK("root signature", ID3D12Device_CreateRootSignature(device, 0, ID3D10Blob_GetBufferPointer(serialized), ID3D10Blob_GetBufferSize(serialized),
		&IID_ID3D12RootSignature, (void **)&root));
	D3D12_COMPUTE_PIPELINE_STATE_DESC pipeline_desc = {root, {wave_shader, sizeof wave_shader}};
	ID3D12PipelineState *pipeline = NULL;
	CHECK("compute pipeline", ID3D12Device_CreateComputePipelineState(device, &pipeline_desc, &IID_ID3D12PipelineState, (void **)&pipeline));

	ID3D12Resource *results = make_buffer(D3D12_HEAP_TYPE_DEFAULT, WORDS * 4, D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS, D3D12_RESOURCE_STATE_UNORDERED_ACCESS, "results");
	ID3D12Resource *readback = make_buffer(D3D12_HEAP_TYPE_READBACK, WORDS * 4, D3D12_RESOURCE_FLAG_NONE, D3D12_RESOURCE_STATE_COPY_DEST, "readback");

	ID3D12GraphicsCommandList *list = NULL;
	CHECK("list", ID3D12Device_CreateCommandList(device, 0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator, pipeline, &IID_ID3D12GraphicsCommandList, (void **)&list));
	ID3D12GraphicsCommandList_SetComputeRootSignature(list, root);
	ID3D12GraphicsCommandList_SetComputeRootUnorderedAccessView(list, 0, ID3D12Resource_GetGPUVirtualAddress(results));
	ID3D12GraphicsCommandList_Dispatch(list, GROUPS, 1, 1);
	D3D12_RESOURCE_BARRIER barrier = {D3D12_RESOURCE_BARRIER_TYPE_TRANSITION, D3D12_RESOURCE_BARRIER_FLAG_NONE};
	barrier.Transition.pResource = results;
	barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
	barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_UNORDERED_ACCESS;
	barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_SOURCE;
	ID3D12GraphicsCommandList_ResourceBarrier(list, 1, &barrier);
	ID3D12GraphicsCommandList_CopyResource(list, readback, results);
	CHECK("close", ID3D12GraphicsCommandList_Close(list));

	ID3D12Fence *fence = NULL;
	CHECK("fence", ID3D12Device_CreateFence(device, 0, D3D12_FENCE_FLAG_NONE, &IID_ID3D12Fence, (void **)&fence));
	ID3D12CommandList *lists[] = {(ID3D12CommandList *)list};
	ID3D12CommandQueue_ExecuteCommandLists(queue, 1, lists);
	CHECK("signal", ID3D12CommandQueue_Signal(queue, fence, 1));
	HANDLE event = CreateEventW(NULL, FALSE, FALSE, NULL);
	CHECK("completion", ID3D12Fence_SetEventOnCompletion(fence, 1, event));
	if (WaitForSingleObject(event, 60000) != WAIT_OBJECT_0)
		fail("wait", 0);

	void *mapped = NULL;
	D3D12_RANGE range = {0, WORDS * 4};
	CHECK("map", ID3D12Resource_Map(readback, 0, &range, &mapped));
	write_file(L"C:\\wave.raw", mapped, WORDS * 4);
	D3D12_RANGE none = {0, 0};
	ID3D12Resource_Unmap(readback, 0, &none);
	write_file(L"C:\\wave.txt", "OK", 2);
	ExitProcess(0);
}
