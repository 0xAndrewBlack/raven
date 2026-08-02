/* Built with -DSCENE the structures are richer: one bottom level structure with two triangle geometries, built for compaction and then compacted,
 * and a top level structure with two instances with different transforms and instance ids (rtscene.hlsl colours a hit by instance and geometry).
 * Besides C:\\rtscene.raw and C:\\rtscene.txt it writes C:\\rtscene_sizes.txt, the compacted and the full size of the bottom level structure.
 *
 * Built with -DANYHIT this scene has an any hit shader that cuts the triangle and a callable shader that supplies the background (rtanyhit.hlsl);
 * built with -DPROCEDURAL the geometry is one box and an intersection shader makes a disc of it (rtprocedural.hlsl). The files are
 * C:\\rtanyhit.* and C:\\rtprocedural.*.
 *
 * Built with -DINLINE_QUERY this is the inline ray query variant: no ray tracing pipeline or shader table, a compute shader (rayquery.hlsl)
 * traces with RayQuery, DispatchRays is replaced by Dispatch, and the files are C:\\rayquery.raw and C:\\rayquery.txt.
 *
 * Direct3D 12 ray tracing workload: builds a bottom level acceleration structure with one triangle and a top level one with one instance of it,
 * creates a ray tracing pipeline from rt_shaders.h (see rt.hlsl), traces one orthographic ray per pixel of a 256 by 256 unordered access
 * texture with DispatchRays, copies the texture into a read-back buffer and writes the pixels to C:\raytrace.raw. C:\raytrace.txt holds OK,
 * SKIP when the device reports no ray tracing, or the first failing step. The triangle has the geometry and vertex colours of the
 * rasterized workloads, so the result is compared with the same reference. */
#define COBJMACROS
#include <windows.h>
#include <d3d12.h>
#if defined(SCENE)
#include "rtscene_shaders.h"
#define rt_library scene_library
#define OUT_TXT L"C:\\rtscene.txt"
#define OUT_RAW L"C:\\rtscene.raw"
#elif defined(ANYHIT)
#include "rtanyhit_shaders.h"
#define rt_library anyhit_library
#define OUT_TXT L"C:\\rtanyhit.txt"
#define OUT_RAW L"C:\\rtanyhit.raw"
#elif defined(PROCEDURAL)
#include "rtprocedural_shaders.h"
#define rt_library procedural_library
#define OUT_TXT L"C:\\rtprocedural.txt"
#define OUT_RAW L"C:\\rtprocedural.raw"
#elif defined(INLINE_QUERY)
#include "rayquery_shaders.h"
#define OUT_TXT L"C:\\rayquery.txt"
#define OUT_RAW L"C:\\rayquery.raw"
#else
#include "rt_shaders.h"
#define OUT_TXT L"C:\\raytrace.txt"
#define OUT_RAW L"C:\\raytrace.raw"
#endif

#define SIZE 256
#define RECORD 64

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
	write_file(OUT_TXT, text, (DWORD)length);
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

static void upload(ID3D12Resource *buffer, const void *data, size_t size)
{
	void *mapped = NULL;
	CHECK("map upload", ID3D12Resource_Map(buffer, 0, NULL, &mapped));
	for (size_t index = 0; index < size; ++index)
		((BYTE *)mapped)[index] = ((const BYTE *)data)[index];
	ID3D12Resource_Unmap(buffer, 0, NULL);
}

static void uav_barrier(ID3D12GraphicsCommandList4 *list, ID3D12Resource *resource)
{
	D3D12_RESOURCE_BARRIER barrier = {D3D12_RESOURCE_BARRIER_TYPE_UAV, D3D12_RESOURCE_BARRIER_FLAG_NONE};
	barrier.UAV.pResource = resource;
	ID3D12GraphicsCommandList4_ResourceBarrier(list, 1, &barrier);
}

void __stdcall entry(void)
{
	CHECK("device", D3D12CreateDevice(NULL, D3D_FEATURE_LEVEL_11_0, &IID_ID3D12Device, (void **)&device));
	D3D12_FEATURE_DATA_D3D12_OPTIONS5 options5 = {0};
	CHECK("feature options 5", ID3D12Device_CheckFeatureSupport(device, D3D12_FEATURE_D3D12_OPTIONS5, &options5, sizeof options5));
#ifdef INLINE_QUERY
	if (options5.RaytracingTier < D3D12_RAYTRACING_TIER_1_1) {
#else
	if (options5.RaytracingTier == D3D12_RAYTRACING_TIER_NOT_SUPPORTED) {
#endif
		write_file(OUT_TXT, "SKIP no ray tracing", 19);
		ExitProcess(0);
	}
	ID3D12Device5 *device5 = NULL;
	CHECK("device 5", ID3D12Device_QueryInterface(device, &IID_ID3D12Device5, (void **)&device5));

	D3D12_COMMAND_QUEUE_DESC queue_desc = {D3D12_COMMAND_LIST_TYPE_DIRECT, 0, D3D12_COMMAND_QUEUE_FLAG_NONE, 0};
	ID3D12CommandQueue *queue = NULL;
	CHECK("queue", ID3D12Device_CreateCommandQueue(device, &queue_desc, &IID_ID3D12CommandQueue, (void **)&queue));
	ID3D12CommandAllocator *allocator = NULL;
	CHECK("allocator", ID3D12Device_CreateCommandAllocator(device, D3D12_COMMAND_LIST_TYPE_DIRECT, &IID_ID3D12CommandAllocator, (void **)&allocator));
	ID3D12GraphicsCommandList *plain = NULL;
	CHECK("list", ID3D12Device_CreateCommandList(device, 0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator, NULL, &IID_ID3D12GraphicsCommandList, (void **)&plain));
	ID3D12GraphicsCommandList4 *list = NULL;
	CHECK("list 4", ID3D12GraphicsCommandList_QueryInterface(plain, &IID_ID3D12GraphicsCommandList4, (void **)&list));

	/* The triangle of the rasterized workloads, in the plane z = 0. */
#if defined(SCENE)
	/* Two triangles in the plane z = 0: one in the lower and one in the upper part of the space the instances are placed in. */
	static const float vertices[18] = {-0.4f, -0.4f, 0.0f, 0.0f, 0.4f, 0.0f, 0.4f, -0.4f, 0.0f,
		-0.4f, 0.45f, 0.0f, 0.0f, 0.85f, 0.0f, 0.4f, 0.45f, 0.0f};
#else
	static const float vertices[9] = {-0.8f, -0.8f, 0.0f, 0.0f, 0.8f, 0.0f, 0.8f, -0.8f, 0.0f};
#endif
	ID3D12Resource *vertex_buffer = make_buffer(D3D12_HEAP_TYPE_UPLOAD, sizeof vertices, D3D12_RESOURCE_FLAG_NONE, D3D12_RESOURCE_STATE_GENERIC_READ, "vertex buffer");
	upload(vertex_buffer, vertices, sizeof vertices);

	D3D12_RAYTRACING_GEOMETRY_DESC geometry = {0};
	D3D12_RAYTRACING_GEOMETRY_DESC geometries[2] = {{0}, {0}};
#if defined(PROCEDURAL)
	/* One box around the disc: x and y from -0.5 to 0.5, z from -0.1 to 0.1. */
	static const float box[6] = {-0.5f, -0.5f, -0.1f, 0.5f, 0.5f, 0.1f};
	ID3D12Resource *box_buffer = make_buffer(D3D12_HEAP_TYPE_UPLOAD, sizeof box, D3D12_RESOURCE_FLAG_NONE, D3D12_RESOURCE_STATE_GENERIC_READ, "box buffer");
	upload(box_buffer, box, sizeof box);
	geometry.Type = D3D12_RAYTRACING_GEOMETRY_TYPE_PROCEDURAL_PRIMITIVE_AABBS;
	geometry.Flags = D3D12_RAYTRACING_GEOMETRY_FLAG_OPAQUE;
	geometry.AABBs.AABBCount = 1;
	geometry.AABBs.AABBs.StartAddress = ID3D12Resource_GetGPUVirtualAddress(box_buffer);
	geometry.AABBs.AABBs.StrideInBytes = sizeof box;
#else
	geometry.Type = D3D12_RAYTRACING_GEOMETRY_TYPE_TRIANGLES;
#if defined(ANYHIT)
	/* Not opaque: the any hit shader decides which hits count. */
	geometry.Flags = D3D12_RAYTRACING_GEOMETRY_FLAG_NONE;
#else
	geometry.Flags = D3D12_RAYTRACING_GEOMETRY_FLAG_OPAQUE;
#endif
	geometry.Triangles.VertexBuffer.StartAddress = ID3D12Resource_GetGPUVirtualAddress(vertex_buffer);
	geometry.Triangles.VertexBuffer.StrideInBytes = 3 * sizeof(float);
	geometry.Triangles.VertexFormat = DXGI_FORMAT_R32G32B32_FLOAT;
	geometry.Triangles.VertexCount = 3;
#endif
#if defined(SCENE)
	for (int index = 0; index < 2; ++index) {
		geometries[index] = geometry;
		geometries[index].Triangles.VertexBuffer.StartAddress += (UINT64)index * 3 * 3 * sizeof(float);
	}
#endif
	D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_INPUTS bottom_inputs = {0};
	bottom_inputs.Type = D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE_BOTTOM_LEVEL;
#if defined(SCENE)
	bottom_inputs.Flags = D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAG_ALLOW_COMPACTION;
	bottom_inputs.NumDescs = 2;
#else
	bottom_inputs.Flags = D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAG_NONE;
	bottom_inputs.NumDescs = 1;
#endif
	bottom_inputs.DescsLayout = D3D12_ELEMENTS_LAYOUT_ARRAY;
#if defined(SCENE)
	bottom_inputs.pGeometryDescs = geometries;
#else
	bottom_inputs.pGeometryDescs = &geometry;
#endif
	D3D12_RAYTRACING_ACCELERATION_STRUCTURE_PREBUILD_INFO bottom_info = {0};
	ID3D12Device5_GetRaytracingAccelerationStructurePrebuildInfo(device5, &bottom_inputs, &bottom_info);
	if (!bottom_info.ResultDataMaxSizeInBytes)
		fail("bottom level prebuild size", 0);

	ID3D12Resource *bottom = make_buffer(D3D12_HEAP_TYPE_DEFAULT, bottom_info.ResultDataMaxSizeInBytes, D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS,
		D3D12_RESOURCE_STATE_RAYTRACING_ACCELERATION_STRUCTURE, "bottom level buffer");

#if defined(SCENE)
	/* Two instances: the structure moved left, and the structure at half size moved right; the instance ids are 0 and 1. */
	D3D12_RAYTRACING_INSTANCE_DESC instance[2] = {{{{0}}}, {{{0}}}};
	instance[0].Transform[0][0] = instance[0].Transform[1][1] = instance[0].Transform[2][2] = 1.0f;
	instance[0].Transform[0][3] = -0.5f;
	instance[0].InstanceID = 0;
	instance[1].Transform[0][0] = instance[1].Transform[1][1] = instance[1].Transform[2][2] = 0.5f;
	instance[1].Transform[0][3] = 0.5f;
	instance[1].InstanceID = 1;
	instance[0].InstanceMask = instance[1].InstanceMask = 0xff;
	/* The bottom level address is filled in once the compacted structure exists. */
	ID3D12Resource *instances = make_buffer(D3D12_HEAP_TYPE_UPLOAD, sizeof instance, D3D12_RESOURCE_FLAG_NONE, D3D12_RESOURCE_STATE_GENERIC_READ, "instance buffer");
#else
	D3D12_RAYTRACING_INSTANCE_DESC instance = {0};
	instance.Transform[0][0] = instance.Transform[1][1] = instance.Transform[2][2] = 1.0f;
	instance.InstanceMask = 0xff;
	instance.AccelerationStructure = ID3D12Resource_GetGPUVirtualAddress(bottom);
	ID3D12Resource *instances = make_buffer(D3D12_HEAP_TYPE_UPLOAD, sizeof instance, D3D12_RESOURCE_FLAG_NONE, D3D12_RESOURCE_STATE_GENERIC_READ, "instance buffer");
	upload(instances, &instance, sizeof instance);

#endif
	D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_INPUTS top_inputs = {0};
	top_inputs.Type = D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE_TOP_LEVEL;
	top_inputs.Flags = D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAG_NONE;
#if defined(SCENE)
	top_inputs.NumDescs = 2;
#else
	top_inputs.NumDescs = 1;
#endif
	top_inputs.DescsLayout = D3D12_ELEMENTS_LAYOUT_ARRAY;
	top_inputs.InstanceDescs = ID3D12Resource_GetGPUVirtualAddress(instances);
	D3D12_RAYTRACING_ACCELERATION_STRUCTURE_PREBUILD_INFO top_info = {0};
	ID3D12Device5_GetRaytracingAccelerationStructurePrebuildInfo(device5, &top_inputs, &top_info);
	if (!top_info.ResultDataMaxSizeInBytes)
		fail("top level prebuild size", 0);
	ID3D12Resource *top = make_buffer(D3D12_HEAP_TYPE_DEFAULT, top_info.ResultDataMaxSizeInBytes, D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS,
		D3D12_RESOURCE_STATE_RAYTRACING_ACCELERATION_STRUCTURE, "top level buffer");
	const UINT64 scratch_size = bottom_info.ScratchDataSizeInBytes > top_info.ScratchDataSizeInBytes ? bottom_info.ScratchDataSizeInBytes : top_info.ScratchDataSizeInBytes;
	ID3D12Resource *scratch = make_buffer(D3D12_HEAP_TYPE_DEFAULT, scratch_size ? scratch_size : 256, D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS,
		D3D12_RESOURCE_STATE_UNORDERED_ACCESS, "scratch buffer");

	/* A root signature with one table: the acceleration structure at t0 and the output texture at u0. */
	D3D12_DESCRIPTOR_RANGE ranges[2] = {
		{D3D12_DESCRIPTOR_RANGE_TYPE_SRV, 1, 0, 0, D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND},
		{D3D12_DESCRIPTOR_RANGE_TYPE_UAV, 1, 0, 0, D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND},
	};
	D3D12_ROOT_PARAMETER parameter = {D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE};
	parameter.DescriptorTable.NumDescriptorRanges = 2;
	parameter.DescriptorTable.pDescriptorRanges = ranges;
	parameter.ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
	D3D12_ROOT_SIGNATURE_DESC root_desc = {1, &parameter, 0, NULL, D3D12_ROOT_SIGNATURE_FLAG_NONE};
	ID3DBlob *serialized = NULL, *errors = NULL;
	CHECK("serialize root signature", D3D12SerializeRootSignature(&root_desc, D3D_ROOT_SIGNATURE_VERSION_1, &serialized, &errors));
	ID3D12RootSignature *root = NULL;
	CHECK("root signature", ID3D12Device_CreateRootSignature(device, 0, ID3D10Blob_GetBufferPointer(serialized), ID3D10Blob_GetBufferSize(serialized),
		&IID_ID3D12RootSignature, (void **)&root));

#ifdef INLINE_QUERY
	D3D12_COMPUTE_PIPELINE_STATE_DESC compute_desc = {root, {rayquery_shader, sizeof rayquery_shader}};
	ID3D12PipelineState *compute_state = NULL;
	CHECK("compute pipeline", ID3D12Device_CreateComputePipelineState(device, &compute_desc, &IID_ID3D12PipelineState, (void **)&compute_state));
#else
	/* The pipeline: the library, a triangle hit group around the closest hit shader, the payload and attribute sizes, one level of recursion. */
	D3D12_DXIL_LIBRARY_DESC library = {{rt_library, sizeof rt_library}, 0, NULL};
#if defined(PROCEDURAL)
	D3D12_HIT_GROUP_DESC hit_group = {L"HitGroup", D3D12_HIT_GROUP_TYPE_PROCEDURAL_PRIMITIVE, NULL, L"chit", L"isect"};
#elif defined(ANYHIT)
	D3D12_HIT_GROUP_DESC hit_group = {L"HitGroup", D3D12_HIT_GROUP_TYPE_TRIANGLES, L"ahit", L"chit", NULL};
#else
	D3D12_HIT_GROUP_DESC hit_group = {L"HitGroup", D3D12_HIT_GROUP_TYPE_TRIANGLES, NULL, L"chit", NULL};
#endif
	D3D12_RAYTRACING_SHADER_CONFIG shader_config = {4 * sizeof(float), 2 * sizeof(float)};
	D3D12_RAYTRACING_PIPELINE_CONFIG pipeline_config = {1};
	D3D12_GLOBAL_ROOT_SIGNATURE global_root = {root};
	D3D12_STATE_SUBOBJECT subobjects[5] = {
		{D3D12_STATE_SUBOBJECT_TYPE_DXIL_LIBRARY, &library},
		{D3D12_STATE_SUBOBJECT_TYPE_HIT_GROUP, &hit_group},
		{D3D12_STATE_SUBOBJECT_TYPE_RAYTRACING_SHADER_CONFIG, &shader_config},
		{D3D12_STATE_SUBOBJECT_TYPE_RAYTRACING_PIPELINE_CONFIG, &pipeline_config},
		{D3D12_STATE_SUBOBJECT_TYPE_GLOBAL_ROOT_SIGNATURE, &global_root},
	};
	D3D12_STATE_OBJECT_DESC pipeline_desc = {D3D12_STATE_OBJECT_TYPE_RAYTRACING_PIPELINE, 5, subobjects};
	ID3D12StateObject *pipeline = NULL;
	CHECK("state object", ID3D12Device5_CreateStateObject(device5, &pipeline_desc, &IID_ID3D12StateObject, (void **)&pipeline));
	ID3D12StateObjectProperties *properties = NULL;
	CHECK("state object properties", ID3D12StateObject_QueryInterface(pipeline, &IID_ID3D12StateObjectProperties, (void **)&properties));

	/* The shader table: the ray generation, miss and hit group records, one 64 byte record each. */
	ID3D12Resource *table = make_buffer(D3D12_HEAP_TYPE_UPLOAD, 4 * RECORD, D3D12_RESOURCE_FLAG_NONE, D3D12_RESOURCE_STATE_GENERIC_READ, "shader table");
	BYTE records[4 * RECORD] = {0};
#if defined(ANYHIT)
	static const wchar_t *names[4] = {L"raygen", L"miss", L"HitGroup", L"background"};
	const int record_count = 4;
#else
	static const wchar_t *names[3] = {L"raygen", L"miss", L"HitGroup"};
	const int record_count = 3;
#endif
	for (int index = 0; index < record_count; ++index) {
		const void *identifier = ID3D12StateObjectProperties_GetShaderIdentifier(properties, names[index]);
		if (!identifier)
			fail("shader identifier", index);
		for (int byte = 0; byte < D3D12_SHADER_IDENTIFIER_SIZE_IN_BYTES; ++byte)
			records[index * RECORD + byte] = ((const BYTE *)identifier)[byte];
	}
	upload(table, records, sizeof records);

#endif

	/* The output texture and the two descriptors. */
	D3D12_HEAP_PROPERTIES default_heap = {D3D12_HEAP_TYPE_DEFAULT, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_MEMORY_POOL_UNKNOWN, 1, 1};
	D3D12_RESOURCE_DESC texture_desc = {D3D12_RESOURCE_DIMENSION_TEXTURE2D, 0, SIZE, SIZE, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0},
		D3D12_TEXTURE_LAYOUT_UNKNOWN, D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS};
	ID3D12Resource *texture = NULL;
	CHECK("texture", ID3D12Device_CreateCommittedResource(device, &default_heap, D3D12_HEAP_FLAG_NONE, &texture_desc, D3D12_RESOURCE_STATE_UNORDERED_ACCESS,
		NULL, &IID_ID3D12Resource, (void **)&texture));
	D3D12_DESCRIPTOR_HEAP_DESC heap_desc = {D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV, 2, D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE, 0};
	ID3D12DescriptorHeap *heap = NULL;
	CHECK("descriptor heap", ID3D12Device_CreateDescriptorHeap(device, &heap_desc, &IID_ID3D12DescriptorHeap, (void **)&heap));
	D3D12_CPU_DESCRIPTOR_HANDLE cpu;
	heap->lpVtbl->GetCPUDescriptorHandleForHeapStart(heap, &cpu);
	D3D12_GPU_DESCRIPTOR_HANDLE gpu;
	heap->lpVtbl->GetGPUDescriptorHandleForHeapStart(heap, &gpu);
	const UINT step = ID3D12Device_GetDescriptorHandleIncrementSize(device, D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
	D3D12_SHADER_RESOURCE_VIEW_DESC srv = {0};
	srv.Format = DXGI_FORMAT_UNKNOWN;
	srv.ViewDimension = D3D12_SRV_DIMENSION_RAYTRACING_ACCELERATION_STRUCTURE;
	srv.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
	srv.RaytracingAccelerationStructure.Location = ID3D12Resource_GetGPUVirtualAddress(top);
	ID3D12Device_CreateShaderResourceView(device, NULL, &srv, cpu);
	D3D12_UNORDERED_ACCESS_VIEW_DESC uav = {DXGI_FORMAT_R8G8B8A8_UNORM, D3D12_UAV_DIMENSION_TEXTURE2D};
	D3D12_CPU_DESCRIPTOR_HANDLE second = {cpu.ptr + step};
	ID3D12Device_CreateUnorderedAccessView(device, texture, NULL, &uav, second);

	const UINT pitch = SIZE * 4;
	ID3D12Resource *readback = make_buffer(D3D12_HEAP_TYPE_READBACK, (UINT64)pitch * SIZE, D3D12_RESOURCE_FLAG_NONE, D3D12_RESOURCE_STATE_COPY_DEST, "readback");

	/* Build both structures, trace, and copy the picture out. */
	D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_DESC build = {0};
	build.DestAccelerationStructureData = ID3D12Resource_GetGPUVirtualAddress(bottom);
	build.Inputs = bottom_inputs;
	build.ScratchAccelerationStructureData = ID3D12Resource_GetGPUVirtualAddress(scratch);
#if defined(SCENE)
	/* Build the bottom level structure and have the GPU write the size it would have compacted, read that size back, and make the compacted
	 * copy; the top level structure is then built over the compacted one. */
	ID3D12Resource *size_buffer = make_buffer(D3D12_HEAP_TYPE_DEFAULT, 8, D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS, D3D12_RESOURCE_STATE_UNORDERED_ACCESS, "size buffer");
	ID3D12Resource *size_readback = make_buffer(D3D12_HEAP_TYPE_READBACK, 8, D3D12_RESOURCE_FLAG_NONE, D3D12_RESOURCE_STATE_COPY_DEST, "size readback");
	D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_DESC post = {ID3D12Resource_GetGPUVirtualAddress(size_buffer),
		D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_COMPACTED_SIZE};
	ID3D12GraphicsCommandList4_BuildRaytracingAccelerationStructure(list, &build, 1, &post);
	uav_barrier(list, bottom);
	D3D12_RESOURCE_BARRIER to_copy = {D3D12_RESOURCE_BARRIER_TYPE_TRANSITION, D3D12_RESOURCE_BARRIER_FLAG_NONE};
	to_copy.Transition.pResource = size_buffer;
	to_copy.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
	to_copy.Transition.StateBefore = D3D12_RESOURCE_STATE_UNORDERED_ACCESS;
	to_copy.Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_SOURCE;
	ID3D12GraphicsCommandList4_ResourceBarrier(list, 1, &to_copy);
	ID3D12GraphicsCommandList4_CopyBufferRegion(list, size_readback, 0, size_buffer, 0, 8);
	CHECK("close first", ID3D12GraphicsCommandList4_Close(list));
	ID3D12Fence *first_fence = NULL;
	CHECK("first fence", ID3D12Device_CreateFence(device, 0, D3D12_FENCE_FLAG_NONE, &IID_ID3D12Fence, (void **)&first_fence));
	ID3D12CommandList *first_lists[] = {(ID3D12CommandList *)list};
	ID3D12CommandQueue_ExecuteCommandLists(queue, 1, first_lists);
	CHECK("first signal", ID3D12CommandQueue_Signal(queue, first_fence, 1));
	HANDLE first_event = CreateEventW(NULL, FALSE, FALSE, NULL);
	CHECK("first completion", ID3D12Fence_SetEventOnCompletion(first_fence, 1, first_event));
	if (WaitForSingleObject(first_event, 60000) != WAIT_OBJECT_0)
		fail("first wait", 0);
	UINT64 compacted_size = 0;
	{
		void *size_mapped = NULL;
		D3D12_RANGE size_range = {0, 8};
		CHECK("map size", ID3D12Resource_Map(size_readback, 0, &size_range, &size_mapped));
		compacted_size = *(const UINT64 *)size_mapped;
		D3D12_RANGE size_none = {0, 0};
		ID3D12Resource_Unmap(size_readback, 0, &size_none);
	}
	if (!compacted_size || compacted_size > bottom_info.ResultDataMaxSizeInBytes)
		fail("compacted size", (HRESULT)compacted_size);
	{
		char text[64];
		wsprintfA(text, "%u %u", (unsigned)compacted_size, (unsigned)bottom_info.ResultDataMaxSizeInBytes);
		write_file(L"C:\\rtscene_sizes.txt", text, (DWORD)lstrlenA(text));
	}
	ID3D12Resource *compact = make_buffer(D3D12_HEAP_TYPE_DEFAULT, compacted_size, D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS,
		D3D12_RESOURCE_STATE_RAYTRACING_ACCELERATION_STRUCTURE, "compacted buffer");
	instance[0].AccelerationStructure = instance[1].AccelerationStructure = ID3D12Resource_GetGPUVirtualAddress(compact);
	upload(instances, instance, sizeof instance);
	CHECK("reset allocator", ID3D12CommandAllocator_Reset(allocator));
	CHECK("reset list", ID3D12GraphicsCommandList4_Reset(list, allocator, NULL));
	ID3D12GraphicsCommandList4_CopyRaytracingAccelerationStructure(list, ID3D12Resource_GetGPUVirtualAddress(compact),
		ID3D12Resource_GetGPUVirtualAddress(bottom), D3D12_RAYTRACING_ACCELERATION_STRUCTURE_COPY_MODE_COMPACT);
	uav_barrier(list, compact);
#else
	ID3D12GraphicsCommandList4_BuildRaytracingAccelerationStructure(list, &build, 0, NULL);
	uav_barrier(list, bottom);
#endif
	build.DestAccelerationStructureData = ID3D12Resource_GetGPUVirtualAddress(top);
	build.Inputs = top_inputs;
	ID3D12GraphicsCommandList4_BuildRaytracingAccelerationStructure(list, &build, 0, NULL);
	uav_barrier(list, top);

	ID3D12GraphicsCommandList4_SetDescriptorHeaps(list, 1, &heap);
	ID3D12GraphicsCommandList4_SetComputeRootSignature(list, root);
	ID3D12GraphicsCommandList4_SetComputeRootDescriptorTable(list, 0, gpu);
#ifdef INLINE_QUERY
	ID3D12GraphicsCommandList4_SetPipelineState(list, compute_state);
	ID3D12GraphicsCommandList4_Dispatch(list, SIZE / 8, SIZE / 8, 1);
#else
	ID3D12GraphicsCommandList4_SetPipelineState1(list, pipeline);
	const D3D12_GPU_VIRTUAL_ADDRESS table_address = ID3D12Resource_GetGPUVirtualAddress(table);
	D3D12_DISPATCH_RAYS_DESC dispatch = {0};
	dispatch.RayGenerationShaderRecord.StartAddress = table_address;
	dispatch.RayGenerationShaderRecord.SizeInBytes = RECORD;
	dispatch.MissShaderTable.StartAddress = table_address + RECORD;
	dispatch.MissShaderTable.SizeInBytes = RECORD;
	dispatch.MissShaderTable.StrideInBytes = RECORD;
	dispatch.HitGroupTable.StartAddress = table_address + 2 * RECORD;
	dispatch.HitGroupTable.SizeInBytes = RECORD;
	dispatch.HitGroupTable.StrideInBytes = RECORD;
#if defined(ANYHIT)
	dispatch.CallableShaderTable.StartAddress = table_address + 3 * RECORD;
	dispatch.CallableShaderTable.SizeInBytes = RECORD;
	dispatch.CallableShaderTable.StrideInBytes = RECORD;
#endif
	dispatch.Width = SIZE;
	dispatch.Height = SIZE;
	dispatch.Depth = 1;
	ID3D12GraphicsCommandList4_DispatchRays(list, &dispatch);

#endif

	D3D12_RESOURCE_BARRIER transition = {D3D12_RESOURCE_BARRIER_TYPE_TRANSITION, D3D12_RESOURCE_BARRIER_FLAG_NONE};
	transition.Transition.pResource = texture;
	transition.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
	transition.Transition.StateBefore = D3D12_RESOURCE_STATE_UNORDERED_ACCESS;
	transition.Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_SOURCE;
	ID3D12GraphicsCommandList4_ResourceBarrier(list, 1, &transition);
	D3D12_TEXTURE_COPY_LOCATION destination = {readback, D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT};
	destination.PlacedFootprint.Footprint.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	destination.PlacedFootprint.Footprint.Width = SIZE;
	destination.PlacedFootprint.Footprint.Height = SIZE;
	destination.PlacedFootprint.Footprint.Depth = 1;
	destination.PlacedFootprint.Footprint.RowPitch = pitch;
	D3D12_TEXTURE_COPY_LOCATION source = {texture, D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX};
	ID3D12GraphicsCommandList4_CopyTextureRegion(list, &destination, 0, 0, 0, &source, NULL);
	CHECK("close", ID3D12GraphicsCommandList4_Close(list));

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
	D3D12_RANGE range = {0, (SIZE_T)pitch * SIZE};
	CHECK("map", ID3D12Resource_Map(readback, 0, &range, &mapped));
	write_file(OUT_RAW, mapped, pitch * SIZE);
	D3D12_RANGE none = {0, 0};
	ID3D12Resource_Unmap(readback, 0, &none);
	write_file(OUT_TXT, "OK", 2);
	ExitProcess(0);
}
