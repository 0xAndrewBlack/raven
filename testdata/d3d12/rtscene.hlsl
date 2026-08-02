RaytracingAccelerationStructure scene : register(t0);
RWTexture2D<float4> output : register(u0);
struct Payload { float4 color; };

[shader("raygeneration")]
void raygen()
{
	uint2 id = DispatchRaysIndex().xy;
	uint2 size = DispatchRaysDimensions().xy;
	float2 uv = (float2(id) + 0.5) / float2(size);
	RayDesc ray;
	ray.Origin = float3(uv.x * 2.0 - 1.0, 1.0 - uv.y * 2.0, -1.0);
	ray.Direction = float3(0.0, 0.0, 1.0);
	ray.TMin = 0.0;
	ray.TMax = 10.0;
	Payload payload;
	payload.color = float4(0.0, 0.0, 0.0, 0.0);
	// A multiplier of zero: every geometry of every instance uses the one hit group record.
	TraceRay(scene, RAY_FLAG_NONE, 0xff, 0, 0, 0, ray, payload);
	output[id] = payload.color;
}

// The colour depends on the instance and on the geometry inside the instance's bottom level structure.
[shader("closesthit")]
void chit(inout Payload payload, BuiltInTriangleIntersectionAttributes attributes)
{
	const float3 table[4] = {float3(1, 0, 0), float3(0, 1, 0), float3(0, 0, 1), float3(1, 1, 0)};
	payload.color = float4(table[InstanceID() * 2 + GeometryIndex()], 1.0);
}

[shader("miss")]
void miss(inout Payload payload)
{
	payload.color = float4(0.1, 0.1, 0.3, 1.0);
}
