RaytracingAccelerationStructure scene : register(t0);
RWTexture2D<float4> output : register(u0);
struct Payload { float4 color; };
struct CallData { float4 color; };

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
	TraceRay(scene, RAY_FLAG_NONE, 0xff, 0, 1, 0, ray, payload);
	output[id] = payload.color;
}

// The any hit shader throws away the part of the triangle whose weight for the second vertex is above one half.
[shader("anyhit")]
void ahit(inout Payload payload, BuiltInTriangleIntersectionAttributes attributes)
{
	if (attributes.barycentrics.x > 0.5)
		IgnoreHit();
}

[shader("closesthit")]
void chit(inout Payload payload, BuiltInTriangleIntersectionAttributes attributes)
{
	float3 weights = float3(1.0 - attributes.barycentrics.x - attributes.barycentrics.y, attributes.barycentrics.x, attributes.barycentrics.y);
	payload.color = float4(weights.x * float3(1, 0, 0) + weights.y * float3(0, 0, 1) + weights.z * float3(0, 1, 0), 1.0);
}

// A miss asks a callable shader for the background, so a callable shader that does not run leaves the picture black.
[shader("miss")]
void miss(inout Payload payload)
{
	CallData data;
	data.color = float4(0.0, 0.0, 0.0, 0.0);
	CallShader(0, data);
	payload.color = data.color;
}

[shader("callable")]
void background(inout CallData data)
{
	data.color = float4(0.1, 0.1, 0.3, 1.0);
}
