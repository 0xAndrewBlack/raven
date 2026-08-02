RaytracingAccelerationStructure scene : register(t0);
RWTexture2D<float4> output : register(u0);
struct Payload { float4 color; };
struct Disc { float2 point2; };

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

// The box around the disc is the only geometry; this shader decides which rays inside the box hit the disc of radius one half in the plane z = 0.
[shader("intersection")]
void isect()
{
	const float3 origin = ObjectRayOrigin();
	const float3 direction = ObjectRayDirection();
	const float t = -origin.z / direction.z;
	const float2 point2 = origin.xy + t * direction.xy;
	Disc disc;
	disc.point2 = point2;
	if (dot(point2, point2) < 0.25 && t >= RayTMin() && t <= RayTCurrent())
		ReportHit(t, 0, disc);
}

[shader("closesthit")]
void chit(inout Payload payload, Disc disc)
{
	payload.color = float4(1.0, 1.0, 0.0, 1.0);
}

[shader("miss")]
void miss(inout Payload payload)
{
	payload.color = float4(0.1, 0.1, 0.3, 1.0);
}
