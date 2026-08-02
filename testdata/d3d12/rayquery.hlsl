RaytracingAccelerationStructure scene : register(t0);
RWTexture2D<float4> output : register(u0);

[numthreads(8, 8, 1)]
void main(uint3 id : SV_DispatchThreadID)
{
	float2 uv = (float2(id.xy) + 0.5) / 256.0;
	RayDesc ray;
	ray.Origin = float3(uv.x * 2.0 - 1.0, 1.0 - uv.y * 2.0, -1.0);
	ray.Direction = float3(0.0, 0.0, 1.0);
	ray.TMin = 0.0;
	ray.TMax = 10.0;
	RayQuery<RAY_FLAG_NONE> query;
	query.TraceRayInline(scene, RAY_FLAG_NONE, 0xff, ray);
	query.Proceed();
	float4 color = float4(0.1, 0.1, 0.3, 1.0);
	if (query.CommittedStatus() == COMMITTED_TRIANGLE_HIT) {
		float2 b = query.CommittedTriangleBarycentrics();
		float3 weights = float3(1.0 - b.x - b.y, b.x, b.y);
		color = float4(weights.x * float3(1, 0, 0) + weights.y * float3(0, 0, 1) + weights.z * float3(0, 1, 0), 1.0);
	}
	output[id.xy] = color;
}
