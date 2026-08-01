RWBuffer<uint> output : register(u0);
Texture2D<float4> input : register(t0);
[numthreads(64, 1, 1)]
void cs_main(uint3 id : SV_DispatchThreadID)
{
	// Each thread writes a value derived from its index and from one texel read with Load.
	uint4 texel = (uint4)(input.Load(int3(id.x % 8, (id.x / 8) % 8, 0)) * 255.0 + 0.5);
	output[id.x] = id.x * id.x + 7 + texel.r;
}
