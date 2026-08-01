cbuffer Tint : register(b0)
{
	float4 tint;
};
Texture2D tex : register(t0);
SamplerState samp : register(s0);
struct VSOut { float4 pos : SV_Position; float2 uv : TEXCOORD0; };
VSOut vs_main(float3 pos : POSITION, float2 uv : TEXCOORD0)
{
	VSOut o;
	o.pos = float4(pos, 1.0);
	o.uv = uv;
	return o;
}
float4 ps_main(VSOut i) : SV_Target { return tex.Sample(samp, i.uv) * tint; }
