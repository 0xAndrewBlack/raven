cbuffer Constants : register(b0) { float4 colors[2]; };

struct VSOut {
	float4 pos : SV_Position;
	nointerpolation uint instance : INSTANCE;
};

// A quad per instance, built from the vertex number alone: instance 0 fills the left half of the target and instance 1 the right half.
VSOut vs_main(uint vertex : SV_VertexID, uint instance : SV_InstanceID)
{
	float2 corner = float2(vertex & 1, vertex >> 1);
	float left = instance == 0 ? -0.9 : 0.1;
	VSOut o;
	o.pos = float4(left + corner.x * 0.8, -0.8 + corner.y * 1.6, 0, 1);
	o.instance = instance;
	return o;
}

struct PSOut {
	float4 blended : SV_Target0;
	float4 marked : SV_Target1;
};

// The first target is blended over what is there; the second says which instance drew the pixel.
PSOut ps_main(VSOut i)
{
	PSOut o;
	o.blended = float4(colors[i.instance].rgb, 0.5);
	o.marked = float4(i.instance == 0 ? 1.0 : 0.0, 0.5, i.instance == 0 ? 0.0 : 1.0, 1.0);
	return o;
}
