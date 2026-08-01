struct VSOut { float4 pos : SV_Position; float4 color : COLOR0; };
VSOut vs_main(float2 pos : POSITION, float4 color : COLOR0)
{
	VSOut o;
	o.pos = float4(pos, 0.0, 1.0);
	o.color = color;
	return o;
}
float4 ps_main(VSOut i) : SV_Target { return i.color; }
