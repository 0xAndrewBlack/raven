#version 450
// A triangle that covers the upper left half of the target.
void main()
{
	vec2 corners[3] = vec2[](vec2(-1.0, -1.0), vec2(1.0, -1.0), vec2(-1.0, 1.0));
	gl_Position = vec4(corners[gl_VertexIndex], 0.0, 1.0);
}
