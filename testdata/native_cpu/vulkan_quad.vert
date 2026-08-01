#version 450
layout(location = 0) in vec2 position;
layout(location = 1) in vec2 coordinate;
layout(location = 0) out vec2 varying_coordinate;
void main()
{
	varying_coordinate = coordinate;
	gl_Position = vec4(position, 0.0, 1.0);
}
