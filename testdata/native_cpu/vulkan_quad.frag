#version 450
layout(set = 0, binding = 0) uniform sampler2D surface;
layout(location = 0) in vec2 varying_coordinate;
layout(location = 0) out vec4 color;
void main() { color = texture(surface, varying_coordinate); }
