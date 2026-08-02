#!/usr/bin/env python3
"""Assemble the geometry shader of the Direct3D 11 geometry workload and write it as a C header.

No installed compiler produces geometry shaders (Wine's HLSL compiler stops at vertex and pixel shaders), so the program is encoded by
hand as shader model 4.0 tokens. The input and output signatures are those of the vertex shader in tri_shaders.h, so the stage fits
between tri_vs and tri_ps. The shader reads a triangle, scales each position by one half in x and y, copies the colour and emits the
three vertices as a triangle strip:

	gs_4_0
	dcl_input_siv v[3][0].xyzw, position
	dcl_input v[3][1].xyzw
	dcl_inputprimitive triangle
	dcl_outputtopology trianglestrip
	dcl_output_siv o0.xyzw, position
	dcl_output o1.xyzw
	dcl_maxout 3
	mul o0.xyzw, v[0][0].xyzw, l(0.5, 0.5, 1.0, 1.0)
	mov o1.xyzw, v[0][1].xyzw
	emit
	... the same for vertices 1 and 2 ...
	ret

usage: generate-d3d11-gs.py TRI_SHADERS_HEADER OUTPUT_HEADER
"""

import math
import re
import struct
import sys


def read_array(header, name):
    body = re.search(name + r"\[\] = \{(.*?)\};", header, re.S).group(1)
    return bytes(int(value, 16) for value in re.findall(r"0x([0-9a-f]{2})", body))


def chunks(blob):
    count = struct.unpack_from("<I", blob, 28)[0]
    found = {}
    for index in range(count):
        offset = struct.unpack_from("<I", blob, 32 + 4 * index)[0]
        tag, size = struct.unpack_from("<4sI", blob, offset)
        found[tag] = blob[offset + 8:offset + 8 + size]
    return found


OP_MOV, OP_MUL, OP_EMIT, OP_RET = 54, 56, 19, 62
OP_TOPOLOGY, OP_PRIMITIVE, OP_MAXOUT = 92, 93, 94
OP_INPUT, OP_INPUT_SIV, OP_OUTPUT, OP_OUTPUT_SIV = 95, 97, 101, 103
POSITION = 1

# Operand tokens: four components (2), selection mode, mask or swizzle, operand type, index dimension.
INPUT_MASK = 2 | (0xF << 4) | (1 << 12) | (2 << 20)
INPUT_SWIZZLE = 2 | (1 << 2) | (0xE4 << 4) | (1 << 12) | (2 << 20)
OUTPUT_MASK = 2 | (0xF << 4) | (2 << 12) | (1 << 20)
IMMEDIATE4 = 2 | (4 << 12)


def opcode(number, length, specific=0):
    return number | (specific << 11) | (length << 24)


def f32(value):
    return struct.unpack("<I", struct.pack("<f", value))[0]


def program():
    tokens = [
        opcode(OP_INPUT_SIV, 5), INPUT_MASK, 3, 0, POSITION,
        opcode(OP_INPUT, 4), INPUT_MASK, 3, 1,
        opcode(OP_PRIMITIVE, 1, 3),
        opcode(OP_TOPOLOGY, 1, 5),
        opcode(OP_OUTPUT_SIV, 4), OUTPUT_MASK, 0, POSITION,
        opcode(OP_OUTPUT, 3), OUTPUT_MASK, 1,
        opcode(OP_MAXOUT, 2), 3,
    ]
    for vertex in range(3):
        tokens += [opcode(OP_MUL, 11), OUTPUT_MASK, 0, INPUT_SWIZZLE, vertex, 0, IMMEDIATE4,
                   f32(0.5), f32(0.5), f32(1.0), f32(1.0)]
        tokens += [opcode(OP_MOV, 6), OUTPUT_MASK, 1, INPUT_SWIZZLE, vertex, 1]
        tokens += [opcode(OP_EMIT, 1)]
    tokens += [opcode(OP_RET, 1)]
    version = (2 << 16) | (4 << 4)
    return struct.pack(f"<{len(tokens) + 2}I", version, len(tokens) + 2, *tokens)


_SHIFTS = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
_CONSTANTS = [int(abs(math.sin(index + 1)) * 2 ** 32) & 0xFFFFFFFF for index in range(64)]


def md5_block(state, block):
    words = struct.unpack("<16I", block)
    a, b, c, d = state
    for index in range(64):
        if index < 16:
            mixed, word = (b & c) | (~b & d), index
        elif index < 32:
            mixed, word = (d & b) | (~d & c), (5 * index + 1) % 16
        elif index < 48:
            mixed, word = b ^ c ^ d, (3 * index + 5) % 16
        else:
            mixed, word = c ^ (b | ~d), (7 * index) % 16
        total = (a + mixed + _CONSTANTS[index] + words[word]) & 0xFFFFFFFF
        a, d, c = d, c, b
        b = (b + (((total << _SHIFTS[index]) | (total >> (32 - _SHIFTS[index]))) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, (a, b, c, d))]


def dxbc_checksum(blob):
    """The container checksum: MD5 of everything after it, with the length folded into the padding the way the Windows compiler does."""
    data = blob[20:]
    size = len(data)
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    for start in range(0, size - size % 64, 64):
        state = md5_block(state, data[start:start + 64])
    tail = data[size - size % 64:]
    bits, last = (size * 8) & 0xFFFFFFFF, ((size * 2) | 1) & 0xFFFFFFFF
    if len(tail) >= 56:
        state = md5_block(state, (tail + b"\x80").ljust(64, b"\0"))
        state = md5_block(state, struct.pack("<I", bits) + bytes(56) + struct.pack("<I", last))
    else:
        block = struct.pack("<I", bits) + tail + b"\x80"
        state = md5_block(state, block.ljust(60, b"\0") + struct.pack("<I", last))
    return struct.pack("<4I", *state)


def container(parts):
    header = 32 + 4 * len(parts)
    offsets, body = [], b""
    for tag, data in parts:
        offsets.append(header + len(body))
        body += tag + struct.pack("<I", len(data)) + data
    blob = b"DXBC" + bytes(16) + struct.pack("<III", 1, header + len(body), len(parts))
    blob += struct.pack(f"<{len(offsets)}I", *offsets) + body
    return blob[:4] + dxbc_checksum(blob) + blob[20:]


def main():
    source, target = sys.argv[1:3]
    vertex = chunks(read_array(open(source).read(), "tri_vs"))
    blob = container([(b"ISGN", vertex[b"OSGN"]), (b"OSGN", vertex[b"OSGN"]), (b"SHDR", program())])
    lines = []
    for start in range(0, len(blob), 12):
        lines.append("\t" + ", ".join(f"0x{byte:02x}" for byte in blob[start:start + 12]) + ",")
    with open(target, "w") as out:
        out.write("/* Generated by scripts/generate-d3d11-gs.py: a gs_4_0 shader that halves the x and y of a triangle. */\n")
        out.write("static const unsigned char tri_gs[] = {\n" + "\n".join(lines) + "\n};\n")


if __name__ == "__main__":
    main()
