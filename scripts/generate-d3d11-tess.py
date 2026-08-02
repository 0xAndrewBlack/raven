#!/usr/bin/env python3
"""Assemble the hull and domain shaders of the Direct3D 11 tessellation workload and write them as a C header.

As with the geometry shader (generate-d3d11-gs.py) no installed compiler writes these stages, so the shader model 5.0 tokens are encoded by
hand. The stages sit between tri_vs and tri_ps, which keep their signatures: the vertex shader's outputs are the hull shader's control
points. The pair draws every triangle patch at half size:

	hs_5_0
	hs_decls
	dcl_input_control_point_count 3
	dcl_output_control_point_count 3
	dcl_tessellator_domain domain_tri
	dcl_tessellator_partitioning partitioning_integer
	dcl_tessellator_output_primitive output_triangle_cw
	dcl_hs_max_tessfactor l(64.0)
	hs_control_point_phase
	dcl_input vicp[3][0].xyzw
	dcl_input vicp[3][1].xyzw
	dcl_input vOutputControlPointID
	dcl_output o0.xyzw
	dcl_output o1.xyzw
	mov o0.xyzw, vicp[vOutputControlPointID + 0][0].xyzw
	mov o1.xyzw, vicp[vOutputControlPointID + 0][1].xyzw
	ret
	hs_fork_phase
	dcl_output_siv o0.x, finalTriUeq0EdgeTessFactor  (and the V and W edges, o1 and o2)
	dcl_output_siv o3.x, finalTriInsideTessFactor
	mov o0.x, l(3.0)  (and the other three factors)
	ret

	ds_5_0
	dcl_input_control_point_count 3
	dcl_tessellator_domain domain_tri
	dcl_input vDomain.xyz
	dcl_input vicp[3][0].xyzw
	dcl_input vicp[3][1].xyzw
	dcl_output_siv o0.xyzw, position
	dcl_output o1.xyzw
	dcl_temps 1
	the barycentric blend of the three control points' positions, then mul o0.xyzw, r0.xyzw, l(0.5, 0.5, 1.0, 1.0),
	and the barycentric blend of their colours into o1

usage: generate-d3d11-tess.py TRI_SHADERS_HEADER OUTPUT_HEADER
"""

import importlib.util
import struct
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("gs", Path(__file__).with_name("generate-d3d11-gs.py"))
gs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gs)

OP_MOV, OP_MUL, OP_MAD, OP_RET, OP_TEMPS = 54, 56, 50, 62, 104
OP_INPUT, OP_OUTPUT, OP_OUTPUT_SIV = 95, 101, 103
OP_HS_DECLS, OP_CONTROL_POINT_PHASE, OP_FORK_PHASE = 113, 114, 115
OP_INPUT_CP_COUNT, OP_OUTPUT_CP_COUNT, OP_DOMAIN, OP_PARTITIONING, OP_OUTPUT_PRIMITIVE, OP_MAX_TESSFACTOR = 147, 148, 149, 150, 151, 152
DOMAIN_TRI, PARTITIONING_INTEGER, PRIMITIVE_TRIANGLE_CW = 2, 1, 3
POSITION = 1
TRI_U_EQ_0, TRI_V_EQ_0, TRI_W_EQ_0, TRI_INSIDE = 17, 18, 19, 20

TYPE_TEMP, TYPE_OUTPUT_CONTROL_POINT_ID, TYPE_INPUT_CONTROL_POINT, TYPE_DOMAIN_POINT = 0, 22, 25, 28
REPRESENTATION_IMMEDIATE_PLUS_RELATIVE = 3


def swizzle(*lanes):
    return sum(lane << (2 * position) for position, lane in enumerate(lanes))


XYZW, XXXX, YYYY, ZZZZ = swizzle(0, 1, 2, 3), swizzle(0, 0, 0, 0), swizzle(1, 1, 1, 1), swizzle(2, 2, 2, 2)

# Operand tokens: components (2 is four), selection mode (0 mask, 1 swizzle, 2 select one), mask or swizzle, type, index dimension.
CONTROL_POINT_MASK = 2 | (0xF << 4) | (TYPE_INPUT_CONTROL_POINT << 12) | (2 << 20)
OUTPUT_MASK = gs.OUTPUT_MASK
TEMP_MASK = 2 | (0xF << 4) | (TYPE_TEMP << 12) | (1 << 20)
TEMP_SWIZZLE = 2 | (1 << 2) | (XYZW << 4) | (TYPE_TEMP << 12) | (1 << 20)
DOMAIN_MASK = 2 | (0x7 << 4) | (TYPE_DOMAIN_POINT << 12)
IMMEDIATE4 = gs.IMMEDIATE4
CONTROL_POINT_ID = 1 | (TYPE_OUTPUT_CONTROL_POINT_ID << 12)
CONTROL_POINT_ID_X = 1 | (2 << 2) | (TYPE_OUTPUT_CONTROL_POINT_ID << 12)
OUTPUT_X = 2 | (1 << 4) | (2 << 12) | (1 << 20)


def control_point(lanes=XYZW):
    return 2 | (1 << 2) | (lanes << 4) | (TYPE_INPUT_CONTROL_POINT << 12) | (2 << 20)


def domain(lanes):
    return 2 | (1 << 2) | (lanes << 4) | (TYPE_DOMAIN_POINT << 12)


def opcode(number, length, specific=0):
    return gs.opcode(number, length, specific)


def f32(value):
    return gs.f32(value)


def shader_blob(program_type, tokens):
    version = (program_type << 16) | (5 << 4)
    return struct.pack(f"<{len(tokens) + 2}I", version, len(tokens) + 2, *tokens)


def hull_program():
    # A control point read through the output control point id: vicp[vOutputControlPointID + 0][register].
    def read(register):
        return [opcode(OP_MOV, 7), OUTPUT_MASK, register,
                control_point() | (REPRESENTATION_IMMEDIATE_PLUS_RELATIVE << 22), 0, CONTROL_POINT_ID_X, register]

    tokens = [
        opcode(OP_HS_DECLS, 1),
        opcode(OP_INPUT_CP_COUNT, 1, 3), opcode(OP_OUTPUT_CP_COUNT, 1, 3),
        opcode(OP_DOMAIN, 1, DOMAIN_TRI), opcode(OP_PARTITIONING, 1, PARTITIONING_INTEGER),
        opcode(OP_OUTPUT_PRIMITIVE, 1, PRIMITIVE_TRIANGLE_CW),
        opcode(OP_MAX_TESSFACTOR, 2), f32(64.0),
        opcode(OP_CONTROL_POINT_PHASE, 1),
        opcode(OP_INPUT, 4), CONTROL_POINT_MASK, 3, 0,
        opcode(OP_INPUT, 4), CONTROL_POINT_MASK, 3, 1,
        opcode(OP_INPUT, 2), CONTROL_POINT_ID,
        opcode(OP_OUTPUT, 3), OUTPUT_MASK, 0,
        opcode(OP_OUTPUT, 3), OUTPUT_MASK, 1,
    ]
    tokens += read(0) + read(1) + [opcode(OP_RET, 1)]
    factors = (TRI_U_EQ_0, TRI_V_EQ_0, TRI_W_EQ_0, TRI_INSIDE)
    tokens += [opcode(OP_FORK_PHASE, 1)]
    for register, name in enumerate(factors):
        tokens += [opcode(OP_OUTPUT_SIV, 4), OUTPUT_X, register, name]
    for register in range(len(factors)):
        tokens += [opcode(OP_MOV, 8), OUTPUT_X, register, IMMEDIATE4, f32(3.0), f32(3.0), f32(3.0), f32(3.0)]
    tokens += [opcode(OP_RET, 1)]
    return shader_blob(3, tokens)


def domain_program():
    tokens = [
        opcode(OP_INPUT_CP_COUNT, 1, 3), opcode(OP_DOMAIN, 1, DOMAIN_TRI),
        opcode(OP_INPUT, 2), DOMAIN_MASK,
        opcode(OP_INPUT, 4), CONTROL_POINT_MASK, 3, 0,
        opcode(OP_INPUT, 4), CONTROL_POINT_MASK, 3, 1,
        opcode(OP_OUTPUT_SIV, 4), OUTPUT_MASK, 0, POSITION,
        opcode(OP_OUTPUT, 3), OUTPUT_MASK, 1,
        opcode(OP_TEMPS, 2), 1,
    ]

    def blend(register):
        tokens.extend([opcode(OP_MUL, 7), TEMP_MASK, 0, control_point(), 0, register, domain(XXXX)])
        for vertex, lanes in ((1, YYYY), (2, ZZZZ)):
            tokens.extend([opcode(OP_MAD, 9), TEMP_MASK, 0, control_point(), vertex, register, domain(lanes), TEMP_SWIZZLE, 0])

    blend(0)
    tokens += [opcode(OP_MUL, 10), OUTPUT_MASK, 0, TEMP_SWIZZLE, 0, IMMEDIATE4, f32(0.5), f32(0.5), f32(1.0), f32(1.0)]
    blend(1)
    tokens += [opcode(OP_MOV, 5), OUTPUT_MASK, 1, TEMP_SWIZZLE, 0]
    tokens += [opcode(OP_RET, 1)]
    return shader_blob(4, tokens)


def signature(entries):
    """A signature chunk of (name, index, system value, register, mask, unused mask) entries; every component type is float."""
    names, table = [], b""
    start = 8 + 24 * len(entries)
    for entry in entries:
        names.append(start + len(table))
        table += entry[0].encode() + b"\0"
    data = struct.pack("<II", len(entries), 8)
    for offset, (name, index, system, register, mask, unused) in zip(names, entries):
        data += struct.pack("<IIIIIBBH", offset, index, system, 3, register, mask, unused, 0)
    data += table
    return data + bytes(-len(data) % 4)


def as_input(blob):
    """The same elements as an input signature: the last mask byte is then the mask of the components that are read."""
    count = struct.unpack_from("<I", blob, 0)[0]
    data = bytearray(blob)
    for index in range(count):
        base = 8 + 24 * index
        data[base + 21] = data[base + 20]
    return bytes(data)


def main():
    source, target = sys.argv[1:3]
    vertex = gs.chunks(gs.read_array(open(source).read(), "tri_vs"))
    control_points = vertex[b"OSGN"]
    patch = signature([("SV_TessFactor", 0, TRI_U_EQ_0, 0, 1, 14), ("SV_TessFactor", 1, TRI_V_EQ_0, 1, 1, 14),
                       ("SV_TessFactor", 2, TRI_W_EQ_0, 2, 1, 14), ("SV_InsideTessFactor", 0, TRI_INSIDE, 3, 1, 14)])
    hull = gs.container([(b"ISGN", as_input(control_points)), (b"OSGN", control_points), (b"PCSG", patch), (b"SHEX", hull_program())])
    domain_blob = gs.container([(b"ISGN", as_input(control_points)), (b"OSGN", control_points), (b"PCSG", patch), (b"SHEX", domain_program())])
    with open(target, "w") as out:
        out.write("/* Generated by scripts/generate-d3d11-tess.py: hs_5_0 and ds_5_0 shaders that draw each triangle patch at half size. */\n")
        for name, blob in (("tri_hs", hull), ("tri_ds", domain_blob)):
            lines = ["\t" + ", ".join(f"0x{byte:02x}" for byte in blob[start:start + 12]) + "," for start in range(0, len(blob), 12)]
            out.write(f"static const unsigned char {name}[] = {{\n" + "\n".join(lines) + "\n};\n")


if __name__ == "__main__":
    main()
