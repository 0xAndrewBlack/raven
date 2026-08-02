#!/usr/bin/env python3
"""Lists the methods of COM interfaces, in vtable order, with their stdcall argument word counts.

The counts come from a MinGW-w64 header: every parameter of these interfaces is a 32-bit word, so a method takes its parameter count plus
the object pointer. The order is the vtable's: the base interface first, then the methods the interface adds.

usage: generate-com-vtables.py HEADER OUTPUT.inc INTERFACE ...
"""

import re
import sys

DECLARATION = re.compile(r"DECLARE_INTERFACE(?:_IID)?_\(\s*(\w+)\s*,\s*(\w+)")
UNKNOWN = [("QueryInterface", 3), ("AddRef", 1), ("Release", 1)]


def declarations(text):
    return {match.group(1): (match.group(2), match.start()) for match in DECLARATION.finditer(text)}


def own_methods(text, name, start):
    end = text.index("#undef INTERFACE", start)
    found = []
    for match in re.finditer(r"STDMETHOD(?:_\(\s*[^,)]+,\s*(\w+)\s*\)|\((\w+)\))\s*\(([^;]*?)\)\s*PURE;", text[start:end], re.S):
        method, params = match.group(1) or match.group(2), match.group(3).strip()
        params = re.sub(r"^THIS_?", "", params).strip()
        count = 0
        if params:
            depth = 0
            count = 1
            for character in params:
                depth += character in "(<"
                depth -= character in ")>"
                if character == "," and depth == 0:
                    count += 1
        found.append((method, count + 1))
    return [item for item in found if item[0] not in ("QueryInterface", "AddRef", "Release")]


def table(text, known, interface):
    chain = []
    cursor = interface
    while cursor != "IUnknown":
        chain.append(cursor)
        cursor = known[cursor][0]
    result = list(UNKNOWN)
    for name in reversed(chain):
        result += own_methods(text, name, known[name][1])
    return result


def main():
    text = open(sys.argv[1]).read()
    known = declarations(text)
    with open(sys.argv[2], "w") as out:
        out.write(f"// Produced by scripts/generate-com-vtables.py from {sys.argv[1].rsplit('/', 1)[-1]} of MinGW-w64; do not edit.\n")
        for interface in sys.argv[3:]:
            out.write(f"// {interface}\n")
            for index, (name, words) in enumerate(table(text, known, interface)):
                out.write(f"{{\"{interface}\", \"{name}\", {index}, {words}}},\n")


if __name__ == "__main__":
    main()
