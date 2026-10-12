#!/usr/bin/env python3
"""Generate l_intl.nls: the upper and lower case tables Windows keeps in the system directory.

The .NET Framework 2.0 runtime maps this file to change the case of text. The tables come from the Unicode
character database of Python's unicodedata module: each character of the Basic Multilingual Plane that has a
single-character case mapping that maps back to it.

The file is a version word (1) followed by the upper case table and the lower case table. Each table is a word
holding its own length in words, then three levels: 256 offsets for the high byte of a character, rows of 16
offsets for its next four bits, and rows of 16 differences for its last four bits. A character c maps to
c + table[table[table[c >> 8] + ((c >> 4) & 15)] + (c & 15)], modulo 65536, offsets counting words after the
length.

usage: generate-intl-nls.py OUTPUT
"""

import struct
import sys


def mapping(convert):
    table = [0] * 65536
    for code in range(65536):
        if 0xd800 <= code <= 0xdfff:
            continue
        mapped = convert(chr(code))
        # A letter whose full upper case is two letters, as a Greek vowel with its iota below, keeps its simple mapping in title case.
        if convert is str.upper and len(mapped) != 1 and len(chr(code).title()) == 1:
            mapped = chr(code).title()
        if len(mapped) == 1 and ord(mapped) < 65536 and ord(mapped) != code:
            table[code] = ord(mapped)
    return table


def round_trip(upper, lower):
    # A case mapping counts only when the other table maps the result back.
    upper_kept = [target if target and lower[target] == code else 0 for code, target in enumerate(upper)]
    lower_kept = [target if target and upper[target] == code else 0 for code, target in enumerate(lower)]
    return upper_kept, lower_kept


def binary_table(table):
    differences = [((target - code) & 0xffff) if target else 0 for code, target in enumerate(table)]
    data_rows, data_index = [], {}
    middle = []
    for block in range(4096):
        row = tuple(differences[block * 16:block * 16 + 16])
        if row not in data_index:
            data_index[row] = len(data_rows)
            data_rows.append(row)
        middle.append(data_index[row])
    middle_rows, middle_index = [], {}
    top = []
    for high in range(256):
        row = tuple(middle[high * 16:high * 16 + 16])
        if row not in middle_index:
            middle_index[row] = len(middle_rows)
            middle_rows.append(row)
        top.append(middle_index[row])
    middle_start = 256
    data_start = middle_start + 16 * len(middle_rows)
    words = [middle_start + 16 * index for index in top]
    for row in middle_rows:
        words.extend(data_start + 16 * index for index in row)
    for row in data_rows:
        words.extend(row)
    return struct.pack("<%dH" % (len(words) + 1), len(words) + 1, *words)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    upper, lower = round_trip(mapping(str.upper), mapping(str.lower))
    with open(sys.argv[1], "wb") as output:
        output.write(struct.pack("<H", 1) + binary_table(upper) + binary_table(lower))


if __name__ == "__main__":
    main()
