# UTF-8 conversion

RtlUTF8ToUnicodeN and RtlUnicodeToUTF8N are selected unchanged from ReactOS revision
32bb061415f813b6ced25ff91f4d258f33c5191f, sdk/lib/rtl/utf8.c. Its GPL-2.0-or-later
notice and COPYING remain beside the source. provenance.json records source and
selection hashes for both functions. The native adapter supplies fixed-width types and host buffers;
guest memory remains owned and checked by NativeProcess. No upstream process,
loader, heap or NLS globals are imported. Product distribution review remains open.
