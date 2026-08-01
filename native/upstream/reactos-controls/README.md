# Common controls component

`scripts/provision-controls.py` builds the ReactOS common controls library
(`dll/win32/comctl32`) from the pinned archive at
`dacf2a6c47fa562799f9c8a41ab6d5c558556558` (SHA-256
`5373bbbb60541cb2a49e0acb53360e1218d4f5d56c31f9187b341b9fc16daa69`). The upstream
sources, resources and export specification are compiled as pinned, apart from the patches below; the build
records every command and the SHA-256 of each extracted source in
`provenance.json`.

Raven's corrections to upstream behavior live in `patches/` as unified diffs applied
before the build; their hashes are recorded in `provenance.json`.

The build exports `LoadIconWithScaleDown` at ordinal 381 as version 6 programs expect. `debug.c` replaces the upstream trace formatter with a version that never
traces, and `guids.c` instantiates the image list interface identifiers. Both are
Raven code. The component imports only the system DLLs that Raven provides.

Upstream license texts stay beside the sources: the library is LGPL-2.1+. Product
license and distribution review remains required before packaging.
