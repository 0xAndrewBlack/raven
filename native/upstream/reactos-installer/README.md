# Windows Installer components

`scripts/provision-installer.py` builds the Windows Installer engine and the libraries it
installs with from the pinned ReactOS archive the common controls component uses
(`dacf2a6c47fa562799f9c8a41ab6d5c558556558`, SHA-256
`5373bbbb60541cb2a49e0acb53360e1218d4f5d56c31f9187b341b9fc16daa69`), for 64-bit
programs and, with `--arch x86`, for 32-bit ones:

- `msi.dll` (`dll/win32/msi`): the installer engine, its SQL and condition grammars
  (bison) and the RPC stubs of its custom action server (widl);
- `cabinet.dll` (`dll/win32/cabinet`, on `sdk/lib/3rdparty/zlib`);
- `sxs.dll` (`dll/win32/sxs`): the side-by-side assembly cache;
- `raven-storage.dll`: the structured storage of `dll/win32/ole32` and
  `dll/win32/coml2`, the compound files packages are made of. The runtime's ole32
  hands those exports to it.

The runtime takes `msi.dll`, `cabinet.dll` and `sxs.dll` from beside itself whatever
copies a program ships or an installer leaves in the system directory.

Raven's corrections to upstream behavior live in `patches/` and are applied before the
build. `support.c` and `storage.c` are Raven code: they answer the compatibility
database, binary file patches and the class key helper the sources expect from
libraries Raven does not ship. Binary patches of installed files are not applied yet.
The build records every command, the hash of each extracted source and of each
component in `provenance.json`.

Upstream license texts stay beside the sources: the libraries are LGPL-2.1+. Product
license and distribution review remains required before packaging.
