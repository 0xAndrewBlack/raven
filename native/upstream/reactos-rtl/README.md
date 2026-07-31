# Guest RTL component

`scripts/provision-rtl.py` builds selected unchanged ReactOS RTL/CRT files at
`dacf2a6c47fa562799f9c8a41ab6d5c558556558`. The source archive SHA-256 is
`5373bbbb60541cb2a49e0acb53360e1218d4f5d56c31f9187b341b9fc16daa69`.
User-mode support functions, Unicode initialization and the verifier notification
retain their original bytes and notices. The build records their source ranges and
hashes, generates official NT/IDL headers, and uses GCC's AMD64 SEH support.

`initialize.c` connects the private RTL initializers to Raven-owned heap-list
storage. The public creation export checks the list bound and unsupported modes
before entering the unchanged allocator. The component imports only NT services
and exception/diagnostic boundaries; it has no DllMain, TLS or upstream loader.
Unimplemented thread/keyed-event/performance-counter/diagnostic paths stop
explicitly. Guest exception handler dispatch remains incomplete.

Upstream COPYING, COPYING.LIB and COPYING.ARM remain beside the extracted sources.
The selected source/header set contains mixed licenses. Product license and
distribution review remains required before packaging; source/function provenance
does not replace that review.
