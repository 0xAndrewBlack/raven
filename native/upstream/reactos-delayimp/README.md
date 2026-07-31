# ReactOS delay import helper

Source: sdk/lib/delayimp/delayimp.c at
ReactOS dacf2a6c47fa562799f9c8a41ab6d5c558556558.

[Pinned source](https://github.com/reactos/reactos/blob/dacf2a6c47fa562799f9c8a41ab6d5c558556558/sdk/lib/delayimp/delayimp.c)

SHA-256: 3d2142502beec3d56394eebaec8064377173da2291c5a4a9d5094cf5c1cd1999.
The source is unchanged. Its MIT identifier and copyright notices are retained;
LICENSE contains the MIT terms for these authors.

CMake compiles this helper into Windows contract fixtures with MinGW headers
and LLVM's PE delay thunks. It is not compiled into the Linux runtime or used as
a second module loader. Guest LoadLibrary/GetProcAddress calls still pass through
Raven's own process coordinator. Default hook pointers are supplied by the
fixture. No other ReactOS source or complete NTDLL loader is adopted here.
