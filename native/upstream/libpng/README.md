# libpng codec evaluation

Component: libpng 1.6.59, PNG Reference Library License version 2.
Source: https://download.sourceforge.net/libpng/libpng-1.6.59.tar.xz
SHA-256: d80dd2a38a37f803cb9b6ac7b14bd6e74ddc3b654780a8380bdf93523fdb4389
Published checksum: https://www.libpng.org/pub/png/libpng.html

Raven calls the unmodified library through its simplified decode API. Source
and build trees remain outside the repository. LICENSE is retained unchanged.
The native CMake target requires at least version 1.6.59 and uses PNG::PNG;
older installations do not enable this evaluation. The tested source is built
as a static library, separately for sanitizer and release builds.

The codec produces bounded top-down RGBA8 pixels with straight alpha. It owns
no Windows handles, windows, bitmaps or process state. PNG decompression is
upstream reuse; GDI masks, raster rules, scaling and icon lifetime remain Raven
contracts. This does not adopt the Skia rendering backend before GDI checks.
Skia also provides a libpng codec path:
https://skia.googlesource.com/skia/+/refs/heads/main/src/codec/SkPngCodec.cpp

Build the checksum-verified source with CMake, PNG_SHARED=OFF, PNG_STATIC=ON,
PNG_TESTS=OFF and PNG_TOOLS=OFF. Use separate build/install prefixes for Clang
Debug with AddressSanitizer/UBSan and GCC Release. Set CMAKE_PREFIX_PATH to the
matching install prefix when configuring Raven; keep both builds at two workers.
native_png_codec_contract reads the actual Notepad++ image, writes decoded RGBA
records into the build's png-output directory, and runs malformed-input controls.
The records are codec evidence, not DrawIconEx output or an executed application.
