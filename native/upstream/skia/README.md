# Skia CPU text backend

Source: https://skia.googlesource.com/skia.git
Revision: a21aae83d6e4e3da284100a30f0a5eafc443b60f.
The source is unchanged; LICENSE is retained unchanged.

RAVEN_SKIA_SOURCE, RAVEN_SKIA_LIBRARY and RAVEN_FONT_DIRECTORY enable the
qualified CPU/FreeType backend. The font-enabled library uses the custom-empty
font manager and system FreeType; GPU, fontconfig, HarfBuzz and ICU are disabled
in this configuration. Source/build trees remain outside the repository. CMake
checks the three qualified Liberation 2.1.5 regular font hashes. The fonts carry
SIL Open Font License 1.1 metadata; font/FreeType distribution notices and the
complete product packaging/license review remain required.

The backend owns immutable typefaces and transient glyph masks only. Raven owns
logical fonts, DC selections/colors/clips, bitmap pixels and HWNDs. Antialias
measurement and monochrome glyph drawing are separate qualified operations.
Native text uses the existing canonical bitmap storage and exact GDI alpha rules.
Unsupported font styles, quality, stock fonts, shaping and mapping paths fail
explicitly. This is selected text adoption, not full GDI or Skia backend coverage.

Clang instruments Raven's adapter with ASan/UBSan. The pinned Skia Release library
is not instrumented. Native contract fixtures validate metrics and pixels. Application compatibility
is tested separately.
