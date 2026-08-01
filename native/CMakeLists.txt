add_library(raven_pe STATIC pe/pe.cpp pe/loaded_image.cpp pe/module_set.cpp pe/resources.cpp)
target_include_directories(raven_pe PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(raven_pe PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_library(raven_pixels STATIC graphics/icon_bitmap.cpp graphics/icon_group.cpp graphics/stretch.cpp)
target_include_directories(raven_pixels PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(raven_pixels PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
add_executable(icon_bitmap_test graphics/icon_bitmap_test.cpp)
target_link_libraries(icon_bitmap_test PRIVATE raven_pixels raven_pe)
add_test(NAME native_icon_dib_contract COMMAND icon_bitmap_test
    ${PROJECT_SOURCE_DIR}/testdata/npp/notepad++.exe ${CMAKE_CURRENT_BINARY_DIR}/icon-output)
set_tests_properties(native_icon_dib_contract PROPERTIES TIMEOUT 30)
add_executable(icon_group_test graphics/icon_group_test.cpp)
target_link_libraries(icon_group_test PRIVATE raven_pixels raven_pe)
add_test(NAME native_icon_group_contract COMMAND icon_group_test ${PROJECT_SOURCE_DIR}/testdata/npp/notepad++.exe)
set_tests_properties(native_icon_group_contract PROPERTIES TIMEOUT 30)
add_executable(stretch_test graphics/stretch_test.cpp)
target_include_directories(stretch_test PRIVATE ${PROJECT_SOURCE_DIR}/testdata/native_loader)
target_link_libraries(stretch_test PRIVATE raven_pixels)
add_test(NAME native_blackonwhite_contract COMMAND stretch_test
    ${PROJECT_SOURCE_DIR}/testdata/native_loader/blackonwhite_reference.bin)
set_tests_properties(native_blackonwhite_contract PROPERTIES TIMEOUT 30)

find_package(PNG 1.6.59 QUIET)
if(PNG_FOUND)
    target_sources(raven_pixels PRIVATE graphics/png_codec.cpp)
    target_compile_definitions(raven_pixels PUBLIC RAVEN_PNG=1)
    target_link_libraries(raven_pixels PUBLIC PNG::PNG)
    add_executable(png_codec_test graphics/png_codec_test.cpp)
    target_link_libraries(png_codec_test PRIVATE raven_pixels raven_pe)
    add_test(NAME native_png_codec_contract COMMAND png_codec_test
        ${PROJECT_SOURCE_DIR}/testdata/npp/notepad++.exe ${CMAKE_CURRENT_BINARY_DIR}/png-output)
    set_tests_properties(native_png_codec_contract PROPERTIES TIMEOUT 30)
else()
    # Tests that decode PNG images need libpng 1.6.59 or newer; without it they are not built, so say so instead of staying silent.
    message(WARNING "libpng 1.6.59 or newer not found: PNG decoding and the tests that depend on it are disabled. "
        "Run scripts/provision-libpng.py and configure with the PNG_LIBRARY_RELEASE and PNG_PNG_INCLUDE_DIR it prints.")
    add_test(NAME native_png_dependent_tests_unavailable COMMAND ${CMAKE_COMMAND} -E echo
        "libpng 1.6.59 or newer is missing: PNG-dependent tests were not built (see scripts/provision-libpng.py)")
    set_tests_properties(native_png_dependent_tests_unavailable PROPERTIES SKIP_REGULAR_EXPRESSION "libpng 1.6.59 or newer is missing")
endif()

add_executable(raven main.cpp)
target_link_libraries(raven PRIVATE raven_pe)

add_executable(pe_test pe/pe_test.cpp)
target_link_libraries(pe_test PRIVATE raven_pe)
add_test(NAME pe_contracts COMMAND pe_test)
set_tests_properties(pe_contracts PROPERTIES TIMEOUT 10)

add_executable(module_set_test pe/module_set_test.cpp)
target_link_libraries(module_set_test PRIVATE raven_pe)
add_test(NAME module_set_contracts COMMAND module_set_test)
set_tests_properties(module_set_contracts PROPERTIES TIMEOUT 10)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    enable_language(ASM)
    add_executable(raven-bootstrap cpu/bootstrap.S)
    target_compile_options(raven-bootstrap PRIVATE -fno-sanitize=all)
    target_link_options(raven-bootstrap PRIVATE -fno-sanitize=all -nostdlib -static
        -Wl,-no-pie,-Ttext-segment=0x700000000000,-e,_start,--build-id=none)
    file(SHA256 ${CMAKE_CURRENT_SOURCE_DIR}/upstream/reactos-nonclient/borders.inc NONCLIENT_SOURCE_HASH)
    if(NOT NONCLIENT_SOURCE_HASH STREQUAL "dab51515f54adc39af43f088a02afe45a719476408bee3c7bef6113c25b180fc")
        message(FATAL_ERROR "Pinned ReactOS nonclient functions differ")
    endif()
    add_library(raven_cpu STATIC cpu/native_cpu.cpp nt/environment.cpp nt/system.cpp nt/providers.cpp nt/api.cpp nt/unwind.cpp nt/seh.cpp nt/apiset.cpp nt/system_exports.cpp nt/text.cpp nt/paths.cpp nt/file_api.cpp nt/ansi_api.cpp nt/shlwapi_api.cpp nt/registry_api.cpp nt/shell_api.cpp nt/platform_api.cpp nt/hash.cpp nt/version_api.cpp nt/system_api.cpp nt/process_api.cpp nt/sync_api.cpp nt/threads.cpp nt/thread_api.cpp nt/text_api.cpp nt/memory_api.cpp nt/guest_allocator.cpp nt/module_api.cpp nt/loader.cpp nt/tls.cpp nt/exceptions.cpp nt/resources.cpp nt/memory.cpp nt/objects.cpp nt/object_api.cpp nt/heap.cpp desktop/objects.cpp desktop/nonclient.cpp desktop/api.cpp desktop/surface.cpp desktop/windows.cpp desktop/system.cpp desktop/user_api.cpp desktop/window_manager.cpp desktop/menu_manager.cpp desktop/shared_pixels.cpp desktop/user_ext.cpp desktop/scrollbar.cpp desktop/window_long.cpp desktop/child_frame.cpp desktop/gdi.cpp desktop/gdi_api.cpp desktop/gdi_text.cpp)
    target_include_directories(raven_cpu PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    set(NLS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/upstream/reactos-nls)
    file(SHA256 ${NLS_SOURCE}/txt2nls.cpp NLS_TOOL_HASH)
    file(SHA256 ${NLS_SOURCE}/c_1252.txt NLS_TEXT_HASH)
    if(NOT NLS_TOOL_HASH STREQUAL "74053f42959ab949e58ab27587672740f954b2ffba5e3a931223fe8f9d6c1355" OR
       NOT NLS_TEXT_HASH STREQUAL "d606b8bf22f35178703d201cf81c45783bc211f0437f0d17db61c13fe53f1c69")
        message(FATAL_ERROR "Pinned ReactOS NLS sources differ")
    endif()
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/nls-generated)
    add_executable(raven-txt2nls ${NLS_SOURCE}/txt2nls.cpp)
    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/nls-generated/nls-cp1252.h
        COMMAND raven-txt2nls ${NLS_SOURCE}/c_1252.txt ${CMAKE_CURRENT_BINARY_DIR}/nls-generated/c_1252.nls
        COMMAND ${CMAKE_COMMAND} -DINPUT=${CMAKE_CURRENT_BINARY_DIR}/nls-generated/c_1252.nls
            -DOUTPUT=${CMAKE_CURRENT_BINARY_DIR}/nls-generated/nls-cp1252.h -P ${NLS_SOURCE}/embed.cmake
        DEPENDS raven-txt2nls ${NLS_SOURCE}/c_1252.txt ${NLS_SOURCE}/embed.cmake VERBATIM)
    target_sources(raven_cpu PRIVATE nt/nls.cpp nt/multibyte.cpp nt/startup.cpp nt/launch.cpp nt/file.cpp nt/prefix.cpp nt/registry.cpp nt/advapi_api.cpp nt/msvcrt_api.cpp nt/profile_api.cpp nt/x86_process.cpp ${CMAKE_CURRENT_BINARY_DIR}/nls-generated/nls-cp1252.h)
    file(SHA256 ${CMAKE_CURRENT_SOURCE_DIR}/upstream/reactos-utf8/decode.inc UTF8_SOURCE_HASH)
    if(NOT UTF8_SOURCE_HASH STREQUAL "5aafb54712b7c21db62bfdf966e5d8852200941643bde751150eb0d55a909524")
        message(FATAL_ERROR "Pinned ReactOS UTF-8 decoder differs")
    endif()
    file(SHA256 ${CMAKE_CURRENT_SOURCE_DIR}/upstream/reactos-utf8/encode.inc UTF8_ENCODER_HASH)
    if(NOT UTF8_ENCODER_HASH STREQUAL "834ed2a1a12a6ee3ad41a582a7024c130bf0694392951715940617bf85ab2b48")
        message(FATAL_ERROR "Pinned ReactOS UTF-8 encoder differs")
    endif()
    file(SHA256 ${CMAKE_CURRENT_SOURCE_DIR}/upstream/unicode/cp1252-decomposition.inc DECOMPOSITION_HASH)
    if(NOT DECOMPOSITION_HASH STREQUAL "dc36d1023c7fcd96043122aae2854b6f67febb7debfe4be8780aadbb5a9ba30b")
        message(FATAL_ERROR "Pinned CP1252 decompositions differ")
    endif()
    add_executable(launch_test nt/launch_test.cpp)
    target_link_libraries(launch_test PRIVATE raven_cpu)
    add_test(NAME native_launch_arguments_contract COMMAND launch_test)
    set_tests_properties(native_launch_arguments_contract PROPERTIES TIMEOUT 15)
    target_include_directories(raven_cpu PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/nls-generated)
    add_executable(nls_test nt/nls_test.cpp)
    target_link_libraries(nls_test PRIVATE raven_cpu)
    add_test(NAME native_ansi_code_page COMMAND nls_test ${PROJECT_SOURCE_DIR}/testdata/native_loader/cp1252_reference.bin)
    set_tests_properties(native_ansi_code_page PROPERTIES TIMEOUT 15)
    target_sources(raven_cpu PRIVATE desktop/brush.cpp desktop/bitblt.cpp)
    target_link_libraries(raven_cpu PUBLIC raven_pe raven_pixels)
    set(RAVEN_SKIA_SOURCE "" CACHE PATH "Pinned Skia source directory")
    set(RAVEN_SKIA_LIBRARY "" CACHE FILEPATH "Font-enabled CPU Skia library")
    set(RAVEN_FONT_DIRECTORY "" CACHE PATH "Qualified regular font directory")
    if(RAVEN_SKIA_SOURCE OR RAVEN_SKIA_LIBRARY OR RAVEN_FONT_DIRECTORY)
        if(NOT EXISTS "${RAVEN_SKIA_SOURCE}/include/core/SkFont.h" OR NOT EXISTS "${RAVEN_SKIA_LIBRARY}" OR NOT IS_DIRECTORY "${RAVEN_FONT_DIRECTORY}")
            message(FATAL_ERROR "Skia text requires source, CPU library and qualified font directory")
        endif()
        set(FONT_FILES LiberationSans-Regular.ttf LiberationMono-Regular.ttf LiberationSerif-Regular.ttf)
        set(FONT_HASHES bade59d822652f76e6941aa87b40a87c13d1cc70db98ededb5011127efafd1d3
            5883330d94debd992952cd8f0571b225f478c2d797d3f36c7521b0a5c9bde0f2
            9caef765d2e891c10dd73658894f01e660fe0c1c83e0bda7d6edf561d8f623d4)
        foreach(INDEX RANGE 0 2)
            list(GET FONT_FILES ${INDEX} FONT_FILE)
            list(GET FONT_HASHES ${INDEX} FONT_HASH)
            file(SHA256 "${RAVEN_FONT_DIRECTORY}/${FONT_FILE}" ACTUAL_FONT_HASH)
            if(NOT ACTUAL_FONT_HASH STREQUAL FONT_HASH)
                message(FATAL_ERROR "Qualified font checksum differs: ${FONT_FILE}")
            endif()
        endforeach()
        find_package(Freetype REQUIRED)
        find_package(Threads REQUIRED)
        add_library(raven_text STATIC graphics/text.cpp)
        target_include_directories(raven_text PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
        target_include_directories(raven_text SYSTEM PRIVATE ${RAVEN_SKIA_SOURCE})
        target_compile_definitions(raven_text PRIVATE SK_RELEASE)
        target_compile_options(raven_text PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
        target_link_libraries(raven_text PUBLIC ${RAVEN_SKIA_LIBRARY} Freetype::Freetype Threads::Threads ${CMAKE_DL_LIBS})
        target_sources(raven_cpu PRIVATE desktop/text.cpp)
        target_link_libraries(raven_cpu PUBLIC raven_text)
        target_compile_definitions(raven_cpu PUBLIC RAVEN_SKIA=1 PRIVATE RAVEN_FONT_DIRECTORY="${RAVEN_FONT_DIRECTORY}")
    endif()
    find_package(Vulkan QUIET)
    if(Vulkan_FOUND)
        # Commands that no hand-written handler covers are marshaled from the Khronos registry when it is installed.
        find_file(RAVEN_VK_XML vk.xml PATHS /usr/share/vulkan/registry /usr/local/share/vulkan/registry)
        find_file(RAVEN_VULKAN_CORE_HEADER vulkan/vulkan_core.h PATHS ${Vulkan_INCLUDE_DIRS} /usr/include)
        find_package(Python3 COMPONENTS Interpreter QUIET)
        set(VULKAN_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/vulkan-generated)
        if(RAVEN_VK_XML AND RAVEN_VULKAN_CORE_HEADER AND Python3_Interpreter_FOUND)
            add_custom_command(OUTPUT ${VULKAN_GENERATED_DIR}/vulkan_marshal_generated.inc ${VULKAN_GENERATED_DIR}/vulkan_handle_types.inc
                    ${VULKAN_GENERATED_DIR}/vulkan_generated_exports.def ${VULKAN_GENERATED_DIR}/vulkan_all_exports.def
                COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/generate-vulkan-marshal.py ${RAVEN_VK_XML}
                    ${PROJECT_SOURCE_DIR}/testdata/native_cpu/vulkan.def ${VULKAN_GENERATED_DIR} ${RAVEN_VULKAN_CORE_HEADER}
                DEPENDS ${PROJECT_SOURCE_DIR}/scripts/generate-vulkan-marshal.py ${RAVEN_VK_XML} ${PROJECT_SOURCE_DIR}/testdata/native_cpu/vulkan.def VERBATIM)
            add_custom_target(vulkan_marshal_generated DEPENDS ${VULKAN_GENERATED_DIR}/vulkan_marshal_generated.inc)
            set(VULKAN_GENERATED_SOURCES graphics/vulkan_marshal.cpp graphics/vulkan_generated.cpp)
        endif()
        target_sources(raven_cpu PRIVATE graphics/vulkan_bridge.cpp graphics/vulkan_resources.cpp graphics/vulkan_enumerate.cpp graphics/vulkan_queries.cpp)
        if(VULKAN_GENERATED_SOURCES)
            target_sources(raven_cpu PRIVATE ${VULKAN_GENERATED_SOURCES})
            target_include_directories(raven_cpu PRIVATE ${VULKAN_GENERATED_DIR})
            target_compile_definitions(raven_cpu PUBLIC RAVEN_VULKAN_GENERATED=1)
            add_dependencies(raven_cpu vulkan_marshal_generated)
        endif()
        target_link_libraries(raven_cpu PUBLIC Vulkan::Vulkan)
        target_compile_definitions(raven_cpu PUBLIC RAVEN_VULKAN=1)
    endif()
    target_compile_options(raven_cpu PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    target_link_libraries(raven PRIVATE raven_cpu)
    find_package(PkgConfig QUIET)
    target_sources(raven_cpu PRIVATE desktop/keyboard.cpp)
    target_sources(raven_cpu PRIVATE desktop/window_data.cpp)
    target_sources(raven_cpu PRIVATE desktop/clip.cpp)
    target_sources(raven_cpu PRIVATE desktop/pen.cpp desktop/caps.cpp desktop/load.cpp desktop/accelerator.cpp)
    target_sources(raven_cpu PRIVATE desktop/frame.cpp desktop/menu_loop.cpp)
    target_sources(raven_cpu PRIVATE desktop/class_info.cpp desktop/colors.cpp desktop/hierarchy.cpp desktop/menu.cpp desktop/menu_api.cpp desktop/extract.cpp graphics/icon_file.cpp nt/dependencies.cpp)
    target_sources(raven_cpu PRIVATE desktop/region.cpp)
    if(PkgConfig_FOUND)
        pkg_check_modules(XKBCOMMON QUIET IMPORTED_TARGET xkbcommon)
        pkg_check_modules(PIXMAN QUIET IMPORTED_TARGET pixman-1)
        if(PIXMAN_FOUND)
            target_link_libraries(raven_cpu PUBLIC PkgConfig::PIXMAN)
            target_compile_definitions(raven_cpu PRIVATE RAVEN_PIXMAN=1)
            add_executable(region_test desktop/region_test.cpp)
            target_link_libraries(region_test PRIVATE raven_cpu)
            add_test(NAME native_update_regions COMMAND region_test)
            set_tests_properties(native_update_regions PROPERTIES TIMEOUT 15)
        endif()
        if(XKBCOMMON_FOUND)
            target_link_libraries(raven_cpu PUBLIC PkgConfig::XKBCOMMON)
            target_compile_definitions(raven_cpu PRIVATE RAVEN_XKB=1)
            add_executable(keyboard_map_test desktop/keyboard_test.cpp)
            target_link_libraries(keyboard_map_test PRIVATE raven_cpu)
            add_test(NAME native_keyboard_layouts COMMAND keyboard_map_test)
            set_tests_properties(native_keyboard_layouts PROPERTIES TIMEOUT 15)
        endif()
        pkg_check_modules(WAYLAND_CLIENT QUIET IMPORTED_TARGET wayland-client)
        pkg_get_variable(WAYLAND_PROTOCOLS_DATA wayland-protocols pkgdatadir)
        find_program(WAYLAND_SCANNER wayland-scanner)
        if(WAYLAND_CLIENT_FOUND AND WAYLAND_SCANNER AND EXISTS "${WAYLAND_PROTOCOLS_DATA}/stable/xdg-shell/xdg-shell.xml")
            enable_language(C)
            set(XDG_PROTOCOL ${WAYLAND_PROTOCOLS_DATA}/stable/xdg-shell/xdg-shell.xml)
            add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xdg-shell-client-protocol.h
                COMMAND ${WAYLAND_SCANNER} client-header ${XDG_PROTOCOL} ${CMAKE_CURRENT_BINARY_DIR}/xdg-shell-client-protocol.h
                DEPENDS ${XDG_PROTOCOL} VERBATIM)
            add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xdg-shell-protocol.c
                COMMAND ${WAYLAND_SCANNER} private-code ${XDG_PROTOCOL} ${CMAKE_CURRENT_BINARY_DIR}/xdg-shell-protocol.c
                DEPENDS ${XDG_PROTOCOL} VERBATIM)
            add_library(raven_wayland STATIC desktop/wayland.cpp
                ${CMAKE_CURRENT_BINARY_DIR}/xdg-shell-client-protocol.h ${CMAKE_CURRENT_BINARY_DIR}/xdg-shell-protocol.c)
            target_include_directories(raven_wayland PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
            target_link_libraries(raven_wayland PUBLIC PkgConfig::WAYLAND_CLIENT)
            target_compile_options(raven_wayland PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
            target_link_libraries(raven PRIVATE raven_wayland)
            target_compile_definitions(raven PRIVATE RAVEN_WAYLAND=1)
        endif()
    endif()
    target_compile_definitions(raven PRIVATE RAVEN_NATIVE_CPU=1)
    add_dependencies(raven raven-bootstrap)
    add_executable(native_cpu_test cpu/native_cpu_test.cpp)
    target_link_libraries(native_cpu_test PRIVATE raven_cpu)
    add_dependencies(native_cpu_test raven-bootstrap)
    add_test(NAME native_cpu_contracts COMMAND native_cpu_test $<TARGET_FILE:raven-bootstrap>)
    add_executable(native_x86_test cpu/native_x86_test.cpp)
    target_link_libraries(native_x86_test PRIVATE raven_cpu)
    add_dependencies(native_x86_test raven-bootstrap)
    add_test(NAME native_x86_contracts COMMAND native_x86_test $<TARGET_FILE:raven-bootstrap>)
    set_tests_properties(native_x86_contracts PROPERTIES TIMEOUT 30)
    set_tests_properties(native_cpu_contracts PROPERTIES TIMEOUT 15)
    add_executable(providers_test nt/providers_test.cpp)
    target_link_libraries(providers_test PRIVATE raven_cpu)
    add_dependencies(providers_test raven-bootstrap)
    add_test(NAME native_provider_contract COMMAND providers_test $<TARGET_FILE:raven-bootstrap>)
    set_tests_properties(native_provider_contract PROPERTIES TIMEOUT 15)
    add_executable(font_test desktop/font_test.cpp)
    target_link_libraries(font_test PRIVATE raven_cpu)
    add_test(NAME native_font_ownership COMMAND font_test)
    set_tests_properties(native_font_ownership PROPERTIES TIMEOUT 15)
    add_executable(compatible_bitmap_test desktop/compatible_bitmap_test.cpp)
    target_link_libraries(compatible_bitmap_test PRIVATE raven_cpu)
    add_dependencies(compatible_bitmap_test raven-bootstrap)
    add_test(NAME native_compatible_bitmap_contract COMMAND compatible_bitmap_test $<TARGET_FILE:raven-bootstrap>)
    set_tests_properties(native_compatible_bitmap_contract PROPERTIES TIMEOUT 15)
    add_executable(bitblt_test desktop/bitblt_test.cpp)
    target_link_libraries(bitblt_test PRIVATE raven_cpu)
    add_dependencies(bitblt_test raven-bootstrap)
    add_test(NAME native_bitblt_contract COMMAND bitblt_test $<TARGET_FILE:raven-bootstrap>)
    set_tests_properties(native_bitblt_contract PROPERTIES TIMEOUT 15)
    add_executable(brush_test desktop/brush_test.cpp)
    add_executable(window_data_test desktop/window_data_test.cpp)
    add_executable(class_info_test desktop/class_info_test.cpp)
    target_link_libraries(class_info_test PRIVATE raven_cpu)
    add_test(NAME native_class_info_ownership COMMAND class_info_test)
    set_tests_properties(native_class_info_ownership PROPERTIES TIMEOUT 15)
    target_link_libraries(window_data_test PRIVATE raven_cpu)
    add_test(NAME native_window_data_ownership COMMAND window_data_test)
    set_tests_properties(native_window_data_ownership PROPERTIES TIMEOUT 15)
    target_link_libraries(brush_test PRIVATE raven_cpu)
    add_test(NAME native_brush_ownership COMMAND brush_test)
    set_tests_properties(native_brush_ownership PROPERTIES TIMEOUT 15)
    add_executable(exceptions_test nt/exceptions_test.cpp)
    target_link_libraries(exceptions_test PRIVATE raven_cpu)
    add_dependencies(exceptions_test raven-bootstrap)
    add_test(NAME native_exception_contract COMMAND exceptions_test $<TARGET_FILE:raven-bootstrap>)
    set_tests_properties(native_exception_contract PROPERTIES TIMEOUT 15)
    add_executable(memory_test nt/memory_test.cpp)
    target_link_libraries(memory_test PRIVATE raven_cpu)
    add_dependencies(memory_test raven-bootstrap)
    add_test(NAME native_memory_contract COMMAND memory_test $<TARGET_FILE:raven-bootstrap>)
    set_tests_properties(native_memory_contract PROPERTIES TIMEOUT 15)
    add_executable(objects_test nt/objects_test.cpp)
    target_link_libraries(objects_test PRIVATE raven_cpu)
    add_dependencies(objects_test raven-bootstrap)
    add_test(NAME native_object_contract COMMAND objects_test $<TARGET_FILE:raven-bootstrap>)
    set_tests_properties(native_object_contract PROPERTIES TIMEOUT 15)

    find_program(RAVEN_MINGW64 x86_64-w64-mingw32-gcc)
    find_program(RAVEN_WINDRES x86_64-w64-mingw32-windres)
    if(RAVEN_MINGW64)
        set(MULTIBYTE_CLIENT ${CMAKE_CURRENT_BINARY_DIR}/multibyte-client.exe)
        set(MULTIBYTE_BOUNDARY ${CMAKE_CURRENT_BINARY_DIR}/multibyte-boundary.exe)
        add_custom_command(OUTPUT ${MULTIBYTE_CLIENT} ${MULTIBYTE_BOUNDARY}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -fno-builtin
                -Wl,--entry,raven_entry,--image-base,0x1c6000000,--no-insert-timestamp
                -o ${MULTIBYTE_CLIENT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/multibyte_client.c -lkernel32
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -fno-builtin -DCONVERSION_BOUNDARY
                -Wl,--entry,raven_entry,--image-base,0x1c6000000,--no-insert-timestamp
                -o ${MULTIBYTE_BOUNDARY} ${PROJECT_SOURCE_DIR}/testdata/native_loader/multibyte_client.c -lkernel32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/multibyte_client.c ${PROJECT_SOURCE_DIR}/testdata/native_loader/multibyte_reference.h VERBATIM)
        add_custom_target(multibyte_pe_fixtures ALL DEPENDS ${MULTIBYTE_CLIENT} ${MULTIBYTE_BOUNDARY})
        add_executable(multibyte_test nt/multibyte_test.cpp)
        target_link_libraries(multibyte_test PRIVATE raven_cpu)
        add_dependencies(multibyte_test multibyte_pe_fixtures raven-bootstrap)
        add_test(NAME native_multibyte_contract COMMAND multibyte_test $<TARGET_FILE:raven-bootstrap> ${MULTIBYTE_CLIENT})
        add_test(NAME native_multibyte_cli COMMAND raven --run-process --execution=native ${MULTIBYTE_CLIENT})
        add_test(NAME native_multibyte_boundary COMMAND raven --run-process --execution=native ${MULTIBYTE_BOUNDARY})
        set_tests_properties(native_multibyte_contract PROPERTIES TIMEOUT 30)
        set_tests_properties(native_multibyte_cli native_multibyte_boundary PROPERTIES TIMEOUT 30 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
    endif()
    if(RAVEN_MINGW64 AND PIXMAN_FOUND)
        set(PEN_CLIENT ${CMAKE_CURRENT_BINARY_DIR}/pen-client.exe)
        add_custom_command(OUTPUT ${PEN_CLIENT}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -fno-builtin
                -Wl,--entry,raven_entry,--image-base,0x1d5000000,--no-insert-timestamp
                -o ${PEN_CLIENT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/pen_client.c -luser32 -lgdi32 -lkernel32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/pen_client.c ${PROJECT_SOURCE_DIR}/testdata/native_loader/pen_reference.h VERBATIM)
        add_custom_target(pen_pe_fixture ALL DEPENDS ${PEN_CLIENT})
        add_executable(drawing_test desktop/drawing_test.cpp)
        target_link_libraries(drawing_test PRIVATE raven_cpu)
        add_dependencies(drawing_test pen_pe_fixture raven-bootstrap)
        add_test(NAME native_pen_drawing COMMAND drawing_test $<TARGET_FILE:raven-bootstrap> ${PEN_CLIENT} --pen)
        add_test(NAME native_pen_drawing_cli COMMAND raven --run-process --execution=native --timeout-ms=30000 ${PEN_CLIENT})
        set_tests_properties(native_pen_drawing native_pen_drawing_cli PROPERTIES TIMEOUT 40)
        set_tests_properties(native_pen_drawing_cli PROPERTIES PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        if(TARGET raven_text)
            set(TEXT_OUTPUT_CLIENT ${CMAKE_CURRENT_BINARY_DIR}/text-output-client.exe)
            add_custom_command(OUTPUT ${TEXT_OUTPUT_CLIENT}
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -fno-builtin
                    -Wl,--entry,raven_entry,--image-base,0x1d6000000,--no-insert-timestamp
                    -o ${TEXT_OUTPUT_CLIENT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/text_output_client.c -luser32 -lgdi32 -lkernel32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/text_output_client.c ${PROJECT_SOURCE_DIR}/testdata/native_loader/text_output_reference.h VERBATIM)
            add_custom_target(text_output_pe_fixture ALL DEPENDS ${TEXT_OUTPUT_CLIENT})
            add_dependencies(drawing_test text_output_pe_fixture)
            add_test(NAME native_text_output COMMAND drawing_test $<TARGET_FILE:raven-bootstrap> ${TEXT_OUTPUT_CLIENT} --text)
            add_test(NAME native_text_output_cli COMMAND raven --run-process --execution=native --timeout-ms=30000 ${TEXT_OUTPUT_CLIENT})
            set_tests_properties(native_text_output native_text_output_cli PROPERTIES TIMEOUT 40)
            set_tests_properties(native_text_output_cli PROPERTIES PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
            set(RAVEN_TEXT_COMPONENT_PATH "" CACHE FILEPATH "Selected guest layout component built by scripts/provision-text.py")
            if(RAVEN_TEXT_COMPONENT_PATH)
                get_filename_component(TEXT_COMPONENT_DIR "${RAVEN_TEXT_COMPONENT_PATH}" DIRECTORY)
                if(NOT EXISTS "${RAVEN_TEXT_COMPONENT_PATH}" OR NOT EXISTS "${TEXT_COMPONENT_DIR}/raven-text.a")
                    message(FATAL_ERROR "Selected guest layout component or import library is missing")
                endif()
                foreach(CLIENT IN ITEMS layout layout_failure layout_alignment)
                    set(CLIENT_SOURCE ${PROJECT_SOURCE_DIR}/testdata/native_loader/${CLIENT}_client.c)
                    set(CLIENT_EXE ${CMAKE_CURRENT_BINARY_DIR}/${CLIENT}-client.exe)
                    add_custom_command(OUTPUT ${CLIENT_EXE}
                        COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -fno-builtin
                            -Wl,--entry,raven_entry,--image-base,0x1d9000000,--no-insert-timestamp
                            -o ${CLIENT_EXE} ${CLIENT_SOURCE} ${TEXT_COMPONENT_DIR}/raven-text.a -luser32 -lgdi32 -lkernel32
                        DEPENDS ${CLIENT_SOURCE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/layout_reference.h
                            ${PROJECT_SOURCE_DIR}/testdata/native_loader/layout_alignment_reference.h
                            ${RAVEN_TEXT_COMPONENT_PATH} ${TEXT_COMPONENT_DIR}/raven-text.a VERBATIM)
                    add_custom_target(${CLIENT}_pe_fixture ALL DEPENDS ${CLIENT_EXE})
                    add_test(NAME native_${CLIENT}_component COMMAND raven --run-process --execution=native
                        --timeout-ms=30000 ${CLIENT_EXE} ${RAVEN_TEXT_COMPONENT_PATH})
                    set_tests_properties(native_${CLIENT}_component PROPERTIES TIMEOUT 40 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
                endforeach()
            endif()
        endif()
        set(CLIP_CLIENT ${CMAKE_CURRENT_BINARY_DIR}/clip-client.exe)
        set(CLIP_PAINT_CLIENT ${CMAKE_CURRENT_BINARY_DIR}/clip-paint-client.exe)
        add_custom_command(OUTPUT ${CLIP_PAINT_CLIENT}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -fno-builtin
                -Wl,--entry,raven_entry,--image-base,0x1d1000000,--no-insert-timestamp
                -o ${CLIP_PAINT_CLIENT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/clip_paint_client.c -luser32 -lgdi32 -lkernel32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/clip_paint_client.c VERBATIM)
        add_custom_command(OUTPUT ${CLIP_CLIENT}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -fno-builtin
                -Wl,--entry,raven_entry,--image-base,0x1d0000000,--no-insert-timestamp
                -o ${CLIP_CLIENT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/clip_client.c -luser32 -lgdi32 -lkernel32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/clip_client.c VERBATIM)
        add_custom_target(clip_pe_fixtures ALL DEPENDS ${CLIP_CLIENT} ${CLIP_PAINT_CLIENT})
        add_executable(clip_test desktop/clip_test.cpp)
        target_link_libraries(clip_test PRIVATE raven_cpu)
        add_dependencies(clip_test clip_pe_fixtures raven-bootstrap)
        add_test(NAME native_clipping COMMAND clip_test $<TARGET_FILE:raven-bootstrap> ${CLIP_CLIENT})
        add_test(NAME native_clipping_cli COMMAND raven --run-process --execution=native ${CLIP_CLIENT})
        add_test(NAME native_control_clip_paint COMMAND clip_test $<TARGET_FILE:raven-bootstrap> ${CLIP_PAINT_CLIENT} --paint)
        set_tests_properties(native_clipping native_clipping_cli native_control_clip_paint PROPERTIES TIMEOUT 30)
        set_tests_properties(native_clipping_cli PROPERTIES PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
    endif()
    if(RAVEN_MINGW64)
        set(WINDOW_TEXT_CLIENT ${CMAKE_CURRENT_BINARY_DIR}/window-text-client.exe)
        add_custom_command(OUTPUT ${WINDOW_TEXT_CLIENT}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -fno-builtin
                -Wl,--entry,raven_entry,--image-base,0x1cf000000,--no-insert-timestamp
                -o ${WINDOW_TEXT_CLIENT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/window_text_client.c -luser32 -lkernel32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/window_text_client.c VERBATIM)
        add_custom_target(window_text_pe_fixtures ALL DEPENDS ${WINDOW_TEXT_CLIENT})
        add_executable(window_text_test desktop/window_text_test.cpp)
        target_link_libraries(window_text_test PRIVATE raven_cpu)
        add_dependencies(window_text_test window_text_pe_fixtures raven-bootstrap)
        add_test(NAME native_window_text COMMAND window_text_test $<TARGET_FILE:raven-bootstrap> ${WINDOW_TEXT_CLIENT})
        add_test(NAME native_window_text_cli COMMAND raven --run-process --execution=native ${WINDOW_TEXT_CLIENT})
        set_tests_properties(native_window_text native_window_text_cli PROPERTIES TIMEOUT 30)
        set_tests_properties(native_window_text_cli PROPERTIES PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(COLOR_CLIENT ${CMAKE_CURRENT_BINARY_DIR}/color-client.exe)
        add_custom_command(OUTPUT ${COLOR_CLIENT}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -fno-builtin
                -Wl,--entry,raven_entry,--image-base,0x1cc000000,--no-insert-timestamp
                -o ${COLOR_CLIENT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/color_client.c -luser32 -lgdi32 -lkernel32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/color_client.c ${PROJECT_SOURCE_DIR}/testdata/native_loader/color_reference.h VERBATIM)
        add_custom_target(color_pe_fixtures ALL DEPENDS ${COLOR_CLIENT})
        add_executable(colors_test desktop/colors_test.cpp)
        target_link_libraries(colors_test PRIVATE raven_cpu)
        add_dependencies(colors_test color_pe_fixtures raven-bootstrap)
        add_test(NAME native_system_colors COMMAND colors_test $<TARGET_FILE:raven-bootstrap> ${COLOR_CLIENT})
        add_test(NAME native_system_colors_cli COMMAND raven --run-process --execution=native ${COLOR_CLIENT})
        set_tests_properties(native_system_colors native_system_colors_cli PROPERTIES TIMEOUT 30)
        set_tests_properties(native_system_colors_cli PROPERTIES PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
    endif()
    if(RAVEN_MINGW64 AND TARGET raven_text)
        set(CHILD_CLIENT ${CMAKE_CURRENT_BINARY_DIR}/child-client.exe)
        set(CHILD_INPUT ${CMAKE_CURRENT_BINARY_DIR}/child-input.exe)
        add_custom_command(OUTPUT ${CHILD_CLIENT} ${CHILD_INPUT}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -fno-builtin
                -Wl,--entry,raven_entry,--image-base,0x1ca000000,--no-insert-timestamp
                -o ${CHILD_CLIENT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/child_client.c -luser32 -lgdi32 -lkernel32
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -fno-builtin -DCHILD_INPUT
                -Wl,--entry,raven_entry,--image-base,0x1ca000000,--no-insert-timestamp
                -o ${CHILD_INPUT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/child_client.c -luser32 -lgdi32 -lkernel32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/child_client.c ${PROJECT_SOURCE_DIR}/testdata/native_loader/child_reference.h VERBATIM)
        set(CHILD_REJECT ${CMAKE_CURRENT_BINARY_DIR}/child-reject.exe)
        add_custom_command(OUTPUT ${CHILD_REJECT}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -fno-builtin
                -Wl,--entry,raven_entry,--image-base,0x1cb000000,--no-insert-timestamp
                -o ${CHILD_REJECT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/child_reject.c -luser32 -lkernel32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/child_reject.c VERBATIM)
        add_custom_target(child_pe_fixtures ALL DEPENDS ${CHILD_CLIENT} ${CHILD_INPUT} ${CHILD_REJECT})
        add_executable(child_test desktop/child_test.cpp)
        target_link_libraries(child_test PRIVATE raven_cpu)
        add_dependencies(child_test child_pe_fixtures raven-bootstrap)
        add_test(NAME native_child_windows COMMAND child_test $<TARGET_FILE:raven-bootstrap> ${CHILD_CLIENT})
        add_test(NAME native_child_input COMMAND child_test $<TARGET_FILE:raven-bootstrap> ${CHILD_INPUT} --input)
        add_test(NAME native_child_rejection COMMAND child_test $<TARGET_FILE:raven-bootstrap> ${CHILD_REJECT} --reject)
        set_tests_properties(native_child_windows native_child_input native_child_rejection PROPERTIES TIMEOUT 30)
    endif()
    if(RAVEN_MINGW64 AND RAVEN_WINDRES AND PNG_FOUND)
        set(EXTRACT_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/extract-fixtures)
        file(MAKE_DIRECTORY ${EXTRACT_FIXTURES})
        file(WRITE ${EXTRACT_FIXTURES}/empty.bin "")
        file(WRITE ${EXTRACT_FIXTURES}/not-icon.txt "Not an icon file.\n")
        add_custom_command(OUTPUT ${EXTRACT_FIXTURES}/client.exe ${EXTRACT_FIXTURES}/icons.ico
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -fno-builtin
                -Wl,--entry,raven_entry,--image-base,0x1c7000000,--no-insert-timestamp
                -o ${EXTRACT_FIXTURES}/client.exe ${PROJECT_SOURCE_DIR}/testdata/native_loader/extract_client.c -luser32 -lgdi32 -lkernel32
            COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_resources.ico ${EXTRACT_FIXTURES}/icons.ico
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/extract_client.c ${PROJECT_SOURCE_DIR}/testdata/native_loader/extract_reference.h ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_resources.ico VERBATIM)
        add_custom_target(extract_pe_fixtures ALL DEPENDS ${EXTRACT_FIXTURES}/client.exe ${EXTRACT_FIXTURES}/icons.ico)
        add_executable(extract_test desktop/extract_test.cpp)
        target_link_libraries(extract_test PRIVATE raven_cpu)
        add_dependencies(extract_test extract_pe_fixtures desktop_pe_fixtures raven-bootstrap)
        add_test(NAME native_extract_icons_contract COMMAND extract_test $<TARGET_FILE:raven-bootstrap>
            ${EXTRACT_FIXTURES}/client.exe ${CMAKE_CURRENT_BINARY_DIR}/desktop-fixtures/icons.dll ${EXTRACT_FIXTURES}/icons.ico)
        set_tests_properties(native_extract_icons_contract PROPERTIES TIMEOUT 30)
    endif()
    if(RAVEN_MINGW64 AND RAVEN_WINDRES)
        set(MENU_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/menu-fixtures)
        add_custom_command(OUTPUT ${MENU_FIXTURES}/client.exe ${MENU_FIXTURES}/boundary.exe ${MENU_FIXTURES}/menus.dll
            COMMAND ${CMAKE_COMMAND} -E make_directory ${MENU_FIXTURES}
            COMMAND ${RAVEN_WINDRES} ${PROJECT_SOURCE_DIR}/testdata/native_loader/menu_resources.rc ${MENU_FIXTURES}/resources.o
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                -Wl,--entry,0,--image-base,0x1c2000000,--no-insert-timestamp
                -o ${MENU_FIXTURES}/menus.dll ${MENU_FIXTURES}/resources.o
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x1c3000000,--no-insert-timestamp
                -o ${MENU_FIXTURES}/client.exe ${PROJECT_SOURCE_DIR}/testdata/native_loader/menu_client.c -lkernel32 -luser32
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -DMENU_BOUNDARY
                -Wl,--entry,raven_entry,--image-base,0x1c3000000,--no-insert-timestamp
                -o ${MENU_FIXTURES}/boundary.exe ${PROJECT_SOURCE_DIR}/testdata/native_loader/menu_client.c -lkernel32 -luser32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/menu_client.c ${PROJECT_SOURCE_DIR}/testdata/native_loader/menu_resources.rc VERBATIM)
        add_custom_target(menu_pe_fixtures ALL DEPENDS ${MENU_FIXTURES}/client.exe ${MENU_FIXTURES}/boundary.exe ${MENU_FIXTURES}/menus.dll)
        add_executable(menu_test desktop/menu_test.cpp)
        target_link_libraries(menu_test PRIVATE raven_cpu)
        add_dependencies(menu_test menu_pe_fixtures)
        add_test(NAME native_menu_ownership COMMAND menu_test ${MENU_FIXTURES}/menus.dll)
        add_test(NAME native_menu_cli COMMAND raven --run-process --execution=native ${MENU_FIXTURES}/client.exe)
        add_test(NAME native_menu_boundary COMMAND raven --run-process --execution=native ${MENU_FIXTURES}/boundary.exe)
        set_tests_properties(native_menu_ownership PROPERTIES TIMEOUT 15)
        set_tests_properties(native_menu_cli native_menu_boundary PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
    endif()
    if(RAVEN_MINGW64)
        set(CLASS_MODULE ${CMAKE_CURRENT_BINARY_DIR}/class-module.dll)
        add_custom_command(OUTPUT ${CLASS_MODULE}
            COMMAND ${RAVEN_MINGW64} -shared -nostdlib -fno-stack-protector
                -Wl,--entry,DllMain,--image-base,0x1be000000,--no-insert-timestamp
                -o ${CLASS_MODULE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/class_module.c -lkernel32 -luser32 -lgdi32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/class_module.c VERBATIM)
        add_custom_target(class_module_fixture ALL DEPENDS ${CLASS_MODULE})
        foreach(CLASS_INFO_VARIANT IN ITEMS positive boundary)
            set(CLASS_INFO ${CMAKE_CURRENT_BINARY_DIR}/class-info-${CLASS_INFO_VARIANT}.exe)
            set(CLASS_INFO_OPTIONS)
            if(CLASS_INFO_VARIANT STREQUAL boundary)
                set(CLASS_INFO_OPTIONS -DRAVEN_CLASS_INFO_BOUNDARY)
            endif()
            add_custom_command(OUTPUT ${CLASS_INFO}
                COMMAND ${RAVEN_MINGW64} -nostdlib -fno-stack-protector ${CLASS_INFO_OPTIONS}
                    -Wl,--entry,raven_entry,--image-base,0x1bc000000,--no-insert-timestamp
                    -o ${CLASS_INFO} ${PROJECT_SOURCE_DIR}/testdata/native_loader/class_info_client.c -lkernel32 -luser32 -lgdi32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/class_info_client.c VERBATIM)
            add_custom_target(class_info_${CLASS_INFO_VARIANT} ALL DEPENDS ${CLASS_INFO} ${CLASS_MODULE})
            add_test(NAME native_class_info_${CLASS_INFO_VARIANT} COMMAND raven --run-process --execution=native ${CLASS_INFO})
            set_tests_properties(native_class_info_${CLASS_INFO_VARIANT} PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        endforeach()
        foreach(WINDOW_DATA_VARIANT IN ITEMS positive boundary)
            set(WINDOW_DATA ${CMAKE_CURRENT_BINARY_DIR}/window-data-${WINDOW_DATA_VARIANT}.exe)
            set(WINDOW_DATA_OPTIONS)
            if(WINDOW_DATA_VARIANT STREQUAL boundary)
                set(WINDOW_DATA_OPTIONS -DRAVEN_WINDOW_DATA_BOUNDARY)
            endif()
            add_custom_command(OUTPUT ${WINDOW_DATA}
                COMMAND ${RAVEN_MINGW64} -nostdlib -fno-stack-protector ${WINDOW_DATA_OPTIONS}
                    -Wl,--entry,raven_entry,--image-base,0x1ba000000,--no-insert-timestamp
                    -o ${WINDOW_DATA} ${PROJECT_SOURCE_DIR}/testdata/native_loader/window_data_client.c -lkernel32 -luser32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/window_data_client.c VERBATIM)
            add_custom_target(window_data_${WINDOW_DATA_VARIANT} ALL DEPENDS ${WINDOW_DATA})
            add_test(NAME native_window_data_${WINDOW_DATA_VARIANT} COMMAND raven --run-process --execution=native ${WINDOW_DATA})
            set_tests_properties(native_window_data_${WINDOW_DATA_VARIANT} PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        endforeach()
        set(CLASS_BACKGROUND ${CMAKE_CURRENT_BINARY_DIR}/class-background.exe)
        add_custom_command(OUTPUT ${CLASS_BACKGROUND}
            COMMAND ${RAVEN_MINGW64} -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x1b8000000,--no-insert-timestamp
                -o ${CLASS_BACKGROUND} ${PROJECT_SOURCE_DIR}/testdata/native_loader/class_background_client.c -lkernel32 -luser32 -lgdi32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/class_background_client.c VERBATIM)
        add_custom_target(class_background_fixture ALL DEPENDS ${CLASS_BACKGROUND})
        add_executable(class_background_test desktop/class_background_test.cpp)
        target_link_libraries(class_background_test PRIVATE raven_cpu)
        add_dependencies(class_background_test class_background_fixture raven-bootstrap)
        add_test(NAME native_class_background COMMAND class_background_test $<TARGET_FILE:raven-bootstrap> ${CLASS_BACKGROUND} ${CMAKE_CURRENT_BINARY_DIR}/class-background.bgra)
        set_tests_properties(native_class_background PROPERTIES TIMEOUT 20)
        set(CLASS_BACKGROUND_BOUNDARY ${CMAKE_CURRENT_BINARY_DIR}/class-background-boundary.exe)
        add_custom_command(OUTPUT ${CLASS_BACKGROUND_BOUNDARY}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -DRAVEN_CLASS_BACKGROUND_BOUNDARY
                -Wl,--entry,raven_entry,--image-base,0x1b8000000,--no-insert-timestamp
                -o ${CLASS_BACKGROUND_BOUNDARY} ${PROJECT_SOURCE_DIR}/testdata/native_loader/class_background_client.c -lkernel32 -luser32 -lgdi32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/class_background_client.c VERBATIM)
        add_custom_target(class_background_boundary ALL DEPENDS ${CLASS_BACKGROUND_BOUNDARY})
        add_test(NAME native_class_background_boundary COMMAND raven --run-process --execution=native ${CLASS_BACKGROUND_BOUNDARY})
        set_tests_properties(native_class_background_boundary PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(EXIT_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/exit-fixtures)
        file(MAKE_DIRECTORY ${EXIT_FIXTURES})
        set(EXIT_OUTPUTS "")
        foreach(EXIT_DLL_CASE basic attach tls repeat fault)
            set(EXIT_DLL_DEFINE "")
            if(NOT EXIT_DLL_CASE STREQUAL "basic")
                string(TOUPPER "${EXIT_DLL_CASE}" EXIT_DLL_MODE)
                set(EXIT_DLL_DEFINE -DRAVEN_EXIT_${EXIT_DLL_MODE})
            endif()
            add_custom_command(OUTPUT ${EXIT_FIXTURES}/exit-${EXIT_DLL_CASE}.dll
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector ${EXIT_DLL_DEFINE}
                    -Wl,--entry,DllMain,--image-base,0x1cf000000,--no-insert-timestamp
                    -o ${EXIT_FIXTURES}/exit-${EXIT_DLL_CASE}.dll ${PROJECT_SOURCE_DIR}/testdata/native_loader/exit_module.c -lkernel32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/exit_module.c VERBATIM)
            list(APPEND EXIT_OUTPUTS ${EXIT_FIXTURES}/exit-${EXIT_DLL_CASE}.dll)
        endforeach()
        foreach(EXIT_MODE RANGE 0 8)
            add_custom_command(OUTPUT ${EXIT_FIXTURES}/exit-${EXIT_MODE}.exe
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -DRAVEN_EXIT_MODE=${EXIT_MODE}
                    -Wl,--entry,raven_entry,--image-base,0x1ce000000,--no-insert-timestamp
                    -o ${EXIT_FIXTURES}/exit-${EXIT_MODE}.exe ${PROJECT_SOURCE_DIR}/testdata/native_loader/exit_client.c -lkernel32 -luser32 -lgdi32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/exit_client.c VERBATIM)
            list(APPEND EXIT_OUTPUTS ${EXIT_FIXTURES}/exit-${EXIT_MODE}.exe)
        endforeach()
        add_custom_target(exit_fixtures ALL DEPENDS ${EXIT_OUTPUTS})
        add_executable(exit_test nt/exit_test.cpp)
        target_link_libraries(exit_test PRIVATE raven_cpu)
        add_dependencies(exit_test exit_fixtures raven-bootstrap)
        add_test(NAME native_process_exit COMMAND exit_test $<TARGET_FILE:raven-bootstrap> ${EXIT_FIXTURES})
        set_tests_properties(native_process_exit PROPERTIES TIMEOUT 30)
        set(TLS_ORDER_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/tls-order-fixtures)
        file(MAKE_DIRECTORY ${TLS_ORDER_FIXTURES})
        add_custom_command(OUTPUT ${TLS_ORDER_FIXTURES}/tls-order.dll
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                -Wl,--entry,DllMain,--image-base,0x1bd000000,--no-insert-timestamp
                -o ${TLS_ORDER_FIXTURES}/tls-order.dll ${PROJECT_SOURCE_DIR}/testdata/native_loader/tls_order_module.c -lkernel32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/tls_order_module.c VERBATIM)
        foreach(TLS_ORDER_CASE unload shutdown)
            set(TLS_ORDER_DEFINE "")
            if(TLS_ORDER_CASE STREQUAL "shutdown")
                set(TLS_ORDER_DEFINE -DRAVEN_TLS_ORDER_SHUTDOWN)
            endif()
            add_custom_command(OUTPUT ${TLS_ORDER_FIXTURES}/${TLS_ORDER_CASE}.exe
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector ${TLS_ORDER_DEFINE}
                    -Wl,--entry,raven_entry,--image-base,0x1bc000000,--no-insert-timestamp
                    -o ${TLS_ORDER_FIXTURES}/${TLS_ORDER_CASE}.exe ${PROJECT_SOURCE_DIR}/testdata/native_loader/tls_order_client.c -lkernel32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/tls_order_client.c VERBATIM)
        endforeach()
        add_custom_target(tls_order_fixtures ALL DEPENDS ${TLS_ORDER_FIXTURES}/tls-order.dll ${TLS_ORDER_FIXTURES}/unload.exe ${TLS_ORDER_FIXTURES}/shutdown.exe)
        add_executable(tls_order_test nt/tls_order_test.cpp)
        target_link_libraries(tls_order_test PRIVATE raven_cpu)
        add_dependencies(tls_order_test tls_order_fixtures raven-bootstrap)
        add_test(NAME native_tls_detach_order COMMAND tls_order_test $<TARGET_FILE:raven-bootstrap> ${TLS_ORDER_FIXTURES})
        set_tests_properties(native_tls_detach_order PROPERTIES TIMEOUT 15)
        set(COMPATIBLE_BITMAP_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/compatible-bitmap.exe)
        add_custom_command(OUTPUT ${COMPATIBLE_BITMAP_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x1ba000000,--no-insert-timestamp
                -o ${COMPATIBLE_BITMAP_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/compatible_bitmap_client.c -lgdi32 -lkernel32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/compatible_bitmap_client.c VERBATIM)
        add_custom_target(compatible_bitmap_fixture ALL DEPENDS ${COMPATIBLE_BITMAP_FIXTURE})
        add_test(NAME native_compatible_bitmap_cli COMMAND raven --run-process --execution=native ${COMPATIBLE_BITMAP_FIXTURE})
        set_tests_properties(native_compatible_bitmap_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(BITBLT_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/bitblt-fixture.exe)
        add_custom_command(OUTPUT ${BITBLT_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x1b8000000,--no-insert-timestamp
                -o ${BITBLT_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/bitblt_client.c -lgdi32 -lkernel32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/bitblt_client.c VERBATIM)
        add_custom_target(bitblt_pe_fixture ALL DEPENDS ${BITBLT_FIXTURE})
        add_test(NAME native_bitblt_cli COMMAND raven --run-process --execution=native ${BITBLT_FIXTURE})
        set_tests_properties(native_bitblt_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(BRUSH_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/brush-fixture.exe)
        add_custom_command(OUTPUT ${BRUSH_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x1b6000000,--no-insert-timestamp
                -o ${BRUSH_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/brush_client.c -lgdi32 -luser32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/brush_client.c VERBATIM)
        add_custom_target(brush_pe_fixture ALL DEPENDS ${BRUSH_FIXTURE})
        add_test(NAME native_brush_cli COMMAND raven --run-process --execution=native ${BRUSH_FIXTURE})
        set_tests_properties(native_brush_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        if(TARGET raven_text)
            set(TEXT_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/text-fixture.exe)
            add_custom_command(OUTPUT ${TEXT_FIXTURE}
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                    -Wl,--entry,raven_entry,--image-base,0x1b0000000,--no-insert-timestamp
                    -o ${TEXT_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/text_client.c -lgdi32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/text_client.c ${PROJECT_SOURCE_DIR}/testdata/native_loader/text_reference.h VERBATIM)
            add_custom_target(text_pe_fixture ALL DEPENDS ${TEXT_FIXTURE})
            set(TEXT_BOUNDARY ${CMAKE_CURRENT_BINARY_DIR}/text-boundary.exe)
            add_custom_command(OUTPUT ${TEXT_BOUNDARY}
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -DRAVEN_TEXT_BOUNDARY
                    -Wl,--entry,raven_entry,--image-base,0x1b0000000,--no-insert-timestamp
                    -o ${TEXT_BOUNDARY} ${PROJECT_SOURCE_DIR}/testdata/native_loader/text_client.c -lgdi32 -lkernel32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/text_client.c ${PROJECT_SOURCE_DIR}/testdata/native_loader/text_reference.h VERBATIM)
            add_custom_target(text_boundary_fixture ALL DEPENDS ${TEXT_BOUNDARY})
            add_test(NAME native_text_boundary COMMAND raven --run-process --execution=native --timeout-ms=30000 ${TEXT_BOUNDARY})
            set_tests_properties(native_text_boundary PROPERTIES TIMEOUT 40 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
            # The fallback faces are optional host fonts, so the test only exists where both are installed.
            if(EXISTS /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf AND EXISTS /usr/local/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc)
                set(TEXT_FALLBACK ${CMAKE_CURRENT_BINARY_DIR}/text-fallback.exe)
                add_custom_command(OUTPUT ${TEXT_FALLBACK}
                    COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                        -Wl,--entry,raven_entry,--image-base,0x1db000000,--no-insert-timestamp
                        -o ${TEXT_FALLBACK} ${PROJECT_SOURCE_DIR}/testdata/native_loader/text_fallback_client.c -lgdi32 -lkernel32
                    DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/text_fallback_client.c VERBATIM)
                add_custom_target(text_fallback_fixture ALL DEPENDS ${TEXT_FALLBACK})
                add_test(NAME native_text_fallback COMMAND raven --run-process --execution=native --timeout-ms=30000 ${TEXT_FALLBACK})
                set_tests_properties(native_text_fallback PROPERTIES TIMEOUT 40 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
            endif()
            add_test(NAME native_text_cli COMMAND raven --run-process --execution=native --timeout-ms=30000 ${TEXT_FIXTURE})
            set_tests_properties(native_text_cli PROPERTIES TIMEOUT 40 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
            add_executable(text_client_test desktop/text_client_test.cpp)
            target_link_libraries(text_client_test PRIVATE raven_cpu)
            add_dependencies(text_client_test text_pe_fixture raven-bootstrap)
            add_test(NAME native_text_pixels COMMAND text_client_test $<TARGET_FILE:raven-bootstrap> ${TEXT_FIXTURE} ${CMAKE_CURRENT_BINARY_DIR}/text-output)
            set_tests_properties(native_text_pixels PROPERTIES TIMEOUT 40)
            set(TEXT_PAINT ${CMAKE_CURRENT_BINARY_DIR}/text-paint.exe)
            add_custom_command(OUTPUT ${TEXT_PAINT}
                COMMAND ${RAVEN_MINGW64} -nostdlib -fno-stack-protector
                    -Wl,--entry,raven_entry,--image-base,0x1b4000000,--no-insert-timestamp
                    -o ${TEXT_PAINT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/text_paint_client.c -lkernel32 -luser32 -lgdi32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/text_paint_client.c VERBATIM)
            add_custom_target(text_paint_fixture ALL DEPENDS ${TEXT_PAINT})
            add_executable(text_paint_test desktop/text_paint_test.cpp)
            target_link_libraries(text_paint_test PRIVATE raven_cpu)
            add_dependencies(text_paint_test text_paint_fixture raven-bootstrap)
            add_test(NAME native_text_paint COMMAND text_paint_test $<TARGET_FILE:raven-bootstrap> ${TEXT_PAINT} ${CMAKE_CURRENT_BINARY_DIR}/text-paint.bgra)
            set_tests_properties(native_text_paint PROPERTIES TIMEOUT 20)
        endif()
        set(FONT_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/font-fixture.exe)
        add_custom_command(OUTPUT ${FONT_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x1ab000000,--no-insert-timestamp
                -o ${FONT_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/font_client.c -lgdi32 -luser32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/font_client.c VERBATIM)
        add_custom_target(font_pe_fixture ALL DEPENDS ${FONT_FIXTURE})
        add_test(NAME native_font_cli COMMAND raven --run-process --execution=native ${FONT_FIXTURE})
        set_tests_properties(native_font_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(FONT_BOUNDARY ${CMAKE_CURRENT_BINARY_DIR}/font-boundary.exe)
        add_custom_command(OUTPUT ${FONT_BOUNDARY}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -DRAVEN_FONT_BOUNDARY
                -Wl,--entry,raven_entry,--image-base,0x1ab000000,--no-insert-timestamp
                -o ${FONT_BOUNDARY} ${PROJECT_SOURCE_DIR}/testdata/native_loader/font_client.c -lgdi32 -luser32 -lkernel32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/font_client.c VERBATIM)
        add_custom_target(font_boundary_fixture ALL DEPENDS ${FONT_BOUNDARY})
        add_test(NAME native_font_boundary COMMAND raven --run-process --execution=native ${FONT_BOUNDARY})
        set_tests_properties(native_font_boundary PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(MEMORY_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/memory-fixture.exe)
        add_custom_command(OUTPUT ${MEMORY_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x196000000
                -o ${MEMORY_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/memory_client.c -lkernel32 -lntdll
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/memory_client.c VERBATIM)
        add_custom_target(memory_pe_fixture ALL DEPENDS ${MEMORY_FIXTURE})
        add_test(NAME native_memory_cli COMMAND raven --run-process --execution=native ${MEMORY_FIXTURE})
        set_tests_properties(native_memory_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(SYSTEM_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/system-fixture.exe)
        add_custom_command(OUTPUT ${SYSTEM_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x198000000
                -o ${SYSTEM_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/system_client.c -lkernel32 -lntdll
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/system_client.c VERBATIM)
        add_custom_target(system_pe_fixture ALL DEPENDS ${SYSTEM_FIXTURE})
        add_test(NAME native_system_cli COMMAND raven --run-process --execution=native ${SYSTEM_FIXTURE})
        set_tests_properties(native_system_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(EVENT_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/event-fixture.exe)
        add_custom_command(OUTPUT ${EVENT_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x199000000
                -o ${EVENT_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/event_client.c -lkernel32 -lntdll
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/event_client.c VERBATIM)
        add_custom_target(event_pe_fixture ALL DEPENDS ${EVENT_FIXTURE})
        add_test(NAME native_event_cli COMMAND raven --run-process --execution=native ${EVENT_FIXTURE})
        set_tests_properties(native_event_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(WINDOW_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/window-fixture.exe)
        add_custom_command(OUTPUT ${WINDOW_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -nostdlib
                -Wl,--entry,raven_entry,--image-base,0x1a4000000,--no-insert-timestamp
                -o ${WINDOW_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/window_client.c -lkernel32 -luser32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/window_client.c VERBATIM)
        add_custom_target(window_pe_fixture ALL DEPENDS ${WINDOW_FIXTURE})
        set(OUTER_SURFACE_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/outer-surface.exe)
        add_custom_command(OUTPUT ${OUTER_SURFACE_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x1a4000000
                -o ${OUTER_SURFACE_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/outer_surface_client.c -lkernel32 -luser32 -lgdi32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/outer_surface_client.c VERBATIM)
        add_custom_target(outer_surface_pe_fixture ALL DEPENDS ${OUTER_SURFACE_FIXTURE})
        add_test(NAME native_outer_surface_cli COMMAND raven --run-process --execution=native ${OUTER_SURFACE_FIXTURE})
        set_tests_properties(native_outer_surface_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(NONCLIENT_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/nonclient-metrics.exe)
        set(NONCLIENT_BOUNDARY ${CMAKE_CURRENT_BINARY_DIR}/nonclient-metrics-boundary.exe)
        add_custom_command(OUTPUT ${NONCLIENT_FIXTURE} ${NONCLIENT_BOUNDARY}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x1a4000000,--no-insert-timestamp
                -o ${NONCLIENT_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/nonclient_client.c -lkernel32 -luser32
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -DRAVEN_NONCLIENT_BOUNDARY
                -Wl,--entry,raven_entry,--image-base,0x1a4000000,--no-insert-timestamp
                -o ${NONCLIENT_BOUNDARY} ${PROJECT_SOURCE_DIR}/testdata/native_loader/nonclient_client.c -lkernel32 -luser32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/nonclient_client.c ${PROJECT_SOURCE_DIR}/testdata/native_loader/nonclient_reference.h VERBATIM)
        add_custom_target(nonclient_pe_fixture ALL DEPENDS ${NONCLIENT_FIXTURE} ${NONCLIENT_BOUNDARY})
        add_executable(nonclient_test desktop/nonclient_test.cpp)
        target_link_libraries(nonclient_test PRIVATE raven_cpu)
        add_dependencies(nonclient_test nonclient_pe_fixture raven-bootstrap)
        add_test(NAME native_nonclient_contract COMMAND nonclient_test $<TARGET_FILE:raven-bootstrap> ${NONCLIENT_FIXTURE})
        add_test(NAME native_nonclient_cli COMMAND raven --run-process --execution=native ${NONCLIENT_FIXTURE})
        add_test(NAME native_nonclient_boundary COMMAND raven --run-process --execution=native ${NONCLIENT_BOUNDARY})
        set_tests_properties(native_nonclient_contract PROPERTIES TIMEOUT 15)
        set_tests_properties(native_nonclient_cli native_nonclient_boundary PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(CREATION_DC_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/creation-dc.exe)
        add_custom_command(OUTPUT ${CREATION_DC_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x1a4000000,--no-insert-timestamp
                -o ${CREATION_DC_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/creation_dc_client.c -lkernel32 -luser32 -lgdi32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/creation_dc_client.c VERBATIM)
        add_custom_target(creation_dc_fixture ALL DEPENDS ${CREATION_DC_FIXTURE})
        add_executable(creation_dc_test desktop/creation_dc_test.cpp)
        target_link_libraries(creation_dc_test PRIVATE raven_cpu)
        add_dependencies(creation_dc_test creation_dc_fixture raven-bootstrap)
        add_test(NAME native_creation_dc COMMAND creation_dc_test $<TARGET_FILE:raven-bootstrap> ${CREATION_DC_FIXTURE})
        set_tests_properties(native_creation_dc PROPERTIES TIMEOUT 15)
        set(CREATION_DC_BOUNDARY ${CMAKE_CURRENT_BINARY_DIR}/creation-dc-boundary.exe)
        add_custom_command(OUTPUT ${CREATION_DC_BOUNDARY}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -DRAVEN_DC_BOUNDARY
                -Wl,--entry,raven_entry,--image-base,0x1a4000000,--no-insert-timestamp
                -o ${CREATION_DC_BOUNDARY} ${PROJECT_SOURCE_DIR}/testdata/native_loader/creation_dc_client.c -lkernel32 -luser32 -lgdi32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/creation_dc_client.c VERBATIM)
        add_custom_target(creation_dc_boundary_fixture ALL DEPENDS ${CREATION_DC_BOUNDARY})
        add_dependencies(creation_dc_test creation_dc_boundary_fixture)
        add_test(NAME native_creation_dc_boundary COMMAND creation_dc_test $<TARGET_FILE:raven-bootstrap> ${CREATION_DC_BOUNDARY} boundary)
        set_tests_properties(native_creation_dc_boundary PROPERTIES TIMEOUT 15)
        if(TARGET raven_text)
            set(OUTER_SURFACE_VISIBLE ${CMAKE_CURRENT_BINARY_DIR}/outer-surface-visible.exe)
            add_custom_command(OUTPUT ${OUTER_SURFACE_VISIBLE}
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -DVISIBLE_SURFACE
                    -Wl,--entry,raven_entry,--image-base,0x1a4000000,--no-insert-timestamp
                    -o ${OUTER_SURFACE_VISIBLE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/outer_surface_client.c -lkernel32 -luser32 -lgdi32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/outer_surface_client.c ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_data.h VERBATIM)
            add_custom_target(outer_surface_visible_fixture ALL DEPENDS ${OUTER_SURFACE_VISIBLE})
            add_executable(outer_surface_test desktop/outer_surface_test.cpp)
            target_link_libraries(outer_surface_test PRIVATE raven_cpu)
            add_dependencies(outer_surface_test outer_surface_visible_fixture raven-bootstrap)
            add_test(NAME native_outer_surface_visible COMMAND outer_surface_test $<TARGET_FILE:raven-bootstrap> ${OUTER_SURFACE_VISIBLE})
            set_tests_properties(native_outer_surface_visible PROPERTIES TIMEOUT 15)
            set(OUTER_SURFACE_INPUT ${CMAKE_CURRENT_BINARY_DIR}/outer-surface-input.exe)
            add_custom_command(OUTPUT ${OUTER_SURFACE_INPUT}
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -DVISIBLE_SURFACE -DINPUT_SURFACE
                    -Wl,--entry,raven_entry,--image-base,0x1a4000000,--no-insert-timestamp
                    -o ${OUTER_SURFACE_INPUT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/outer_surface_client.c -lkernel32 -luser32 -lgdi32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/outer_surface_client.c ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_data.h VERBATIM)
            add_custom_target(outer_surface_input_fixture ALL DEPENDS ${OUTER_SURFACE_INPUT})
            add_dependencies(outer_surface_test outer_surface_input_fixture)
            add_test(NAME native_outer_surface_input COMMAND outer_surface_test $<TARGET_FILE:raven-bootstrap> ${OUTER_SURFACE_INPUT} input)
            set_tests_properties(native_outer_surface_input PROPERTIES TIMEOUT 15)
            set(OUTER_SURFACE_PAINT ${CMAKE_CURRENT_BINARY_DIR}/outer-surface-paint.exe)
            add_custom_command(OUTPUT ${OUTER_SURFACE_PAINT}
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -DVISIBLE_SURFACE -DPAINT_SURFACE
                    -Wl,--entry,raven_entry,--image-base,0x1a4000000,--no-insert-timestamp
                    -o ${OUTER_SURFACE_PAINT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/outer_surface_client.c -lkernel32 -luser32 -lgdi32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/outer_surface_client.c ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_data.h VERBATIM)
            add_custom_target(outer_surface_paint_fixture ALL DEPENDS ${OUTER_SURFACE_PAINT})
            add_dependencies(outer_surface_test outer_surface_paint_fixture)
            add_test(NAME native_outer_surface_paint COMMAND outer_surface_test $<TARGET_FILE:raven-bootstrap> ${OUTER_SURFACE_PAINT} capture ${CMAKE_CURRENT_BINARY_DIR}/outer-surface-paint.bgra)
            set_tests_properties(native_outer_surface_paint PROPERTIES TIMEOUT 15)
        endif()
        set(INITIAL_MESSAGE_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/initial-message-fixtures)
        add_custom_command(OUTPUT ${INITIAL_MESSAGE_FIXTURES}/client.exe ${INITIAL_MESSAGE_FIXTURES}/exit.exe
            COMMAND ${CMAKE_COMMAND} -E make_directory ${INITIAL_MESSAGE_FIXTURES}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x1a4000000
                -o ${INITIAL_MESSAGE_FIXTURES}/client.exe ${PROJECT_SOURCE_DIR}/testdata/native_loader/initial_messages_client.c -lkernel32 -luser32
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -DEXIT_DURING_SIZE
                -Wl,--entry,raven_entry,--image-base,0x1a4000000
                -o ${INITIAL_MESSAGE_FIXTURES}/exit.exe ${PROJECT_SOURCE_DIR}/testdata/native_loader/initial_messages_client.c -lkernel32 -luser32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/initial_messages_client.c VERBATIM)
        add_custom_target(initial_message_pe_fixtures ALL DEPENDS ${INITIAL_MESSAGE_FIXTURES}/client.exe ${INITIAL_MESSAGE_FIXTURES}/exit.exe)
        add_executable(initial_messages_test desktop/initial_messages_test.cpp)
        target_link_libraries(initial_messages_test PRIVATE raven_cpu)
        add_dependencies(initial_messages_test initial_message_pe_fixtures raven-bootstrap)
        add_test(NAME native_initial_messages_contract COMMAND initial_messages_test $<TARGET_FILE:raven-bootstrap> ${INITIAL_MESSAGE_FIXTURES})
        set_tests_properties(native_initial_messages_contract PROPERTIES TIMEOUT 15)
        add_test(NAME native_initial_messages_cli COMMAND raven --run-process --execution=native ${INITIAL_MESSAGE_FIXTURES}/client.exe)
        set_tests_properties(native_initial_messages_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(COORDINATE_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/coordinate-fixture.exe)
        add_custom_command(OUTPUT ${COORDINATE_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x1a4000000
                -o ${COORDINATE_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/coordinate_client.c -lkernel32 -luser32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/coordinate_client.c VERBATIM)
        add_custom_target(coordinate_pe_fixture ALL DEPENDS ${COORDINATE_FIXTURE})
        add_executable(coordinates_test desktop/coordinates_test.cpp)
        target_link_libraries(coordinates_test PRIVATE raven_cpu)
        add_dependencies(coordinates_test coordinate_pe_fixture raven-bootstrap)
        add_test(NAME native_coordinate_contract COMMAND coordinates_test $<TARGET_FILE:raven-bootstrap> ${COORDINATE_FIXTURE})
        set_tests_properties(native_coordinate_contract PROPERTIES TIMEOUT 15)
        add_test(NAME native_coordinate_cli COMMAND raven --run-process --execution=native ${COORDINATE_FIXTURE})
        set_tests_properties(native_coordinate_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        add_test(NAME native_window_cli COMMAND raven --run-process --execution=native ${WINDOW_FIXTURE})
        set_tests_properties(native_window_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(PAINT_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/paint-fixture.exe)
        add_custom_command(OUTPUT ${PAINT_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -nostdlib
                -Wl,--entry,raven_entry,--image-base,0x1a5000000,--no-insert-timestamp
                -o ${PAINT_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c -lkernel32 -luser32 -lgdi32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c VERBATIM)
        add_custom_target(paint_pe_fixture ALL DEPENDS ${PAINT_FIXTURE})
        set(CLOSE_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/close-fixture.exe)
        add_custom_command(OUTPUT ${CLOSE_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -nostdlib -DRAVEN_CLOSE_LOOP
                -Wl,--entry,raven_entry,--image-base,0x1a5000000,--no-insert-timestamp
                -o ${CLOSE_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c -lkernel32 -luser32 -lgdi32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c VERBATIM)
        add_custom_target(close_pe_fixture ALL DEPENDS ${CLOSE_FIXTURE})
        set(POINTER_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/pointer-fixture.exe)
        add_custom_command(OUTPUT ${POINTER_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -nostdlib -DRAVEN_CLOSE_LOOP -DRAVEN_POINTER_LOOP
                -Wl,--entry,raven_entry,--image-base,0x1a5000000,--no-insert-timestamp
                -o ${POINTER_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c -lkernel32 -luser32 -lgdi32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c VERBATIM)
        add_custom_target(pointer_pe_fixture ALL DEPENDS ${POINTER_FIXTURE})
        set(KEYBOARD_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/keyboard-fixture.exe)
        add_custom_command(OUTPUT ${KEYBOARD_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -nostdlib -DRAVEN_CLOSE_LOOP -DRAVEN_KEYBOARD_LOOP
                -Wl,--entry,raven_entry,--image-base,0x1a5000000,--no-insert-timestamp
                -o ${KEYBOARD_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c -lkernel32 -luser32 -lgdi32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c VERBATIM)
        add_custom_target(keyboard_pe_fixture ALL DEPENDS ${KEYBOARD_FIXTURE})
        set(REPAINT_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/repaint-fixture.exe)
        add_custom_command(OUTPUT ${REPAINT_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -nostdlib -DRAVEN_CLOSE_LOOP -DRAVEN_REPAINT_LOOP
                -Wl,--entry,raven_entry,--image-base,0x1a5000000,--no-insert-timestamp
                -o ${REPAINT_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c -lkernel32 -luser32 -lgdi32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c VERBATIM)
        add_custom_target(repaint_pe_fixture ALL DEPENDS ${REPAINT_FIXTURE})
        if(PIXMAN_FOUND)
            add_executable(repaint_test desktop/repaint_test.cpp)
            target_link_libraries(repaint_test PRIVATE raven_cpu)
            add_dependencies(repaint_test repaint_pe_fixture raven-bootstrap)
            add_test(NAME native_repaint_client COMMAND repaint_test $<TARGET_FILE:raven-bootstrap> ${REPAINT_FIXTURE})
            set_tests_properties(native_repaint_client PROPERTIES TIMEOUT 15)
        endif()
        if(XKBCOMMON_FOUND)
            add_executable(keyboard_client_test desktop/keyboard_client_test.cpp)
            target_link_libraries(keyboard_client_test PRIVATE raven_cpu)
            set(FOCUS_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/keyboard-focus.exe)
            add_custom_command(OUTPUT ${FOCUS_FIXTURE}
                COMMAND ${RAVEN_MINGW64} -nostdlib -DRAVEN_CLOSE_LOOP -DRAVEN_KEYBOARD_LOOP -DRAVEN_FOCUS_LOOP
                    -Wl,--entry,raven_entry,--image-base,0x1a4000000,--no-insert-timestamp
                    -o ${FOCUS_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c -lkernel32 -luser32 -lgdi32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c VERBATIM)
            add_custom_target(keyboard_focus_pe_fixture ALL DEPENDS ${FOCUS_FIXTURE})
            add_dependencies(keyboard_client_test keyboard_pe_fixture keyboard_focus_pe_fixture raven-bootstrap)
            foreach(FOCUS_CASE held duplicate outofrange nofocus)
                add_test(NAME native_keyboard_focus_${FOCUS_CASE} COMMAND keyboard_client_test $<TARGET_FILE:raven-bootstrap> ${FOCUS_FIXTURE} ${FOCUS_CASE})
                set_tests_properties(native_keyboard_focus_${FOCUS_CASE} PROPERTIES TIMEOUT 15)
            endforeach()
            add_test(NAME native_keyboard_client COMMAND keyboard_client_test $<TARGET_FILE:raven-bootstrap> ${KEYBOARD_FIXTURE})
            set_tests_properties(native_keyboard_client PROPERTIES TIMEOUT 15)
        endif()
        set(BITBLT_PAINT ${CMAKE_CURRENT_BINARY_DIR}/bitblt-paint.exe)
        add_custom_command(OUTPUT ${BITBLT_PAINT}
            COMMAND ${RAVEN_MINGW64} -nostdlib -DRAVEN_BITBLT_PAINT
                -Wl,--entry,raven_entry,--image-base,0x1b9000000,--no-insert-timestamp
                -o ${BITBLT_PAINT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c -lkernel32 -luser32 -lgdi32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c VERBATIM)
        add_custom_target(bitblt_paint_fixture ALL DEPENDS ${BITBLT_PAINT})
        set(COMPATIBLE_PAINT ${CMAKE_CURRENT_BINARY_DIR}/compatible-bitmap-paint.exe)
        add_custom_command(OUTPUT ${COMPATIBLE_PAINT}
            COMMAND ${RAVEN_MINGW64} -nostdlib -DRAVEN_BITBLT_PAINT -DRAVEN_COMPATIBLE_PAINT
                -Wl,--entry,raven_entry,--image-base,0x1bb000000,--no-insert-timestamp
                -o ${COMPATIBLE_PAINT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c -lkernel32 -luser32 -lgdi32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/paint_client.c VERBATIM)
        add_custom_target(compatible_bitmap_paint_fixture ALL DEPENDS ${COMPATIBLE_PAINT})
        add_executable(paint_test desktop/paint_test.cpp)
        target_link_libraries(paint_test PRIVATE raven_cpu)
        add_dependencies(paint_test compatible_bitmap_paint_fixture bitblt_paint_fixture paint_pe_fixture close_pe_fixture pointer_pe_fixture raven-bootstrap)
        add_test(NAME native_compatible_bitmap_paint COMMAND paint_test $<TARGET_FILE:raven-bootstrap> ${COMPATIBLE_PAINT} ${CLOSE_FIXTURE} ${POINTER_FIXTURE})
        set_tests_properties(native_compatible_bitmap_paint PROPERTIES TIMEOUT 15)
        add_test(NAME native_bitblt_paint COMMAND paint_test $<TARGET_FILE:raven-bootstrap> ${BITBLT_PAINT} ${CLOSE_FIXTURE} ${POINTER_FIXTURE})
        set_tests_properties(native_bitblt_paint PROPERTIES TIMEOUT 15)
        add_test(NAME native_paint COMMAND paint_test $<TARGET_FILE:raven-bootstrap> ${PAINT_FIXTURE} ${CLOSE_FIXTURE} ${POINTER_FIXTURE})
        set_tests_properties(native_paint PROPERTIES TIMEOUT 15)
        set(MESSAGE_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/message-fixture.exe)
        add_custom_command(OUTPUT ${MESSAGE_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -nostdlib
                -Wl,--entry,raven_entry,--image-base,0x1a6000000,--no-insert-timestamp
                -o ${MESSAGE_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/message_client.c -lkernel32 -luser32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/message_client.c VERBATIM)
        add_custom_target(message_pe_fixture ALL DEPENDS ${MESSAGE_FIXTURE})
        add_test(NAME native_message_cli COMMAND raven --run-process --execution=native ${MESSAGE_FIXTURE})
        set_tests_properties(native_message_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(DEFAULT_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/default-fixture.exe)
        add_custom_command(OUTPUT ${DEFAULT_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -nostdlib
                -Wl,--entry,raven_entry,--image-base,0x1a8000000,--no-insert-timestamp
                -o ${DEFAULT_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/default_client.c -lkernel32 -luser32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/default_client.c VERBATIM)
        add_custom_target(default_pe_fixture ALL DEPENDS ${DEFAULT_FIXTURE})
        add_test(NAME native_default_cli COMMAND raven --run-process --execution=native ${DEFAULT_FIXTURE})
        set_tests_properties(native_default_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(FOCUS_FIXTURE ${CMAKE_CURRENT_BINARY_DIR}/focus-fixture.exe)
        add_custom_command(OUTPUT ${FOCUS_FIXTURE}
            COMMAND ${RAVEN_MINGW64} -nostdlib
                -Wl,--entry,raven_entry,--image-base,0x1a9000000,--no-insert-timestamp
                -o ${FOCUS_FIXTURE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/focus_client.c -lkernel32 -luser32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/focus_client.c VERBATIM)
        add_custom_target(focus_pe_fixture ALL DEPENDS ${FOCUS_FIXTURE})
        add_test(NAME native_focus_cli COMMAND raven --run-process --execution=native ${FOCUS_FIXTURE})
        set_tests_properties(native_focus_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(GEOMETRY_NEGATIVE ${CMAKE_CURRENT_BINARY_DIR}/geometry-negative.exe)
        add_custom_command(OUTPUT ${GEOMETRY_NEGATIVE}
            COMMAND ${RAVEN_MINGW64} -nostdlib
                -Wl,--entry,raven_entry,--image-base,0x1aa000000,--no-insert-timestamp
                -o ${GEOMETRY_NEGATIVE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/geometry_negative.c -lkernel32 -luser32
            DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/geometry_negative.c VERBATIM)
        add_custom_target(geometry_negative_fixture ALL DEPENDS ${GEOMETRY_NEGATIVE})
        add_test(NAME native_geometry_boundary COMMAND raven --run-process --execution=native ${GEOMETRY_NEGATIVE})
        set_tests_properties(native_geometry_boundary PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(RAVEN_CONTROLS_COMPONENT_DIR "" CACHE PATH "Directory holding the common controls component built by scripts/provision-controls.py")
        if(RAVEN_CONTROLS_COMPONENT_DIR)
            if(NOT EXISTS "${RAVEN_CONTROLS_COMPONENT_DIR}/comctl32.dll")
                message(FATAL_ERROR "Configured controls component does not exist")
            endif()
            add_custom_command(TARGET raven POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different ${RAVEN_CONTROLS_COMPONENT_DIR}/comctl32.dll $<TARGET_FILE_DIR:raven>/comctl32.dll
                COMMAND ${CMAKE_COMMAND} -E copy_if_different ${RAVEN_CONTROLS_COMPONENT_DIR}/raven-user32.dll $<TARGET_FILE_DIR:raven>/raven-user32.dll
                COMMAND ${CMAKE_COMMAND} -E copy_if_different ${RAVEN_CONTROLS_COMPONENT_DIR}/raven-shell.dll $<TARGET_FILE_DIR:raven>/raven-shell.dll
                COMMAND ${CMAKE_COMMAND} -E copy_if_different ${RAVEN_CONTROLS_COMPONENT_DIR}/ucrtbase.dll $<TARGET_FILE_DIR:raven>/ucrtbase.dll)
            set(EDIT_TEXT_CLIENT ${CMAKE_CURRENT_BINARY_DIR}/edit-text.exe)
            add_custom_command(OUTPUT ${EDIT_TEXT_CLIENT}
                COMMAND ${RAVEN_MINGW64} -nostdlib
                    -Wl,--entry,raven_entry,--image-base,0x1da000000,--no-insert-timestamp
                    -o ${EDIT_TEXT_CLIENT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/edit_text_client.c -lkernel32 -luser32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/edit_text_client.c VERBATIM)
            add_custom_target(edit_text_fixture ALL DEPENDS ${EDIT_TEXT_CLIENT})
            add_test(NAME native_edit_text_contract COMMAND raven --run-process --execution=native ${EDIT_TEXT_CLIENT})
            set_tests_properties(native_edit_text_contract PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
            set(UCRT_IO_CLIENT ${CMAKE_CURRENT_BINARY_DIR}/ucrt-io.exe)
            add_custom_command(OUTPUT ${UCRT_IO_CLIENT}
                COMMAND ${RAVEN_MINGW64} -nostdlib -O1 -fno-builtin -fno-stack-protector
                    -Wl,--entry,raven_entry,--image-base,0x1dc000000,--no-insert-timestamp
                    -o ${UCRT_IO_CLIENT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/ucrt_io_client.c -lucrtbase -lkernel32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/ucrt_io_client.c VERBATIM)
            add_custom_target(ucrt_io_fixture ALL DEPENDS ${UCRT_IO_CLIENT})
            add_test(NAME native_ucrt_io_contract COMMAND raven --run-process --execution=native ${UCRT_IO_CLIENT})
            set_tests_properties(native_ucrt_io_contract PROPERTIES TIMEOUT 30 PASS_REGULAR_EXPRESSION "Native entry returned 0 "
                ENVIRONMENT RAVEN_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/ucrt-prefix)
        endif()
        set(RAVEN_RTL_COMPONENT_PATH "" CACHE FILEPATH "Pinned guest RTL component built by scripts/provision-rtl.py")
        if(RAVEN_RTL_COMPONENT_PATH)
            if(NOT EXISTS "${RAVEN_RTL_COMPONENT_PATH}")
                message(FATAL_ERROR "Configured native RTL component does not exist")
            endif()
            add_custom_command(TARGET raven POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different ${RAVEN_RTL_COMPONENT_PATH} $<TARGET_FILE_DIR:raven>/raven-rtl.dll)
            set(HEAP_FIXTURE_DIR ${CMAKE_CURRENT_BINARY_DIR}/heap-fixtures)
            set(HEAP_PROBE ${HEAP_FIXTURE_DIR}/heap-probe.dll)
            set(HEAP_CLIENT ${HEAP_FIXTURE_DIR}/client.exe)
            add_custom_command(OUTPUT ${HEAP_PROBE} ${HEAP_FIXTURE_DIR}/heap-probe.lib
                COMMAND ${CMAKE_COMMAND} -E make_directory ${HEAP_FIXTURE_DIR}
                COMMAND ${RAVEN_MINGW64} -shared -nostdlib
                    -Wl,--entry,DllMain,--image-base,0x1a3000000,--no-insert-timestamp
                    -Wl,--out-implib,${HEAP_FIXTURE_DIR}/heap-probe.lib
                    -o ${HEAP_PROBE} ${PROJECT_SOURCE_DIR}/testdata/native_loader/heap_probe.c -lkernel32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/heap_probe.c VERBATIM)
            add_custom_command(OUTPUT ${HEAP_CLIENT}
                COMMAND ${RAVEN_MINGW64} -nostdlib
                    -Wl,--entry,raven_entry,--image-base,0x1a2000000,--no-insert-timestamp
                    -Xlinker --heap -Xlinker 196608,8192
                    -o ${HEAP_CLIENT} ${PROJECT_SOURCE_DIR}/testdata/native_loader/heap_client.c
                    ${HEAP_FIXTURE_DIR}/heap-probe.lib -lkernel32 -lntdll
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/heap_client.c ${HEAP_PROBE}
                    ${HEAP_FIXTURE_DIR}/heap-probe.lib VERBATIM)
            add_custom_target(heap_pe_fixture ALL DEPENDS ${HEAP_CLIENT})
            add_test(NAME native_heap_cli COMMAND raven --run-process --execution=native
                ${HEAP_CLIENT} ${HEAP_PROBE} ${RAVEN_RTL_COMPONENT_PATH})
            set_tests_properties(native_heap_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
            set(HEAP_CAPACITY ${HEAP_FIXTURE_DIR}/capacity.exe)
            add_custom_command(OUTPUT ${HEAP_CAPACITY}
                COMMAND ${RAVEN_MINGW64} -nostdlib
                    -Wl,--entry,raven_entry,--image-base,0x1a2000000,--no-insert-timestamp
                    -o ${HEAP_CAPACITY} ${PROJECT_SOURCE_DIR}/testdata/native_loader/heap_capacity.c -lkernel32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/heap_capacity.c VERBATIM)
            add_custom_target(heap_capacity_fixture ALL DEPENDS ${HEAP_CAPACITY})
            add_test(NAME native_heap_capacity_cli COMMAND raven --run-process --execution=native
                --timeout-ms=30000 ${HEAP_CAPACITY} ${RAVEN_RTL_COMPONENT_PATH})
            set_tests_properties(native_heap_capacity_cli PROPERTIES TIMEOUT 40 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        endif()
        if(PNG_FOUND AND RAVEN_WINDRES)
            set(DESKTOP_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/desktop-fixtures)
            add_custom_command(OUTPUT ${DESKTOP_FIXTURES}/client.exe ${DESKTOP_FIXTURES}/icons.dll
                COMMAND ${CMAKE_COMMAND} -E make_directory ${DESKTOP_FIXTURES}
                COMMAND ${RAVEN_WINDRES} -I ${PROJECT_SOURCE_DIR}/testdata/native_loader
                    ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_resources.rc ${DESKTOP_FIXTURES}/resources.o
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                    -Wl,--entry,raven_entry,--image-base,0x193000000
                    -o ${DESKTOP_FIXTURES}/client.exe ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_client.c
                    -lkernel32 -luser32 -lgdi32 -lcomctl32
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                    -Wl,--entry,0,--image-base,0x194000000
                    -o ${DESKTOP_FIXTURES}/icons.dll ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_module.c ${DESKTOP_FIXTURES}/resources.o
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_client.c
                    ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_module.c
                    ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_resources.rc
                    ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_resources.ico
                    ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_data.h VERBATIM)
            add_custom_target(desktop_pe_fixtures ALL DEPENDS ${DESKTOP_FIXTURES}/client.exe ${DESKTOP_FIXTURES}/icons.dll)
            add_executable(desktop_test desktop/desktop_test.cpp)
            target_include_directories(desktop_test PRIVATE ${PROJECT_SOURCE_DIR}/testdata/native_loader)
            target_link_libraries(desktop_test PRIVATE raven_cpu)
            add_dependencies(desktop_test desktop_pe_fixtures raven-bootstrap)
            add_test(NAME native_desktop_icon_contract COMMAND desktop_test $<TARGET_FILE:raven-bootstrap> ${DESKTOP_FIXTURES}
                ${PROJECT_SOURCE_DIR}/testdata/npp/notepad++.exe ${CMAKE_CURRENT_BINARY_DIR}/desktop-output)
            set_tests_properties(native_desktop_icon_contract PROPERTIES TIMEOUT 120)
            add_test(NAME native_desktop_icon_cli COMMAND raven --run-process --execution=native ${DESKTOP_FIXTURES}/client.exe)
            set_tests_properties(native_desktop_icon_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
            add_custom_command(OUTPUT ${DESKTOP_FIXTURES}/surface.exe
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                    -Wl,--entry,raven_entry,--image-base,0x195000000
                    -o ${DESKTOP_FIXTURES}/surface.exe ${PROJECT_SOURCE_DIR}/testdata/native_loader/surface_client.c
                    -lkernel32 -luser32 -lgdi32
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_loader/surface_client.c
                    ${PROJECT_SOURCE_DIR}/testdata/native_loader/icon_data.h VERBATIM)
            add_custom_target(surface_pe_fixture ALL DEPENDS ${DESKTOP_FIXTURES}/surface.exe)
            add_test(NAME native_desktop_surface_cli COMMAND raven --run-process --execution=native ${DESKTOP_FIXTURES}/surface.exe)
            set_tests_properties(native_desktop_surface_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        endif()
        find_program(RAVEN_DLLTOOL x86_64-w64-mingw32-dlltool)
        if(Vulkan_FOUND AND RAVEN_DLLTOOL)
            set(VULKAN_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/vulkan-fixtures)
            # The import library lists every command the guest provider exports: the hand-written ones and the generated ones.
            if(VULKAN_GENERATED_SOURCES)
                set(VULKAN_FIXTURE_DEF ${VULKAN_GENERATED_DIR}/vulkan_all_exports.def)
            else()
                set(VULKAN_FIXTURE_DEF ${PROJECT_SOURCE_DIR}/testdata/native_cpu/vulkan.def)
            endif()
            add_custom_command(OUTPUT ${VULKAN_FIXTURES}/vulkan.a
                COMMAND ${CMAKE_COMMAND} -E make_directory ${VULKAN_FIXTURES}
                COMMAND ${RAVEN_DLLTOOL} -d ${VULKAN_FIXTURE_DEF}
                    -l ${VULKAN_FIXTURES}/vulkan.a
                DEPENDS ${VULKAN_FIXTURE_DEF} VERBATIM)
            add_custom_command(OUTPUT ${VULKAN_FIXTURES}/client.exe
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -mno-stack-arg-probe
                    -idirafter ${Vulkan_INCLUDE_DIRS} -I${PROJECT_SOURCE_DIR}/testdata/native_cpu
                    -Wl,--entry,raven_entry,--image-base,0x18e000000
                    -o ${VULKAN_FIXTURES}/client.exe ${PROJECT_SOURCE_DIR}/testdata/native_cpu/vulkan_client.c
                    ${VULKAN_FIXTURES}/vulkan.a
                DEPENDS ${PROJECT_SOURCE_DIR}/testdata/native_cpu/vulkan_client.c
                    ${PROJECT_SOURCE_DIR}/testdata/native_cpu/vulkan_compute_spirv.h ${PROJECT_SOURCE_DIR}/testdata/native_cpu/vulkan_triangle_spirv.h ${PROJECT_SOURCE_DIR}/testdata/native_cpu/vulkan_quad_spirv.h ${VULKAN_FIXTURES}/vulkan.a VERBATIM)
            add_custom_target(vulkan_pe_fixture ALL DEPENDS ${VULKAN_FIXTURES}/client.exe)
            add_executable(vulkan_bridge_test graphics/vulkan_bridge_test.cpp)
            target_link_libraries(vulkan_bridge_test PRIVATE raven_cpu)
            add_dependencies(vulkan_bridge_test vulkan_pe_fixture raven-bootstrap)
            add_test(NAME native_vulkan_contract COMMAND vulkan_bridge_test
                $<TARGET_FILE:raven-bootstrap> ${VULKAN_FIXTURES}/client.exe)
            set_tests_properties(native_vulkan_contract PROPERTIES TIMEOUT 20)
            add_test(NAME native_vulkan_cli COMMAND raven --run-process --execution=native ${VULKAN_FIXTURES}/client.exe)
            set_tests_properties(native_vulkan_cli PROPERTIES TIMEOUT 20
                PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        endif()
        set(CALLBACK_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/callback-fixtures)
        set(CALLBACK_SOURCES ${PROJECT_SOURCE_DIR}/testdata/native_cpu)
        add_custom_command(OUTPUT ${CALLBACK_FIXTURES}/ravenprobe.dll ${CALLBACK_FIXTURES}/probe.a
            COMMAND ${CMAKE_COMMAND} -E make_directory ${CALLBACK_FIXTURES}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                -Wl,--entry,0,--image-base,0x183000000
                -Wl,--out-implib,${CALLBACK_FIXTURES}/probe.a
                -o ${CALLBACK_FIXTURES}/ravenprobe.dll
                ${CALLBACK_SOURCES}/callback_probe.c ${CALLBACK_SOURCES}/callback_probe.def
            DEPENDS ${CALLBACK_SOURCES}/callback_probe.c ${CALLBACK_SOURCES}/callback_probe.def
            VERBATIM)
        add_custom_command(OUTPUT ${CALLBACK_FIXTURES}/client.exe
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x184000000
                -o ${CALLBACK_FIXTURES}/client.exe ${CALLBACK_SOURCES}/callback_client.c ${CALLBACK_FIXTURES}/probe.a
            DEPENDS ${CALLBACK_SOURCES}/callback_client.c ${CALLBACK_FIXTURES}/probe.a
            VERBATIM)
        add_custom_target(callback_pe_fixtures DEPENDS ${CALLBACK_FIXTURES}/client.exe ${CALLBACK_FIXTURES}/ravenprobe.dll)
        add_executable(callback_fixture_test cpu/callback_fixture_test.cpp)
        target_link_libraries(callback_fixture_test PRIVATE raven_cpu)
        add_dependencies(callback_fixture_test callback_pe_fixtures raven-bootstrap)
        add_test(NAME compiled_callback_contract COMMAND callback_fixture_test $<TARGET_FILE:raven-bootstrap>
            ${CALLBACK_FIXTURES}/client.exe ${CALLBACK_FIXTURES}/ravenprobe.dll)
        set_tests_properties(compiled_callback_contract PROPERTIES TIMEOUT 15)

        add_custom_command(OUTPUT ${CALLBACK_FIXTURES}/kernel32.dll ${CALLBACK_FIXTURES}/environment.a
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                -Wl,--entry,0,--image-base,0x186000000
                -Wl,--out-implib,${CALLBACK_FIXTURES}/environment.a
                -o ${CALLBACK_FIXTURES}/kernel32.dll
                ${CALLBACK_SOURCES}/environment_probe.c ${CALLBACK_SOURCES}/environment_probe.def
            DEPENDS ${CALLBACK_SOURCES}/environment_probe.c ${CALLBACK_SOURCES}/environment_probe.def
            VERBATIM)
        add_custom_command(OUTPUT ${CALLBACK_FIXTURES}/environment.exe
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x185000000
                -o ${CALLBACK_FIXTURES}/environment.exe ${CALLBACK_SOURCES}/environment_client.c
                ${CALLBACK_FIXTURES}/environment.a
            DEPENDS ${CALLBACK_SOURCES}/environment_client.c ${CALLBACK_FIXTURES}/environment.a
            VERBATIM)
        add_custom_command(OUTPUT ${CALLBACK_FIXTURES}/api_loop.exe
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x187000000
                -o ${CALLBACK_FIXTURES}/api_loop.exe ${CALLBACK_SOURCES}/api_loop.c ${CALLBACK_FIXTURES}/environment.a
            DEPENDS ${CALLBACK_SOURCES}/api_loop.c ${CALLBACK_FIXTURES}/environment.a
            VERBATIM)
        add_custom_target(environment_pe_fixtures DEPENDS ${CALLBACK_FIXTURES}/environment.exe
            ${CALLBACK_FIXTURES}/kernel32.dll ${CALLBACK_FIXTURES}/api_loop.exe)
        add_executable(environment_test nt/environment_test.cpp)
        target_link_libraries(environment_test PRIVATE raven_cpu)
        add_dependencies(environment_test environment_pe_fixtures raven-bootstrap)
        add_test(NAME native_environment_contract COMMAND environment_test $<TARGET_FILE:raven-bootstrap>
            ${CALLBACK_FIXTURES}/environment.exe ${CALLBACK_FIXTURES}/kernel32.dll)
        set_tests_properties(native_environment_contract PROPERTIES TIMEOUT 15)
        add_test(NAME native_process_cli COMMAND raven --run-process --execution=native ${CALLBACK_FIXTURES}/environment.exe)
        set_tests_properties(native_process_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")

        set(MODULE_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/module-fixtures)
        set(LOADER_SOURCES ${PROJECT_SOURCE_DIR}/testdata/native_loader)
        add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/arguments.exe
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x18e000000
                -o ${CMAKE_CURRENT_BINARY_DIR}/arguments.exe ${LOADER_SOURCES}/arguments_client.c -lkernel32
            DEPENDS ${LOADER_SOURCES}/arguments_client.c VERBATIM)
        add_custom_target(arguments_fixture ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/arguments.exe)
        add_test(NAME native_guest_arguments_cli COMMAND raven --run-process --execution=native
            ${CMAKE_CURRENT_BINARY_DIR}/arguments.exe -- "" plain "with space" "a\"b" "C:\\tail\\" --)
        set_tests_properties(native_guest_arguments_cli PROPERTIES TIMEOUT 15)
        # Kernel contract fixtures check their own results and return a distinct non-zero code for each failed expectation.
        find_program(RAVEN_CLANG clang)
        find_package(Python3 COMPONENTS Interpreter QUIET)
        function(raven_kernel_fixture name source base libraries)
            set(output ${CMAKE_CURRENT_BINARY_DIR}/${name}.exe)
            add_custom_command(OUTPUT ${output}
                COMMAND ${RAVEN_MINGW64} -O1 -nostdlib -fno-stack-protector -fno-builtin -mno-stack-arg-probe
                    -Wl,--entry,raven_entry,--image-base,${base}
                    -o ${output} ${LOADER_SOURCES}/${source} ${libraries}
                DEPENDS ${LOADER_SOURCES}/${source} VERBATIM)
            add_custom_target(${name}_fixture ALL DEPENDS ${output})
        endfunction()
        raven_kernel_fixture(kernel-file kernel_files_client.c 0x1b1000000 "-lkernel32")
        raven_kernel_fixture(kernel-ansi kernel_ansi_client.c 0x1b5000000 "-lkernel32")
        raven_kernel_fixture(kernel-threads kernel_threads_client.c 0x1b2000000 "-lkernel32")
        raven_kernel_fixture(kernel-shlwapi kernel_shlwapi_client.c 0x1b4000000 "-lkernel32;-lshlwapi")
        set(KERNEL_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/kernel-prefix)
        add_test(NAME native_kernel_files COMMAND raven --run-process --execution=native ${CMAKE_CURRENT_BINARY_DIR}/kernel-file.exe)
        add_test(NAME native_kernel_ansi COMMAND raven --run-process --execution=native ${CMAKE_CURRENT_BINARY_DIR}/kernel-ansi.exe)
        add_test(NAME native_kernel_threads COMMAND raven --run-process --execution=native ${CMAKE_CURRENT_BINARY_DIR}/kernel-threads.exe)
        add_test(NAME native_kernel_shlwapi COMMAND raven --run-process --execution=native ${CMAKE_CURRENT_BINARY_DIR}/kernel-shlwapi.exe)
        set_tests_properties(native_kernel_files native_kernel_ansi native_kernel_threads native_kernel_shlwapi PROPERTIES TIMEOUT 30
            PASS_REGULAR_EXPRESSION "Native entry returned 0 " ENVIRONMENT RAVEN_PREFIX=${KERNEL_PREFIX})
        add_test(NAME native_kernel_file_persistence COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/check-file-persistence.py ${KERNEL_PREFIX})
        set_tests_properties(native_kernel_file_persistence PROPERTIES TIMEOUT 15 DEPENDS native_kernel_files)
        if(RAVEN_CLANG)
            # The structured-exception fixture needs the compiler's __try support; the program supplies its own scope-table handler.
            set(SEH_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/kernel-seh.o)
            add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kernel-seh.exe
                COMMAND ${RAVEN_CLANG} --target=x86_64-w64-mingw32 -O0 -fms-extensions -fseh-exceptions -Xclang -fasync-exceptions -Wno-inconsistent-dllimport -fno-stack-protector -mno-stack-arg-probe -c
                    -o ${SEH_OBJECT} ${LOADER_SOURCES}/kernel_seh_client.c
                COMMAND ${RAVEN_MINGW64} -nostdlib -Wl,--entry,raven_entry,--image-base,0x1b3000000
                    -o ${CMAKE_CURRENT_BINARY_DIR}/kernel-seh.exe ${SEH_OBJECT} -lkernel32
                DEPENDS ${LOADER_SOURCES}/kernel_seh_client.c VERBATIM)
            add_custom_target(kernel_seh_fixture ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/kernel-seh.exe)
            add_test(NAME native_kernel_seh COMMAND raven --run-process --execution=native ${CMAKE_CURRENT_BINARY_DIR}/kernel-seh.exe)
            set_tests_properties(native_kernel_seh PROPERTIES TIMEOUT 30 PASS_REGULAR_EXPRESSION "Native entry returned 0 "
                ENVIRONMENT RAVEN_PREFIX=${KERNEL_PREFIX})
        endif()
        add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/startup-info.exe
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -ffreestanding -fno-builtin -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x18c000000
                -o ${CMAKE_CURRENT_BINARY_DIR}/startup-info.exe ${LOADER_SOURCES}/startup_info_client.c -lkernel32
            DEPENDS ${LOADER_SOURCES}/startup_info_client.c VERBATIM)
        add_custom_target(startup_info_fixture ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/startup-info.exe)
        add_executable(startup_test nt/startup_test.cpp)
        target_link_libraries(startup_test PRIVATE raven_cpu)
        add_dependencies(startup_test startup_info_fixture raven-bootstrap)
        add_test(NAME native_startup_information COMMAND startup_test $<TARGET_FILE:raven-bootstrap> ${CMAKE_CURRENT_BINARY_DIR}/startup-info.exe)
        set_tests_properties(native_startup_information PROPERTIES TIMEOUT 30)
        add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/file-client.exe
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--no-insert-timestamp
                -o ${CMAKE_CURRENT_BINARY_DIR}/file-client.exe ${LOADER_SOURCES}/file_client.c -lkernel32
            DEPENDS ${LOADER_SOURCES}/file_client.c VERBATIM)
        add_custom_target(file_fixture ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/file-client.exe)
        add_executable(file_test nt/file_test.cpp)
        target_link_libraries(file_test PRIVATE raven_cpu)
        add_dependencies(file_test file_fixture raven-bootstrap)
        add_test(NAME native_standard_files COMMAND file_test $<TARGET_FILE:raven-bootstrap>
            ${CMAKE_CURRENT_BINARY_DIR}/file-client.exe ${CMAKE_CURRENT_BINARY_DIR}/file-contract.bin)
        set_tests_properties(native_standard_files PROPERTIES TIMEOUT 15)
        find_package(Python3 COMPONENTS Interpreter QUIET)
        if(Python3_Interpreter_FOUND)
            find_program(RAVEN_MINGW32 i686-w64-mingw32-gcc)
            if(RAVEN_MINGW32)
                add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/x86-client.exe
                    COMMAND ${RAVEN_MINGW32} -O2 -nostdlib -fno-stack-protector -fno-builtin
                        -Wl,--entry,_raven_entry,--no-insert-timestamp
                        -o ${CMAKE_CURRENT_BINARY_DIR}/x86-client.exe ${LOADER_SOURCES}/x86_client.c -lkernel32
                    DEPENDS ${LOADER_SOURCES}/x86_client.c VERBATIM)
                add_custom_target(x86_fixture ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/x86-client.exe)
                add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/x86-kernel-client.exe
                    COMMAND ${RAVEN_MINGW32} -O2 -nostdlib -fno-stack-protector -fno-builtin
                        -Wl,--entry,_raven_entry,--no-insert-timestamp
                        -o ${CMAKE_CURRENT_BINARY_DIR}/x86-kernel-client.exe ${LOADER_SOURCES}/x86_kernel_client.c -lkernel32
                    DEPENDS ${LOADER_SOURCES}/x86_kernel_client.c VERBATIM)
                add_custom_target(x86_kernel_fixture ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/x86-kernel-client.exe)
                add_test(NAME native_x86_kernel_cli COMMAND raven --run-process --execution=native
                    ${CMAKE_CURRENT_BINARY_DIR}/x86-kernel-client.exe)
                set_tests_properties(native_x86_kernel_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
                # The desktop contracts below are width-neutral; each fixture is the same source the x64 runtime qualifies.
                set(X86_DESKTOP_CLIENTS default window_text coordinate focus message)
                foreach(CLIENT ${X86_DESKTOP_CLIENTS})
                    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/x86-desktop-${CLIENT}.exe
                        COMMAND ${RAVEN_MINGW32} -O2 -nostdlib -fno-stack-protector -fno-builtin
                            -Wl,--entry,_raven_entry,--no-insert-timestamp
                            -o ${CMAKE_CURRENT_BINARY_DIR}/x86-desktop-${CLIENT}.exe
                            ${LOADER_SOURCES}/${CLIENT}_client.c -lkernel32 -luser32 -lgdi32
                        DEPENDS ${LOADER_SOURCES}/${CLIENT}_client.c VERBATIM)
                    list(APPEND X86_DESKTOP_EXECUTABLES ${CMAKE_CURRENT_BINARY_DIR}/x86-desktop-${CLIENT}.exe)
                    add_test(NAME native_x86_desktop_${CLIENT} COMMAND raven --run-process --execution=native
                        ${CMAKE_CURRENT_BINARY_DIR}/x86-desktop-${CLIENT}.exe)
                    set_tests_properties(native_x86_desktop_${CLIENT} PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
                endforeach()
                add_custom_target(x86_desktop_fixtures ALL DEPENDS ${X86_DESKTOP_EXECUTABLES})
                foreach(PHASE 1 2)
                    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/x86-registry-${PHASE}.exe
                        COMMAND ${RAVEN_MINGW32} -O2 -nostdlib -fno-stack-protector -fno-builtin -DRAVEN_PHASE=${PHASE}
                            -Wl,--entry,_raven_entry,--no-insert-timestamp
                            -o ${CMAKE_CURRENT_BINARY_DIR}/x86-registry-${PHASE}.exe ${LOADER_SOURCES}/x86_registry_client.c -ladvapi32 -lkernel32
                        DEPENDS ${LOADER_SOURCES}/x86_registry_client.c VERBATIM)
                endforeach()
                add_custom_target(x86_registry_fixtures ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/x86-registry-1.exe ${CMAKE_CURRENT_BINARY_DIR}/x86-registry-2.exe)
                add_test(NAME native_x86_registry COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/native-x86-registry.py
                    $<TARGET_FILE:raven> ${CMAKE_CURRENT_BINARY_DIR}/x86-registry-1.exe ${CMAKE_CURRENT_BINARY_DIR}/x86-registry-2.exe
                    ${CMAKE_CURRENT_BINARY_DIR}/registry-prefix)
                set_tests_properties(native_x86_registry PROPERTIES TIMEOUT 40)
                # Full application workflow: needs the Wayland presentation backend, the text engine and a headless compositor.
                find_program(RAVEN_LABWC labwc)
                find_program(RAVEN_GRIM grim)
                find_program(RAVEN_WLRCTL wlrctl)
                # Screenshot analysis needs Pillow; take the first interpreter that provides it.
                set(RAVEN_PIL_PYTHON "")
                foreach(CANDIDATE ${Python3_EXECUTABLE} /usr/bin/python3)
                    if(NOT RAVEN_PIL_PYTHON AND EXISTS ${CANDIDATE})
                        execute_process(COMMAND ${CANDIDATE} -c "import PIL" RESULT_VARIABLE CANDIDATE_RESULT OUTPUT_QUIET ERROR_QUIET)
                        if(CANDIDATE_RESULT EQUAL 0)
                            set(RAVEN_PIL_PYTHON ${CANDIDATE})
                        endif()
                    endif()
                endforeach()
                if(TARGET raven_wayland AND RAVEN_SKIA_LIBRARY AND RAVEN_LABWC AND RAVEN_GRIM AND RAVEN_WLRCTL AND RAVEN_PIL_PYTHON
                   AND EXISTS ${PROJECT_SOURCE_DIR}/testdata/winmine/WINMINE.EXE)
                    add_test(NAME native_minesweeper_workflow COMMAND ${RAVEN_PIL_PYTHON}
                        ${PROJECT_SOURCE_DIR}/scripts/native-minesweeper.py $<TARGET_FILE:raven>
                        ${PROJECT_SOURCE_DIR}/testdata/winmine/WINMINE.EXE ${CMAKE_CURRENT_BINARY_DIR}/minesweeper-evidence)
                    set_tests_properties(native_minesweeper_workflow PROPERTIES TIMEOUT 240 RESOURCE_LOCK raven_compositor)
                endif()
                # Notepad++ across three fresh processes needs the guest controls component, keyboard input and a clipboard reader as well.
                find_program(RAVEN_WTYPE wtype)
                find_program(RAVEN_WLPASTE wl-paste)
                if(TARGET raven_wayland AND RAVEN_SKIA_LIBRARY AND RAVEN_LABWC AND RAVEN_GRIM AND RAVEN_WLRCTL AND RAVEN_WTYPE AND RAVEN_WLPASTE
                   AND RAVEN_PIL_PYTHON AND RAVEN_CONTROLS_COMPONENT_DIR AND EXISTS ${PROJECT_SOURCE_DIR}/testdata/npp/notepad++.exe)
                    add_test(NAME native_notepadpp_workflow COMMAND ${RAVEN_PIL_PYTHON}
                        ${PROJECT_SOURCE_DIR}/scripts/native-npp.py $<TARGET_FILE:raven>
                        ${PROJECT_SOURCE_DIR}/testdata/npp ${CMAKE_CURRENT_BINARY_DIR}/notepadpp-evidence)
                    set_tests_properties(native_notepadpp_workflow PROPERTIES TIMEOUT 1200 RESOURCE_LOCK raven_compositor)
                endif()
                add_test(NAME native_x86_process COMMAND ${Python3_EXECUTABLE}
                    ${PROJECT_SOURCE_DIR}/scripts/native-x86-process.py $<TARGET_FILE:raven> ${CMAKE_CURRENT_BINARY_DIR}/x86-client.exe)
                set_tests_properties(native_x86_process PROPERTIES TIMEOUT 30)
                set(X86_TESTS native_x86_process native_x86_kernel_cli native_x86_resource_cli)
                foreach(CLIENT ${X86_DESKTOP_CLIENTS})
                    list(APPEND X86_TESTS native_x86_desktop_${CLIENT})
                endforeach()
                # PE32 processes always open a prefix; keep tests out of the user's home directory.
                foreach(NAME ${X86_TESTS})
                    if(TEST ${NAME})
                        set_property(TEST ${NAME} APPEND PROPERTY ENVIRONMENT RAVEN_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/x86-prefix)
                    endif()
                endforeach()
            endif()
            foreach(STATUS 0 73 256)
                add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/return-${STATUS}.exe
                    COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -DRAVEN_RETURN_STATUS=${STATUS}
                        -Wl,--entry,raven_entry,--no-insert-timestamp
                        -o ${CMAKE_CURRENT_BINARY_DIR}/return-${STATUS}.exe ${LOADER_SOURCES}/return_client.c
                    DEPENDS ${LOADER_SOURCES}/return_client.c VERBATIM)
            endforeach()
            add_custom_target(return_fixtures ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/return-0.exe
                ${CMAKE_CURRENT_BINARY_DIR}/return-73.exe ${CMAKE_CURRENT_BINARY_DIR}/return-256.exe)
            add_test(NAME native_process_return_status COMMAND ${Python3_EXECUTABLE}
                ${PROJECT_SOURCE_DIR}/scripts/native-process-status.py $<TARGET_FILE:raven> ${CMAKE_CURRENT_BINARY_DIR})
            set_tests_properties(native_process_return_status PROPERTIES TIMEOUT 30)
            add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/wsprintf.exe
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                    -Wl,--entry,raven_entry,--no-insert-timestamp
                    -o ${CMAKE_CURRENT_BINARY_DIR}/wsprintf.exe ${LOADER_SOURCES}/wsprintf_client.c -luser32 -lkernel32
                DEPENDS ${LOADER_SOURCES}/wsprintf_client.c VERBATIM)
            add_custom_target(wsprintf_fixture ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/wsprintf.exe)
            add_test(NAME native_wsprintf COMMAND raven --run-process --execution=native ${CMAKE_CURRENT_BINARY_DIR}/wsprintf.exe)
            set_tests_properties(native_wsprintf PROPERTIES TIMEOUT 30 PASS_REGULAR_EXPRESSION "Native entry returned 0 "
                ENVIRONMENT RAVEN_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/wsprintf-prefix)
            add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/display.exe
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                    -Wl,--entry,raven_entry,--no-insert-timestamp
                    -o ${CMAKE_CURRENT_BINARY_DIR}/display.exe ${LOADER_SOURCES}/display_client.c -luser32 -lkernel32
                DEPENDS ${LOADER_SOURCES}/display_client.c VERBATIM)
            add_custom_target(display_fixture ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/display.exe)
            add_test(NAME native_display_enumeration COMMAND raven --run-process --execution=native ${CMAKE_CURRENT_BINARY_DIR}/display.exe)
            set_tests_properties(native_display_enumeration PROPERTIES TIMEOUT 30 PASS_REGULAR_EXPRESSION "Native entry returned 0 "
                ENVIRONMENT RAVEN_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/display-prefix)
            add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/clipboard.exe
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                    -Wl,--entry,raven_entry,--no-insert-timestamp
                    -o ${CMAKE_CURRENT_BINARY_DIR}/clipboard.exe ${LOADER_SOURCES}/clipboard_client.c -luser32 -lkernel32
                DEPENDS ${LOADER_SOURCES}/clipboard_client.c VERBATIM)
            add_custom_target(clipboard_fixture ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/clipboard.exe)
            add_test(NAME native_clipboard_formats COMMAND raven --run-process --execution=native ${CMAKE_CURRENT_BINARY_DIR}/clipboard.exe)
            set_tests_properties(native_clipboard_formats PROPERTIES TIMEOUT 30 PASS_REGULAR_EXPRESSION "Native entry returned 0 "
                ENVIRONMENT RAVEN_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/clipboard-prefix)
            add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/legacy_file.exe
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                    -Wl,--entry,raven_entry,--no-insert-timestamp
                    -o ${CMAKE_CURRENT_BINARY_DIR}/legacy_file.exe ${LOADER_SOURCES}/legacy_file_client.c -lkernel32
                DEPENDS ${LOADER_SOURCES}/legacy_file_client.c VERBATIM)
            add_custom_target(legacy_file_fixture ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/legacy_file.exe)
            add_test(NAME native_legacy_file_api COMMAND raven --run-process --execution=native ${CMAKE_CURRENT_BINARY_DIR}/legacy_file.exe)
            set_tests_properties(native_legacy_file_api PROPERTIES TIMEOUT 30 PASS_REGULAR_EXPRESSION "Native entry returned 0 "
                ENVIRONMENT RAVEN_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/legacy-file-prefix)
            # The DXVK 64-bit DLLs are provisioned outside the tree (scripts/provision-graphics.py); the test needs a Vulkan driver too.
            set(RAVEN_DXVK_PE64_DIR "" CACHE PATH "Directory holding DXVK d3d11.dll, dxgi.dll and d3d10core.dll for 64-bit programs")
            if(RAVEN_DXVK_PE64_DIR AND EXISTS ${RAVEN_DXVK_PE64_DIR}/d3d11.dll AND TARGET vulkan_bridge_test)
                set(RAVEN_VULKAN_ICD "")
                if(EXISTS /usr/share/vulkan/icd.d/lvp_icd.json)
                    set(RAVEN_VULKAN_ICD VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.json)
                endif()
                add_test(NAME native_d3d11_triangle COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/native-d3d11.py
                    $<TARGET_FILE:raven> ${PROJECT_SOURCE_DIR}/testdata/d3d11/triangle.exe ${RAVEN_DXVK_PE64_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}/d3d11-triangle)
                # The software driver's worker threads hold allocations at exit; leak checking still covers everything else.
                set(RAVEN_LSAN LSAN_OPTIONS=suppressions=${PROJECT_SOURCE_DIR}/testdata/lsan.supp)
                set_tests_properties(native_d3d11_triangle PROPERTIES TIMEOUT 300 ENVIRONMENT "${RAVEN_VULKAN_ICD};${RAVEN_LSAN}")
                # Direct3D 12 through vkd3d-proton: device creation only (dependency path); needs its own DLL directory.
                set(RAVEN_VKD3D_PE64_DIR "" CACHE PATH "Directory holding vkd3d-proton d3d12.dll and d3d12core.dll for 64-bit programs")
                if(RAVEN_VKD3D_PE64_DIR AND EXISTS ${RAVEN_VKD3D_PE64_DIR}/d3d12core.dll)
                    add_test(NAME native_d3d12_device COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/native-d3d12.py
                        $<TARGET_FILE:raven> ${PROJECT_SOURCE_DIR}/testdata/d3d12/device.exe ${RAVEN_VKD3D_PE64_DIR} ${RAVEN_DXVK_PE64_DIR}
                        ${CMAKE_CURRENT_BINARY_DIR}/d3d12-device)
                    set_tests_properties(native_d3d12_device PROPERTIES TIMEOUT 300 ENVIRONMENT "${RAVEN_VULKAN_ICD};${RAVEN_LSAN}")
                    add_test(NAME native_d3d12_clear COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/native-d3d12-clear.py
                        $<TARGET_FILE:raven> ${PROJECT_SOURCE_DIR}/testdata/d3d12/clear.exe ${RAVEN_VKD3D_PE64_DIR} ${RAVEN_DXVK_PE64_DIR}
                        ${CMAKE_CURRENT_BINARY_DIR}/d3d12-clear)
                    set_tests_properties(native_d3d12_clear PROPERTIES TIMEOUT 300 ENVIRONMENT "${RAVEN_VULKAN_ICD};${RAVEN_LSAN}")
                    add_test(NAME native_d3d12_draw COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/native-d3d12-draw.py
                        $<TARGET_FILE:raven> ${PROJECT_SOURCE_DIR}/testdata/d3d12/draw.exe ${RAVEN_VKD3D_PE64_DIR} ${RAVEN_DXVK_PE64_DIR}
                        ${CMAKE_CURRENT_BINARY_DIR}/d3d12-draw)
                    set_tests_properties(native_d3d12_draw PROPERTIES TIMEOUT 300 ENVIRONMENT "${RAVEN_VULKAN_ICD};${RAVEN_LSAN}")
                    if(EXISTS /dev/dri/renderD128)
                        add_test(NAME native_d3d12_draw_gpu COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/native-d3d12-draw.py
                            $<TARGET_FILE:raven> ${PROJECT_SOURCE_DIR}/testdata/d3d12/draw.exe ${RAVEN_VKD3D_PE64_DIR} ${RAVEN_DXVK_PE64_DIR}
                            ${CMAKE_CURRENT_BINARY_DIR}/d3d12-draw-gpu gpu)
                        set_tests_properties(native_d3d12_draw_gpu PROPERTIES TIMEOUT 300 ENVIRONMENT "${RAVEN_LSAN}")
                    endif()
                    if(TARGET raven_wayland AND RAVEN_SKIA_LIBRARY AND RAVEN_LABWC AND RAVEN_GRIM AND RAVEN_WLRCTL AND RAVEN_PIL_PYTHON)
                        add_test(NAME native_d3d12_present COMMAND ${RAVEN_PIL_PYTHON} ${PROJECT_SOURCE_DIR}/scripts/native-d3d12-present.py
                            $<TARGET_FILE:raven> ${PROJECT_SOURCE_DIR}/testdata/d3d12/window12.exe ${RAVEN_VKD3D_PE64_DIR} ${RAVEN_DXVK_PE64_DIR}
                            ${CMAKE_CURRENT_BINARY_DIR}/d3d12-present)
                        set_tests_properties(native_d3d12_present PROPERTIES TIMEOUT 240 RESOURCE_LOCK raven_compositor ENVIRONMENT "${RAVEN_VULKAN_ICD};${RAVEN_LSAN}")
                        if(EXISTS /dev/dri/renderD128)
                            add_test(NAME native_d3d12_present_gpu COMMAND ${RAVEN_PIL_PYTHON} ${PROJECT_SOURCE_DIR}/scripts/native-d3d12-present.py
                                $<TARGET_FILE:raven> ${PROJECT_SOURCE_DIR}/testdata/d3d12/window12.exe ${RAVEN_VKD3D_PE64_DIR} ${RAVEN_DXVK_PE64_DIR}
                                ${CMAKE_CURRENT_BINARY_DIR}/d3d12-present-gpu gpu)
                            set_tests_properties(native_d3d12_present_gpu PROPERTIES TIMEOUT 240 RESOURCE_LOCK raven_compositor ENVIRONMENT "${RAVEN_LSAN}")
                        endif()
                    endif()
                    if(EXISTS /dev/dri/renderD128)
                        add_test(NAME native_d3d12_clear_gpu COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/native-d3d12-clear.py
                            $<TARGET_FILE:raven> ${PROJECT_SOURCE_DIR}/testdata/d3d12/clear.exe ${RAVEN_VKD3D_PE64_DIR} ${RAVEN_DXVK_PE64_DIR}
                            ${CMAKE_CURRENT_BINARY_DIR}/d3d12-clear-gpu gpu)
                        set_tests_properties(native_d3d12_clear_gpu PROPERTIES TIMEOUT 300 ENVIRONMENT "${RAVEN_LSAN}")
                    endif()
                    if(EXISTS /dev/dri/renderD128)
                        add_test(NAME native_d3d12_device_gpu COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/native-d3d12.py
                            $<TARGET_FILE:raven> ${PROJECT_SOURCE_DIR}/testdata/d3d12/device.exe ${RAVEN_VKD3D_PE64_DIR} ${RAVEN_DXVK_PE64_DIR}
                            ${CMAKE_CURRENT_BINARY_DIR}/d3d12-device-gpu gpu)
                        set_tests_properties(native_d3d12_device_gpu PROPERTIES TIMEOUT 300 ENVIRONMENT "${RAVEN_LSAN}")
                    endif()
                endif()
                # Presenting to a window also needs the Wayland backend, an isolated compositor and a capture tool.
                if(TARGET raven_wayland AND RAVEN_SKIA_LIBRARY AND RAVEN_LABWC AND RAVEN_GRIM AND RAVEN_WLRCTL AND RAVEN_PIL_PYTHON)
                    add_test(NAME native_d3d11_present COMMAND ${RAVEN_PIL_PYTHON} ${PROJECT_SOURCE_DIR}/scripts/native-d3d11-present.py
                        $<TARGET_FILE:raven> ${PROJECT_SOURCE_DIR}/testdata/d3d11/window.exe ${RAVEN_DXVK_PE64_DIR}
                        ${CMAKE_CURRENT_BINARY_DIR}/d3d11-present)
                    set_tests_properties(native_d3d11_present PROPERTIES TIMEOUT 240 RESOURCE_LOCK raven_compositor ENVIRONMENT "${RAVEN_VULKAN_ICD};${RAVEN_LSAN}")
                    if(EXISTS /dev/dri/renderD128)
                        add_test(NAME native_d3d11_present_gpu COMMAND ${RAVEN_PIL_PYTHON} ${PROJECT_SOURCE_DIR}/scripts/native-d3d11-present.py
                            $<TARGET_FILE:raven> ${PROJECT_SOURCE_DIR}/testdata/d3d11/window.exe ${RAVEN_DXVK_PE64_DIR}
                            ${CMAKE_CURRENT_BINARY_DIR}/d3d11-present-gpu gpu)
                        set_tests_properties(native_d3d11_present_gpu PROPERTIES TIMEOUT 240 RESOURCE_LOCK raven_compositor ENVIRONMENT "${RAVEN_LSAN}")
                    endif()
                endif()
            endif()
        endif()
        set(PARAMETER_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/parameter-fixtures)
        file(MAKE_DIRECTORY ${PARAMETER_FIXTURES})
        add_custom_command(OUTPUT ${PARAMETER_FIXTURES}/parameters.dll ${PARAMETER_FIXTURES}/parameters.a
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector -shared -DRAVEN_PARAMETER_DLL
                -Wl,--entry,DllMain,--image-base,0x188000000,--out-implib,${PARAMETER_FIXTURES}/parameters.a
                -o ${PARAMETER_FIXTURES}/parameters.dll ${LOADER_SOURCES}/process_parameters_client.c -lkernel32
            DEPENDS ${LOADER_SOURCES}/process_parameters_client.c VERBATIM)
        add_custom_command(OUTPUT ${PARAMETER_FIXTURES}/parameters.exe
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x189000000
                -o ${PARAMETER_FIXTURES}/parameters.exe ${LOADER_SOURCES}/process_parameters_client.c
                ${PARAMETER_FIXTURES}/parameters.a -lkernel32
            DEPENDS ${LOADER_SOURCES}/process_parameters_client.c ${PARAMETER_FIXTURES}/parameters.a VERBATIM)
        add_custom_target(parameter_pe_fixtures ALL DEPENDS ${PARAMETER_FIXTURES}/parameters.exe ${PARAMETER_FIXTURES}/parameters.dll)
        add_executable(process_parameters_test nt/process_parameters_test.cpp)
        target_link_libraries(process_parameters_test PRIVATE raven_cpu)
        add_dependencies(process_parameters_test parameter_pe_fixtures raven-bootstrap)
        add_test(NAME native_process_parameters COMMAND process_parameters_test $<TARGET_FILE:raven-bootstrap> ${PARAMETER_FIXTURES})
        set_tests_properties(native_process_parameters PROPERTIES TIMEOUT 30)
        find_program(RAVEN_LLD_LINK NAMES lld-link lld-link-21)
        if(RAVEN_LLD_LINK)
            execute_process(COMMAND ${RAVEN_MINGW64} -print-file-name=libkernel32.a
                OUTPUT_VARIABLE RAVEN_KERNEL32_IMPORT OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
            set(DELAY_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/delay-fixtures)
            set(DELAY_HELPER ${CMAKE_CURRENT_SOURCE_DIR}/upstream/reactos-delayimp/delayimp.c)
            add_custom_command(OUTPUT ${DELAY_FIXTURES}/helper.obj ${DELAY_FIXTURES}/client.obj ${DELAY_FIXTURES}/target.obj
                COMMAND ${CMAKE_COMMAND} -E make_directory ${DELAY_FIXTURES}
                COMMAND ${RAVEN_MINGW64} -O2 -fno-stack-protector -c ${DELAY_HELPER} -o ${DELAY_FIXTURES}/helper.obj
                COMMAND ${RAVEN_MINGW64} -O2 -fno-stack-protector -c ${LOADER_SOURCES}/delay_client.c -o ${DELAY_FIXTURES}/client.obj
                COMMAND ${RAVEN_MINGW64} -O2 -fno-stack-protector -DRAVEN_TLS_DLL -DRAVEN_TLS_DYNAMIC
                    -c ${LOADER_SOURCES}/tls_client.c -o ${DELAY_FIXTURES}/target.obj
                DEPENDS ${DELAY_HELPER} ${LOADER_SOURCES}/delay_client.c ${LOADER_SOURCES}/tls_client.c VERBATIM)
            add_custom_command(OUTPUT ${DELAY_FIXTURES}/delayed.dll ${DELAY_FIXTURES}/delayed.lib
                COMMAND ${RAVEN_LLD_LINK} /dll /entry:DllMain /nodefaultlib /base:0x190000000
                    /out:${DELAY_FIXTURES}/delayed.dll /implib:${DELAY_FIXTURES}/delayed.lib
                    /def:${LOADER_SOURCES}/delay_target.def ${DELAY_FIXTURES}/target.obj ${RAVEN_KERNEL32_IMPORT}
                DEPENDS ${DELAY_FIXTURES}/target.obj ${LOADER_SOURCES}/delay_target.def VERBATIM)
            add_custom_command(OUTPUT ${DELAY_FIXTURES}/client.exe
                COMMAND ${RAVEN_LLD_LINK} /entry:raven_entry /subsystem:console /nodefaultlib /base:0x192000000
                    /delayload:delayed.dll /out:${DELAY_FIXTURES}/client.exe
                    ${DELAY_FIXTURES}/client.obj ${DELAY_FIXTURES}/helper.obj ${DELAY_FIXTURES}/delayed.lib ${RAVEN_KERNEL32_IMPORT}
                DEPENDS ${DELAY_FIXTURES}/client.obj ${DELAY_FIXTURES}/helper.obj ${DELAY_FIXTURES}/delayed.lib VERBATIM)
            add_custom_target(delay_pe_fixtures ALL DEPENDS ${DELAY_FIXTURES}/client.exe ${DELAY_FIXTURES}/delayed.dll)
            add_executable(delay_loader_test nt/delay_loader_test.cpp)
            target_link_libraries(delay_loader_test PRIVATE raven_cpu)
            add_dependencies(delay_loader_test delay_pe_fixtures raven-bootstrap)
            add_test(NAME native_delay_loader_contract COMMAND delay_loader_test $<TARGET_FILE:raven-bootstrap> ${DELAY_FIXTURES})
            set_tests_properties(native_delay_loader_contract PROPERTIES TIMEOUT 15)
            add_test(NAME native_delay_loader_cli COMMAND raven --run-process --execution=native ${DELAY_FIXTURES}/client.exe)
            set_tests_properties(native_delay_loader_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        endif()
        find_program(RAVEN_WINDRES x86_64-w64-mingw32-windres)
        find_program(RAVEN_MINGW32 i686-w64-mingw32-gcc)
        find_program(RAVEN_WINDRES32 i686-w64-mingw32-windres)
        if(RAVEN_WINDRES)
            set(STRING_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/string-fixtures)
            add_custom_command(OUTPUT ${STRING_FIXTURES}/strings.o
                COMMAND ${CMAKE_COMMAND} -E make_directory ${STRING_FIXTURES}
                COMMAND ${RAVEN_WINDRES} ${LOADER_SOURCES}/string_resources.rc ${STRING_FIXTURES}/strings.o
                DEPENDS ${LOADER_SOURCES}/string_resources.rc VERBATIM)
            add_custom_command(OUTPUT ${STRING_FIXTURES}/client.exe ${STRING_FIXTURES}/strings.dll
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                    -Wl,--entry,raven_entry,--image-base,0x192000000
                    -o ${STRING_FIXTURES}/client.exe ${LOADER_SOURCES}/string_client.c ${STRING_FIXTURES}/strings.o -lkernel32 -luser32
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                    -Wl,--entry,0,--image-base,0x190000000
                    -o ${STRING_FIXTURES}/strings.dll ${LOADER_SOURCES}/resource_module.c ${STRING_FIXTURES}/strings.o
                DEPENDS ${STRING_FIXTURES}/strings.o ${LOADER_SOURCES}/string_client.c ${LOADER_SOURCES}/resource_module.c VERBATIM)
            add_custom_target(string_pe_fixtures ALL DEPENDS ${STRING_FIXTURES}/client.exe ${STRING_FIXTURES}/strings.dll)
            add_executable(strings_test desktop/strings_test.cpp)
            target_link_libraries(strings_test PRIVATE raven_cpu)
            add_dependencies(strings_test string_pe_fixtures raven-bootstrap)
            add_test(NAME native_string_resource_contract COMMAND strings_test $<TARGET_FILE:raven-bootstrap> ${STRING_FIXTURES})
            set_tests_properties(native_string_resource_contract PROPERTIES TIMEOUT 15)
            add_test(NAME native_string_resource_cli COMMAND raven --run-process --execution=native ${STRING_FIXTURES}/client.exe)
            set_tests_properties(native_string_resource_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
            set(RESOURCE_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/resource-fixtures)
            add_custom_command(OUTPUT ${RESOURCE_FIXTURES}/resources.o
                COMMAND ${CMAKE_COMMAND} -E make_directory ${RESOURCE_FIXTURES}
                COMMAND ${RAVEN_WINDRES} ${LOADER_SOURCES}/resources.rc ${RESOURCE_FIXTURES}/resources.o
                DEPENDS ${LOADER_SOURCES}/resources.rc VERBATIM)
            add_custom_command(OUTPUT ${RESOURCE_FIXTURES}/client.exe ${RESOURCE_FIXTURES}/resources.dll
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                    -Wl,--entry,raven_entry,--image-base,0x192000000
                    -o ${RESOURCE_FIXTURES}/client.exe ${LOADER_SOURCES}/resource_client.c ${RESOURCE_FIXTURES}/resources.o -lkernel32
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                    -Wl,--entry,0,--image-base,0x190000000
                    -o ${RESOURCE_FIXTURES}/resources.dll ${LOADER_SOURCES}/resource_module.c ${RESOURCE_FIXTURES}/resources.o
                DEPENDS ${RESOURCE_FIXTURES}/resources.o ${LOADER_SOURCES}/resource_client.c ${LOADER_SOURCES}/resource_module.c VERBATIM)
            add_custom_target(resource_pe_fixtures ALL DEPENDS ${RESOURCE_FIXTURES}/client.exe ${RESOURCE_FIXTURES}/resources.dll)
            add_executable(resources_test nt/resources_test.cpp)
            target_link_libraries(resources_test PRIVATE raven_cpu)
            add_dependencies(resources_test resource_pe_fixtures raven-bootstrap)
            add_test(NAME native_resource_contract COMMAND resources_test $<TARGET_FILE:raven-bootstrap> ${RESOURCE_FIXTURES})
            set_tests_properties(native_resource_contract PROPERTIES TIMEOUT 15)
            add_test(NAME native_resource_cli COMMAND raven --run-process --execution=native ${RESOURCE_FIXTURES}/client.exe)
            set_tests_properties(native_resource_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
            if(RAVEN_MINGW32 AND RAVEN_WINDRES32)
                add_custom_command(OUTPUT ${RESOURCE_FIXTURES}/resources32.o ${RESOURCE_FIXTURES}/client32.exe
                    COMMAND ${RAVEN_WINDRES32} ${LOADER_SOURCES}/resources.rc ${RESOURCE_FIXTURES}/resources32.o
                    COMMAND ${RAVEN_MINGW32} -O2 -nostdlib -fno-stack-protector
                        -Wl,--entry,_raven_entry -o ${RESOURCE_FIXTURES}/client32.exe
                        ${LOADER_SOURCES}/resource_client.c ${RESOURCE_FIXTURES}/resources32.o -lkernel32
                    DEPENDS ${RESOURCE_FIXTURES}/resources.o ${LOADER_SOURCES}/resource_client.c ${LOADER_SOURCES}/resources.rc VERBATIM)
                file(MAKE_DIRECTORY ${RESOURCE_FIXTURES}/x86)
                add_custom_command(OUTPUT ${RESOURCE_FIXTURES}/x86/resources.dll
                    COMMAND ${RAVEN_MINGW32} -O2 -nostdlib -shared -fno-stack-protector
                        -Wl,--entry,0 -o ${RESOURCE_FIXTURES}/x86/resources.dll
                        ${LOADER_SOURCES}/resource_module.c ${RESOURCE_FIXTURES}/resources32.o
                    DEPENDS ${RESOURCE_FIXTURES}/resources32.o ${LOADER_SOURCES}/resource_module.c VERBATIM)
                add_custom_target(resource_pe32_fixture ALL DEPENDS ${RESOURCE_FIXTURES}/client32.exe ${RESOURCE_FIXTURES}/x86/resources.dll)
                add_test(NAME native_x86_resource_cli COMMAND raven --run-process --execution=native
                    ${RESOURCE_FIXTURES}/client32.exe ${RESOURCE_FIXTURES}/x86/resources.dll)
                set_tests_properties(native_x86_resource_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
                add_executable(pe_resources_test pe/resources_test.cpp)
                target_link_libraries(pe_resources_test PRIVATE raven_pe)
                add_dependencies(pe_resources_test resource_pe_fixtures resource_pe32_fixture)
                add_test(NAME pe_resource_contract COMMAND pe_resources_test ${RESOURCE_FIXTURES}/client.exe ${RESOURCE_FIXTURES}/client32.exe)
                set_tests_properties(pe_resource_contract PROPERTIES TIMEOUT 10)
            endif()
        endif()
        set(DYNAMIC_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/dynamic-fixtures)
        file(MAKE_DIRECTORY ${DYNAMIC_FIXTURES})
        add_custom_command(OUTPUT ${DYNAMIC_FIXTURES}/tlsprobe.dll ${DYNAMIC_FIXTURES}/tlsprobe.a
            COMMAND ${CMAKE_COMMAND} -E make_directory ${DYNAMIC_FIXTURES}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                -DRAVEN_TLS_DLL -DRAVEN_TLS_DYNAMIC -Wl,--entry,DllMain,--image-base,0x190000000
                -Wl,--out-implib,${DYNAMIC_FIXTURES}/tlsprobe.a
                -o ${DYNAMIC_FIXTURES}/tlsprobe.dll ${LOADER_SOURCES}/tls_client.c -lkernel32
            DEPENDS ${LOADER_SOURCES}/tls_client.c VERBATIM)
        foreach(DYNAMIC_DLL parent reject fault loop detach_fault detach_loop)
            set(DYNAMIC_OPTIONS)
            if(DYNAMIC_DLL STREQUAL reject)
                set(DYNAMIC_OPTIONS -DRAVEN_DYNAMIC_REJECT)
            elseif(DYNAMIC_DLL STREQUAL fault)
                set(DYNAMIC_OPTIONS -DRAVEN_DYNAMIC_FAULT)
            elseif(DYNAMIC_DLL STREQUAL loop)
                set(DYNAMIC_OPTIONS -DRAVEN_DYNAMIC_LOOP)
            elseif(DYNAMIC_DLL STREQUAL detach_fault)
                set(DYNAMIC_OPTIONS -DRAVEN_DYNAMIC_DETACH_FAULT)
            elseif(DYNAMIC_DLL STREQUAL detach_loop)
                set(DYNAMIC_OPTIONS -DRAVEN_DYNAMIC_DETACH_LOOP)
            endif()
            add_custom_command(OUTPUT ${DYNAMIC_FIXTURES}/${DYNAMIC_DLL}.dll
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector ${DYNAMIC_OPTIONS}
                    -Wl,--entry,DllMain,--image-base,0x190000000
                    -o ${DYNAMIC_FIXTURES}/${DYNAMIC_DLL}.dll ${LOADER_SOURCES}/dynamic_parent.c
                    ${DYNAMIC_FIXTURES}/tlsprobe.a -lkernel32
                DEPENDS ${LOADER_SOURCES}/dynamic_parent.c ${DYNAMIC_FIXTURES}/tlsprobe.a VERBATIM)
        endforeach()
        add_custom_command(OUTPUT ${DYNAMIC_FIXTURES}/client.exe
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x192000000
                -o ${DYNAMIC_FIXTURES}/client.exe ${LOADER_SOURCES}/dynamic_client.c -lkernel32
            DEPENDS ${LOADER_SOURCES}/dynamic_client.c VERBATIM)
        add_custom_target(dynamic_pe_fixtures ALL DEPENDS ${DYNAMIC_FIXTURES}/client.exe
            ${DYNAMIC_FIXTURES}/tlsprobe.dll ${DYNAMIC_FIXTURES}/parent.dll ${DYNAMIC_FIXTURES}/reject.dll
            ${DYNAMIC_FIXTURES}/fault.dll ${DYNAMIC_FIXTURES}/loop.dll ${DYNAMIC_FIXTURES}/failure.exe
            ${DYNAMIC_FIXTURES}/detach_fault.dll ${DYNAMIC_FIXTURES}/detach_loop.dll)
        add_custom_command(OUTPUT ${DYNAMIC_FIXTURES}/failure.exe
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x192000000
                -o ${DYNAMIC_FIXTURES}/failure.exe ${LOADER_SOURCES}/dynamic_failure.c -lkernel32
            DEPENDS ${LOADER_SOURCES}/dynamic_failure.c VERBATIM)
        add_executable(dynamic_loader_test nt/dynamic_loader_test.cpp)
        target_link_libraries(dynamic_loader_test PRIVATE raven_cpu)
        add_dependencies(dynamic_loader_test dynamic_pe_fixtures raven-bootstrap)
        add_test(NAME native_dynamic_loader_contract COMMAND dynamic_loader_test $<TARGET_FILE:raven-bootstrap> ${DYNAMIC_FIXTURES})
        set_tests_properties(native_dynamic_loader_contract PROPERTIES TIMEOUT 15)
        add_test(NAME native_dynamic_loader_cli COMMAND raven --run-process --execution=native ${DYNAMIC_FIXTURES}/client.exe)
        set_tests_properties(native_dynamic_loader_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        set(TLS_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/tls-fixtures)
        set(TLS_FILES)
        foreach(TLS_VARIANT standard aligned collision)
            set(TLS_DLL_BASE 0x190000000)
            if(TLS_VARIANT STREQUAL standard)
                set(TLS_OUTPUT ${TLS_FIXTURES})
                set(TLS_OPTIONS)
            elseif(TLS_VARIANT STREQUAL aligned)
                set(TLS_OUTPUT ${TLS_FIXTURES}/aligned)
                set(TLS_OPTIONS -DRAVEN_TLS_ALIGNMENT=8192 -DRAVEN_TLS_ALIGN_FLAG=IMAGE_SCN_ALIGN_8192BYTES)
            else()
                set(TLS_OUTPUT ${TLS_FIXTURES}/collision)
                set(TLS_DLL_BASE 0x192000000)
                set(TLS_OPTIONS)
            endif()
            add_custom_command(OUTPUT ${TLS_OUTPUT}/tlsprobe.dll ${TLS_OUTPUT}/tlsprobe.a
                COMMAND ${CMAKE_COMMAND} -E make_directory ${TLS_OUTPUT}
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector -DRAVEN_TLS_DLL ${TLS_OPTIONS}
                    -Wl,--entry,DllMain,--image-base,${TLS_DLL_BASE} -Wl,--out-implib,${TLS_OUTPUT}/tlsprobe.a
                    -o ${TLS_OUTPUT}/tlsprobe.dll ${LOADER_SOURCES}/tls_client.c -lkernel32
                DEPENDS ${LOADER_SOURCES}/tls_client.c VERBATIM)
            add_custom_command(OUTPUT ${TLS_OUTPUT}/client.exe
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector ${TLS_OPTIONS}
                    -Wl,--entry,raven_entry,--image-base,0x192000000
                    -o ${TLS_OUTPUT}/client.exe ${LOADER_SOURCES}/tls_client.c ${TLS_OUTPUT}/tlsprobe.a -lkernel32
                DEPENDS ${LOADER_SOURCES}/tls_client.c ${TLS_OUTPUT}/tlsprobe.a VERBATIM)
            list(APPEND TLS_FILES ${TLS_OUTPUT}/client.exe ${TLS_OUTPUT}/tlsprobe.dll)
        endforeach()
        add_custom_target(tls_pe_fixtures DEPENDS ${TLS_FILES})
        add_executable(tls_test nt/tls_test.cpp)
        target_link_libraries(tls_test PRIVATE raven_cpu)
        add_dependencies(tls_test tls_pe_fixtures raven-bootstrap)
        add_test(NAME native_static_tls COMMAND tls_test $<TARGET_FILE:raven-bootstrap> ${TLS_FIXTURES} ${TLS_FIXTURES}/aligned ${TLS_FIXTURES}/collision)
        set_tests_properties(native_static_tls PROPERTIES TIMEOUT 20)
        add_test(NAME native_static_tls_cli COMMAND raven --run-process --execution=native
            ${TLS_FIXTURES}/client.exe ${TLS_FIXTURES}/tlsprobe.dll)
        set_tests_properties(native_static_tls_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        add_test(NAME native_collision_cli COMMAND raven --run-process --execution=native
            ${TLS_FIXTURES}/collision/client.exe ${TLS_FIXTURES}/collision/tlsprobe.dll)
        set_tests_properties(native_collision_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        add_custom_command(OUTPUT ${MODULE_FIXTURES}/target.dll
            COMMAND ${CMAKE_COMMAND} -E make_directory ${MODULE_FIXTURES}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                -Wl,--entry,0,--image-base,0x180000000 -o ${MODULE_FIXTURES}/target.dll
                ${LOADER_SOURCES}/target.c ${LOADER_SOURCES}/target.def
            DEPENDS ${LOADER_SOURCES}/target.c ${LOADER_SOURCES}/target.def VERBATIM)
        add_custom_command(OUTPUT ${MODULE_FIXTURES}/facade.dll ${MODULE_FIXTURES}/facade.a
            COMMAND ${CMAKE_COMMAND} -E make_directory ${MODULE_FIXTURES}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                -Wl,--entry,0,--image-base,0x180100000 -Wl,--out-implib,${MODULE_FIXTURES}/facade.a
                -o ${MODULE_FIXTURES}/facade.dll ${LOADER_SOURCES}/target.c ${LOADER_SOURCES}/facade.def
            DEPENDS ${LOADER_SOURCES}/target.c ${LOADER_SOURCES}/facade.def VERBATIM)
        add_custom_command(OUTPUT ${MODULE_FIXTURES}/client.exe
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x188000000
                -o ${MODULE_FIXTURES}/client.exe ${CALLBACK_SOURCES}/module_api_client.c
                ${MODULE_FIXTURES}/facade.a -lkernel32
            DEPENDS ${CALLBACK_SOURCES}/module_api_client.c ${MODULE_FIXTURES}/facade.a VERBATIM)
        add_custom_target(module_api_pe_fixtures ALL DEPENDS ${MODULE_FIXTURES}/client.exe
            ${MODULE_FIXTURES}/facade.dll ${MODULE_FIXTURES}/target.dll)
        add_test(NAME native_module_api_cli COMMAND raven --run-process --execution=native
            ${MODULE_FIXTURES}/client.exe ${MODULE_FIXTURES}/facade.dll ${MODULE_FIXTURES}/target.dll)
        set_tests_properties(native_module_api_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")

        set(LIFECYCLE_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/lifecycle-fixtures)
        add_custom_command(OUTPUT ${LIFECYCLE_FIXTURES}/base.dll ${LIFECYCLE_FIXTURES}/base.a
            COMMAND ${CMAKE_COMMAND} -E make_directory ${LIFECYCLE_FIXTURES}
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                -Wl,--entry,DllMain,--image-base,0x18a000000 -Wl,--out-implib,${LIFECYCLE_FIXTURES}/base.a
                -o ${LIFECYCLE_FIXTURES}/base.dll ${LOADER_SOURCES}/lifecycle_base.c -lkernel32
            DEPENDS ${LOADER_SOURCES}/lifecycle_base.c VERBATIM)
        add_custom_command(OUTPUT ${LIFECYCLE_FIXTURES}/dependent.dll ${LIFECYCLE_FIXTURES}/dependent.a
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                -Wl,--entry,DllMain,--image-base,0x18b000000 -Wl,--out-implib,${LIFECYCLE_FIXTURES}/dependent.a
                -o ${LIFECYCLE_FIXTURES}/dependent.dll ${LOADER_SOURCES}/lifecycle_dependent.c
                ${LIFECYCLE_FIXTURES}/base.a -lkernel32
            DEPENDS ${LOADER_SOURCES}/lifecycle_dependent.c ${LIFECYCLE_FIXTURES}/base.a VERBATIM)
        add_custom_command(OUTPUT ${LIFECYCLE_FIXTURES}/client.exe
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x18d000000
                -o ${LIFECYCLE_FIXTURES}/client.exe ${LOADER_SOURCES}/lifecycle_client.c
                ${LIFECYCLE_FIXTURES}/base.a ${LIFECYCLE_FIXTURES}/dependent.a -lkernel32
            DEPENDS ${LOADER_SOURCES}/lifecycle_client.c ${LIFECYCLE_FIXTURES}/base.a
                ${LIFECYCLE_FIXTURES}/dependent.a VERBATIM)
        set(REJECTION_FILES)
        foreach(REJECTION reject fault loop)
            if(REJECTION STREQUAL reject)
                set(REJECTION_MODE 1)
            elseif(REJECTION STREQUAL fault)
                set(REJECTION_MODE 2)
            else()
                set(REJECTION_MODE 3)
            endif()
            add_custom_command(OUTPUT ${LIFECYCLE_FIXTURES}/${REJECTION}.dll
                COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                    -DRAVEN_LOADER_MODE=${REJECTION_MODE} -Wl,--entry,DllMain,--image-base,0x18c000000
                    -o ${LIFECYCLE_FIXTURES}/${REJECTION}.dll ${LOADER_SOURCES}/lifecycle_reject.c ${LIFECYCLE_FIXTURES}/base.a
                DEPENDS ${LOADER_SOURCES}/lifecycle_reject.c ${LIFECYCLE_FIXTURES}/base.a VERBATIM)
            list(APPEND REJECTION_FILES ${LIFECYCLE_FIXTURES}/${REJECTION}.dll)
        endforeach()
        add_custom_target(lifecycle_pe_fixtures DEPENDS ${LIFECYCLE_FIXTURES}/client.exe
            ${LIFECYCLE_FIXTURES}/base.dll ${LIFECYCLE_FIXTURES}/dependent.dll ${REJECTION_FILES})
        add_executable(loader_test nt/loader_test.cpp)
        target_link_libraries(loader_test PRIVATE raven_cpu)
        add_dependencies(loader_test lifecycle_pe_fixtures raven-bootstrap)
        add_test(NAME native_dll_lifecycle COMMAND loader_test $<TARGET_FILE:raven-bootstrap> ${LIFECYCLE_FIXTURES})
        set_tests_properties(native_dll_lifecycle PROPERTIES TIMEOUT 15)
        add_test(NAME native_dll_cli COMMAND raven --run-process --execution=native
            ${LIFECYCLE_FIXTURES}/client.exe ${LIFECYCLE_FIXTURES}/dependent.dll ${LIFECYCLE_FIXTURES}/base.dll)
        set_tests_properties(native_dll_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
        add_custom_command(OUTPUT ${LIFECYCLE_FIXTURES}/forward.dll ${LIFECYCLE_FIXTURES}/forward.a ${LIFECYCLE_FIXTURES}/forward-client.exe
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -shared -fno-stack-protector
                -Wl,--entry,0,--image-base,0x1c7000000,--no-insert-timestamp
                -Wl,--out-implib,${LIFECYCLE_FIXTURES}/forward.a
                -o ${LIFECYCLE_FIXTURES}/forward.dll ${LOADER_SOURCES}/startup_forward.c ${LOADER_SOURCES}/startup_forward.def
            COMMAND ${RAVEN_MINGW64} -O2 -nostdlib -fno-stack-protector
                -Wl,--entry,raven_entry,--image-base,0x1c8000000,--no-insert-timestamp
                -o ${LIFECYCLE_FIXTURES}/forward-client.exe ${LOADER_SOURCES}/startup_forward_client.c ${LIFECYCLE_FIXTURES}/forward.a
            DEPENDS ${LOADER_SOURCES}/startup_forward.c ${LOADER_SOURCES}/startup_forward.def
                ${LOADER_SOURCES}/startup_forward_client.c VERBATIM)
        add_custom_target(startup_forward_fixture ALL DEPENDS ${LIFECYCLE_FIXTURES}/forward.dll ${LIFECYCLE_FIXTURES}/forward-client.exe)
        add_executable(dependencies_test nt/dependencies_test.cpp)
        target_link_libraries(dependencies_test PRIVATE raven_cpu)
        add_dependencies(dependencies_test lifecycle_pe_fixtures startup_forward_fixture raven-bootstrap)
        if(TARGET resource_pe32_fixture)
            add_dependencies(dependencies_test resource_pe32_fixture)
            add_test(NAME native_initial_dependency_contract COMMAND dependencies_test $<TARGET_FILE:raven-bootstrap>
                ${LIFECYCLE_FIXTURES} ${RESOURCE_FIXTURES}/client32.exe)
        else()
            add_test(NAME native_initial_dependency_contract COMMAND dependencies_test $<TARGET_FILE:raven-bootstrap> ${LIFECYCLE_FIXTURES})
        endif()
        add_test(NAME native_initial_dependency_cli COMMAND raven --run-process --execution=native ${LIFECYCLE_FIXTURES}/client.exe)
        add_test(NAME native_initial_forwarder_cli COMMAND raven --run-process --execution=native ${LIFECYCLE_FIXTURES}/forward-client.exe)
        set_tests_properties(native_initial_dependency_contract PROPERTIES TIMEOUT 15)
        set_tests_properties(native_initial_dependency_cli native_initial_forwarder_cli PROPERTIES TIMEOUT 15 PASS_REGULAR_EXPRESSION "Native entry returned 0 ")
    endif()
endif()
