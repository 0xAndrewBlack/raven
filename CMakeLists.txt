cmake_minimum_required(VERSION 3.20)
project(Raven LANGUAGES C CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "The native Raven runtime currently requires Linux")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(RAVEN_SANITIZERS "Enable address and undefined behavior checks" OFF)
if(RAVEN_SANITIZERS)
    # The Skia library is built without RTTI, so dynamic type checks cannot apply to code that links it.
    add_compile_options(-fsanitize=address,undefined -fno-sanitize=vptr -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

enable_testing()
add_subdirectory(native)
