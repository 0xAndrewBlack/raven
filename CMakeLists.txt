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
find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_program(RAVEN_FIXTURE_CC x86_64-w64-mingw32-gcc)
set(RAVEN_TESTDATA_DIR "${CMAKE_BINARY_DIR}/testdata" CACHE PATH "Generated and downloaded test fixtures")
set(RAVEN_MINESWEEPER "" CACHE FILEPATH "Optional user-supplied Minesweeper executable")
if(RAVEN_FIXTURE_CC)
    set(FIXTURE_ARGUMENTS --cc ${RAVEN_FIXTURE_CC})
else()
    set(FIXTURE_ARGUMENTS --data-only)
endif()
execute_process(COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/provision-fixtures.py
    --output ${RAVEN_TESTDATA_DIR} ${FIXTURE_ARGUMENTS} RESULT_VARIABLE FIXTURE_RESULT)
if(NOT FIXTURE_RESULT EQUAL 0)
    message(FATAL_ERROR "Test fixture provisioning failed")
endif()
add_subdirectory(native)
