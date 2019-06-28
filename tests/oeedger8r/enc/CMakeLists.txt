# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT all_t.h all_t.c all_args.h
  DEPENDS
  edger8r
  ../edl/aliasing.edl
  ../edl/all.edl
  ../edl/array.edl
  ../edl/basic.edl
  ../edl/deepcopy.edl
  ../edl/enum.edl
  ../edl/errno.edl
  ../edl/foreign.edl
  ../edl/other.edl
  ../edl/pointer.edl
  ../edl/string.edl
  ../edl/struct.edl
  COMMAND edger8r --experimental --trusted --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../edl --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../moreedl all.edl)

# Dummy target used for generating from EDL on demand.
add_custom_target(edl_enc_trusted DEPENDS all_t.h all_t.c all_args.h)

add_custom_command(
  OUTPUT bar_t.h bar_args.h
  DEPENDS ../moreedl/bar.edl
  COMMAND edger8r --trusted --header-only --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../moreedl bar.edl)

add_enclave(TARGET edl_enc UUID e71cbbea-a638-4653-b46e-2e58a2ca3408 CXX
    SOURCES
    all_t.c
    bar_t.h
    bar.cpp
    config.cpp
    foo.cpp

    testaliasing.cpp
    testarray.cpp
    testbasic.cpp
    testdeepcopy.cpp
    testenum.cpp
    testerrno.cpp
    testforeign.cpp
    testpointer.cpp
    teststring.cpp
    teststruct.cpp)

# The tests intentionally use floats etc in size context.
# Disable warnings.
if (CMAKE_CXX_COMPILER_ID MATCHES GNU OR CMAKE_CXX_COMPILER_ID MATCHES Clang OR USE_CLANGW)
    set_source_files_properties(
        all_t.c
        PROPERTIES COMPILE_FLAGS "-Wno-conversion"
    )
    set_source_files_properties(
        testpointer.cpp
        teststring.cpp
        PROPERTIES COMPILE_FLAGS "-Wno-unused-parameter"
    )      
endif()

target_include_directories(edl_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..)
if (NOT WIN32)
  # Re-enable strict aliasing. TODO: Remove this when #1717 is resolved.
  target_compile_options(edl_enc PUBLIC -fstrict-aliasing -Werror=strict-aliasing)
endif ()

# This is a separate enclave specifically shared with the same host.
oeedl_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../edl/other.edl
    enclave
    other_t
)

add_enclave(TARGET edl_other_enc UUID 6d92103c-1a1c-48b7-a469-f455acef249e CXX SOURCES testother.cpp ${other_t})
target_include_directories(edl_other_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..)
