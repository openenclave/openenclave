# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT all_u.h all_u.c all_args.h
  DEPENDS edger8r
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
          ../edl/switchless.edl
  COMMAND
    edger8r --experimental --untrusted --search-path
    ${CMAKE_CURRENT_SOURCE_DIR}/../edl --search-path
    ${CMAKE_CURRENT_SOURCE_DIR}/../moreedl all.edl)

add_custom_command(
  OUTPUT bar_u.h bar_args.h
  DEPENDS ../moreedl/bar.edl
  COMMAND edger8r --untrusted --header-only --search-path
          ${CMAKE_CURRENT_SOURCE_DIR}/../moreedl bar.edl)

add_custom_command(
  OUTPUT other_u.h other_u.c other_args.h
  DEPENDS ../edl/other.edl
  COMMAND edger8r --untrusted --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../edl
          other.edl)

# Dummy target used for generating from EDL on demand.
add_custom_target(
  edl_host_gen
  DEPENDS all_u.h
          all_u.c
          all_args.h
          bar_u.h
          bar_args.h
          other_u.h
          other_u.c
          other_args.h)

add_executable(
  edl_host
  all_u.c
  bar_u.h
  other_u.c
  main.cpp
  bar.cpp
  foo.cpp
  testarray.cpp
  testbasic.cpp
  testdeepcopy.cpp
  testenum.cpp
  testerrno.cpp
  testforeign.cpp
  testother.cpp
  testpointer.cpp
  teststring.cpp
  teststruct.cpp
  testswitchless.cpp)

# The tests intentionally use floats etc in size context.
# Disable warnings.
if (CMAKE_CXX_COMPILER_ID MATCHES GNU OR CMAKE_CXX_COMPILER_ID MATCHES Clang)
  set_source_files_properties(all_u.c PROPERTIES COMPILE_FLAGS
                                                 "-Wno-conversion")
  set_source_files_properties(testpointer.cpp teststring.cpp
                              PROPERTIES COMPILE_FLAGS "-Wno-unused-parameter")
endif ()

target_include_directories(edl_host PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
                                           ${CMAKE_CURRENT_SOURCE_DIR}/..)
if (NOT WIN32)
  # Re-enable strict aliasing. TODO: Remove this when #1717 is resolved.
  target_compile_options(edl_host PUBLIC -fstrict-aliasing
                                         -Werror=strict-aliasing)
endif ()
target_link_libraries(edl_host oehost)
