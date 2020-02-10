# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_library(gcda STATIC
  src/GCDAProfiling.c
  src/InstrProfiling.c
  src/InstrProfilingUtil.c)

maybe_build_using_clangw(gcda)

target_compile_options(gcda PRIVATE -Wno-error)

target_link_libraries(gcda PUBLIC oelibc)

target_include_directories(gcda PRIVATE src)

#install(TARGETS gcda EXPORT openenclave-targets)

install(TARGETS gcda
    EXPORT openenclave-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
