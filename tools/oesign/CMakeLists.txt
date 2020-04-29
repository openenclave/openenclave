# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(CheckSymbolExists)

list(APPEND SOURCES main.c oedump.c)

CHECK_SYMBOL_EXISTS(getopt_long getopt.h HAVE_GETOPT_LONG)

if (NOT HAVE_GETOPT_LONG)
  list (APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/getopt_long.c)
endif()

add_executable(oesign ${SOURCES})

if (NOT HAVE_GETOPT_LONG)
  target_include_directories(oesign PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# Link oesign against liboehostmr, which has no dependency on
# lib_sgx_enclave_common and libsgx_dcap_ql.
target_link_libraries(oesign oehostmr)

# assemble into proper collector dir
set_property(TARGET oesign PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install(TARGETS oesign EXPORT openenclave-targets DESTINATION ${CMAKE_INSTALL_BINDIR})
