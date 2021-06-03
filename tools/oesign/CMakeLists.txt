# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(CheckSymbolExists)

list(
  APPEND
  SOURCES
  main.c
  oe_err.c
  oedump.c
  oeinfo.c
  oesign.c)

if (WITH_EEID)
  list(APPEND SOURCES oedump_eeid.c)
endif ()

check_symbol_exists(getopt_long getopt.h HAVE_GETOPT_LONG)

if (NOT HAVE_GETOPT_LONG)
  list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/getopt_long.c)
endif ()

add_executable(oesign ${SOURCES})

target_compile_options(oesign PRIVATE -fPIC)

if (NOT HAVE_GETOPT_LONG)
  target_include_directories(oesign PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif ()

# Link oesign against liboehostmr, which has no dependency on
# lib_sgx_enclave_common and libsgx_dcap_ql.
target_link_libraries(oesign oehostmr)

# assemble into proper collector dir
set_property(TARGET oesign PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

if (WIN32)
  set_target_properties(oesign PROPERTIES LINK_FLAGS "/Guard:CF")
endif ()

# install rule
install(
  TARGETS oesign
  EXPORT openenclave-targets
  DESTINATION ${CMAKE_INSTALL_BINDIR})

if (WITH_EEID)
  target_compile_definitions(oesign PRIVATE OE_WITH_EXPERIMENTAL_EEID)
endif ()

##==============================================================================
##
## Build a library out of the oesign sources so that apps can link it and
## override the weak form of main().
##
##==============================================================================

add_library(oesignlib ${SOURCES})

target_compile_options(oesignlib PRIVATE -fPIC)

set_target_properties(oesignlib PROPERTIES OUTPUT_NAME oesign)

if (NOT HAVE_GETOPT_LONG)
  target_include_directories(oesignlib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif ()

target_link_libraries(oesignlib PRIVATE oe_includes)

set_property(TARGET oesignlib PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

install(
  TARGETS oesignlib
  EXPORT openenclave-targets
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host
  RENAME xyz)

if (WITH_EEID)
  target_compile_definitions(oesignlib PRIVATE OE_WITH_EXPERIMENTAL_EEID)
endif ()
