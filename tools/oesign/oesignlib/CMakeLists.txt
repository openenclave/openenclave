##==============================================================================
##
## Build a library out of the oesign sources so that apps can link it and
## override the weak form of main().
##
##==============================================================================

include(CheckSymbolExists)

list(
  APPEND
  SOURCES
  main.c
  ../oe_err.c
  ../oe_err.c
  ../oedump.c
  ../oeinfo.c
  ../oesign.c)

if (WITH_EEID)
  list(APPEND SOURCES ../oedump_eeid.c)
endif ()

check_symbol_exists(getopt_long getopt.h HAVE_GETOPT_LONG)

if (NOT HAVE_GETOPT_LONG)
  list(APPEND SOURCES ../getopt_long.c)
endif ()

add_library(oesignlib ${SOURCES})

target_compile_options(oesignlib PRIVATE -fPIC)

if (NOT HAVE_GETOPT_LONG)
  target_include_directories(oesignlib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
endif ()

set_target_properties(oesignlib PROPERTIES OUTPUT_NAME oesign)

target_link_libraries(oesignlib PRIVATE oe_includes)

set_property(TARGET oesignlib PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

install(
  TARGETS oesignlib
  EXPORT openenclave-targets
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)

if (WITH_EEID)
  target_compile_definitions(oesignlib PRIVATE OE_WITH_EXPERIMENTAL_EEID)
endif ()
