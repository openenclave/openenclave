# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (UNIX)
  find_package(OpenSSL REQUIRED)
endif ()

add_custom_command(
  OUTPUT oeutil_u.h oeutil_u.c oeutil_args.h
  DEPENDS ../oeutil.edl edger8r
  COMMAND edger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../oeutil.edl
          --search-path ${PROJECT_SOURCE_DIR}/include -DOE_SGX)

add_executable(oeutil host.cpp generate_evidence.cpp get_endorsements.cpp
                      get_fmspc.cpp ${CMAKE_CURRENT_BINARY_DIR}/ oeutil_u.c)

add_dependencies(oeutil enclave_key_pair)

target_include_directories(oeutil PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oeutil oehost_prerelease_test)

if (UNIX)
  target_link_libraries(oeutil OpenSSL::SSL)
endif ()

# To enable oeutil to load any public key
target_compile_definitions(oeutil PUBLIC OEUTIL_TCB_ALLOW_ANY_ROOT_KEY
                                         OEUTIL_QUOTE_BYPASS_DATE_CHECK)

if (WIN32)
  if (MSVC)
    target_compile_options(oeutil PRIVATE /guard:cf)
    set_target_properties(oeutil PROPERTIES LINK_FLAGS "/Guard:CF")
  endif ()
endif ()

# Generate the oeutil binary in the the same directory with enclave binary
set_target_properties(oeutil PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

install(
  TARGETS oeutil
  EXPORT openenclave-targets
  DESTINATION ${CMAKE_INSTALL_BINDIR})
