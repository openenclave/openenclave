# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../module_loading.edl)

add_custom_command(
  OUTPUT module_loading_t.h module_loading_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave_library(module_loading_common OBJECT enc.c
                    ${CMAKE_CURRENT_BINARY_DIR}/module_loading_t.c)
enclave_include_directories(module_loading_common PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(module_loading_common oelibc oe_includes)
maybe_build_using_clangw(module_loading_common)

# Add the enclave for postive tests
add_enclave(TARGET module_loading_enc)
maybe_build_using_clangw(module_loading_enc)
add_enclave_dependencies(module_loading_enc module_loading_common module)
if (UNIX)
  enclave_link_libraries(module_loading_enc module_loading_common module)
elseif (WIN32)
  # On Windows, a shared library is assumed to be a .dll file that cannot be
  # directly linked against. Therefore, we mimic the Linux linking behavior
  # by treating the .so file as a static, imported library.
  add_enclave_library(module_so STATIC IMPORTED)
  set_property(
    TARGET module_so PROPERTY IMPORTED_LOCATION
                              ${CMAKE_CURRENT_BINARY_DIR}/libmodule.so)
  if (LVI_MITIGATION MATCHES ControlFlow)
    add_enclave_dependencies(module_loading_enc module-lvi-cfg)
    set_property(
      TARGET module_so-lvi-cfg
      PROPERTY IMPORTED_LOCATION
               ${CMAKE_CURRENT_BINARY_DIR}/libmodule-lvi-cfg.so)
  endif ()
  enclave_link_libraries(module_loading_enc module_loading_common module_so)
endif ()

# Add the enclave for the negative test of linking more than one modules
add_enclave(TARGET module_loading_negative_extra_enc)
maybe_build_using_clangw(module_loading_negative_extra_enc)
add_enclave_dependencies(module_loading_negative_extra_enc module
                         module_negative_extra)
if (UNIX)
  enclave_link_libraries(module_loading_negative_extra_enc
                         module_loading_common module module_negative_extra)
elseif (WIN32)
  # Mimic the Linux linking behavior by treating the .so file as a static, imported library
  add_enclave_library(module_negative_extra_so STATIC IMPORTED)
  set_property(
    TARGET module_negative_extra_so
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_BINARY_DIR}/libmodule_negative_extra.so)
  if (LVI_MITIGATION MATCHES ControlFlow)
    add_enclave_dependencies(module_loading_negative_extra_enc
                             module_negative_extra-lvi-cfg)
    set_property(
      TARGET module_negative_extra_so-lvi-cfg
      PROPERTY IMPORTED_LOCATION
               ${CMAKE_CURRENT_BINARY_DIR}/libmodule_negative_extra-lvi-cfg.so)
  endif ()
  enclave_link_libraries(
    module_loading_negative_extra_enc module_loading_common module_so
    module_negative_extra_so)
endif ()

# Add the enclave for the negative test of loading module from a wrong path
add_enclave(TARGET module_loading_negative_path_enc)
maybe_build_using_clangw(module_loading_negative_path_enc)
add_enclave_dependencies(module_loading_negative_path_enc module)
# Generate the enclave binary in the different directory from the module
set_enclave_properties(
  module_loading_negative_path_enc PROPERTIES RUNTIME_OUTPUT_DIRECTORY
  "${CMAKE_CURRENT_BINARY_DIR}/..")
if (UNIX)
  enclave_link_libraries(module_loading_negative_path_enc module_loading_common
                         module)
elseif (WIN32)
  enclave_link_libraries(module_loading_negative_path_enc module_loading_common
                         module_so)
endif ()

# Add the enclave for the negative test of using RPATH
add_enclave(TARGET module_loading_negative_rpath_enc)
maybe_build_using_clangw(module_loading_negative_rpath_enc)
add_enclave_dependencies(module_loading_negative_rpath_enc module)
if (UNIX)
  enclave_link_libraries(module_loading_negative_rpath_enc
                         module_loading_common module)
elseif (WIN32)
  enclave_link_libraries(module_loading_negative_rpath_enc
                         module_loading_common module_so)
endif ()
enclave_link_libraries(
  module_loading_negative_rpath_enc
  -Wl,-rpath=${CMAKE_CURRENT_BINARY_DIR},--disable-new-dtags)

# Add the enclave for the negative test of using RUNPATH
add_enclave(TARGET module_loading_negative_runpath_enc)
maybe_build_using_clangw(module_loading_negative_runpath_enc)
add_enclave_dependencies(module_loading_negative_runpath_enc module)
if (UNIX)
  enclave_link_libraries(module_loading_negative_runpath_enc
                         module_loading_common module)
elseif (WIN32)
  enclave_link_libraries(module_loading_negative_runpath_enc
                         module_loading_common module_so)
endif ()
enclave_link_libraries(
  module_loading_negative_runpath_enc
  -Wl,-rpath=${CMAKE_CURRENT_BINARY_DIR},--enable-new-dtags)
