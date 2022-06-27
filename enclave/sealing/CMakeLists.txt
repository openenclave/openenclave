# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

macro (add_seal_plugin NAME)
  add_enclave_library(${NAME} OBJECT ${ARGN})
  enclave_include_directories(${NAME} PRIVATE
                              ${CMAKE_SOURCE_DIR}/include/openenclave/corelibc)
  enclave_link_libraries(${NAME} PRIVATE oe_includes)

  install_enclaves(
    TARGETS
    ${NAME}
    EXPORT
    openenclave-targets
    OBJECTS
    DESTINATION
    ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
endmacro ()

if (OE_SGX)
  add_subdirectory(sgx)
endif ()
