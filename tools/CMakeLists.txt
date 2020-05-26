# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (USE_CPP_EDGER8R)
  check_submodule_not_empty(oeedger8r-cpp)
  set(USE_OEEDGER8R_CPP_AS_SUBMODULE on)
  add_subdirectory(oeedger8r-cpp)
  add_executable(edger8r ALIAS oeedger8r)
  install(
    TARGETS oeedger8r
    EXPORT openenclave-targets
    DESTINATION ${CMAKE_INSTALL_BINDIR})
else ()
  add_subdirectory(oeedger8r)
endif ()

if (OE_SGX)
  add_subdirectory(oesgx)
  add_subdirectory(oesign)
endif ()
