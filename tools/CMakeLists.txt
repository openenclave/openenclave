# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

check_submodule_not_empty(oeedger8r-cpp)

# oeedger8r-cpp is built as an external project.
# This ensures that when targeting OE_TRUSTZONE, oeedger8r-cpp itself
# is not cross-compiled. Otherwise the generated ARM binary will not
# be executable on the x64 host.
# BUILD_ALWAYS is set to on so that any source code change to oeedger8r-cpp
# would trigger a rebuild.
include(ExternalProject)
set(BINARY
    ${CMAKE_CURRENT_BINARY_DIR}/oeedger8r-cpp/oeedger8r${CMAKE_EXECUTABLE_SUFFIX}
)

ExternalProject_Add(
  oeedger8r-cpp
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/oeedger8r-cpp
  BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/oeedger8r-cpp
  CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
  BUILD_ALWAYS on
  TEST_BEFORE_INSTALL on
  INSTALL_COMMAND ""
  BUILD_BYPRODUCTS ${BINARY})

# edger8r is the target used to refer to oeedger8r-cpp in rest of the SDK.
add_executable(edger8r IMPORTED GLOBAL)
set_target_properties(edger8r PROPERTIES IMPORTED_LOCATION ${BINARY})
add_custom_target(oeedger8r_target DEPENDS ${BINARY} oeedger8r-cpp)
add_dependencies(edger8r oeedger8r_target)

# Can't use `install(TARGETS)` on an imported executable, because it
# causes CMake to crash. Instead, see `openenclave-config.cmake.in`
# for the manual "export" of this target.
install(
  PROGRAMS ${BINARY}
  RENAME oeedger8r${CMAKE_EXECUTABLE_SUFFIX}
  DESTINATION ${CMAKE_INSTALL_BINDIR})

if (OE_SGX)
  add_subdirectory(oesgx)
  add_subdirectory(oesign)
endif ()
