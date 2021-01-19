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
    ${CMAKE_CURRENT_BINARY_DIR}/oeedger8r-cpp/src/oeedger8r${CMAKE_EXECUTABLE_SUFFIX}
)

if (OE_SGX)
  # For SGX, use the same compilers as OE SDK.
  set(EDGER8R_C_COMPILER ${CMAKE_C_COMPILER})
  set(EDGER8R_CXX_COMPILER ${CMAKE_CXX_COMPILER})
else ()
  # For OPTEE, CMAKE_C_COMPILER and CMAKE_CXX_COMPILERS are set up as
  # cross-compilers, and ought not be used. Determine host compilers to use.
  # Prefer clang, but fallback to GCC since, unlike SGX, we cannot be sure that
  # clang exists in the build environment for OPTEE.
  find_program(EDGER8R_C_COMPILER clang-8 clang gcc)
  find_program(EDGER8R_CXX_COMPILER clang++-8 clang++ g++)
endif ()

ExternalProject_Add(
  oeedger8r-cpp
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/oeedger8r-cpp
  BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/oeedger8r-cpp
  CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
             -DCMAKE_C_COMPILER=${EDGER8R_C_COMPILER}
             -DCMAKE_CXX_COMPILER=${EDGER8R_CXX_COMPILER}
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
  add_subdirectory(oeverify)
endif ()
