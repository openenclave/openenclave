# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

macro (detect_compiler BINDIR CC)
  set(GCC gcc)
  set(CLANG clang)
  if (${CC} STREQUAL CXX)
    set(GCC g++)
    set(CLANG clang++)
  endif ()

  # Set the COMPILER as the variable name (either C_COMPILER or CXX_COMPILER).
  set(COMPILER "${CC}_COMPILER")

  # Use the second level of unwrapping on COMPILER to get the compiler name.
  # If the default compiler is not found, use the following logic to detect
  # the compiler.
  if (NOT EXISTS "${BINDIR}/${${COMPILER}}")
    if (NOT OE_IN_PACKAGE)
      # Build OE. Fallback to gcc/g++.
      set(${COMPILER} ${GCC})
    else ()
      # Build enclave applications. Try to search newer versions of clang/clang++.
      # Be consistent to the logic implemented by samples/config.mk.
      foreach (VERSION 9 8 7)
        set(CLANG_VERSION "")
        if (EXISTS "${BINDIR}/${${COMPILER}}-${VERSION}")
          set(CLANG_VERSION ${VERSION})
          break()
        endif ()
      endforeach ()
      # Set the compiler if a version of clang/clang++ is found.
      if (CLANG_VERSION)
        set(${COMPILER} ${CLANG}-${CLANG_VERSION})
      else ()
        set(${COMPILER} ${GCC})
      endif ()
    endif ()
  endif ()
endmacro ()

# Adopt customized compiler wrappers for LVI mitigation.
function (configure_lvi_mitigation_build)
  cmake_parse_arguments(OE "IN_PACKAGE" "BINDIR" "" ${ARGN})

  if (NOT EXISTS "${OE_BINDIR}")
    message(FATAL_ERROR "${OE_BINDIR} does not exist.")
  endif ()

  if (NOT OE_IN_PACKAGE)
    # Default to clang-7 when building SDK.
    set(C_COMPILER clang-7)
    set(CXX_COMPILER clang++-7)
  else ()
    # Default to clang when building enclave applications.
    set(C_COMPILER clang)
    set(CXX_COMPILER clang++)
  endif ()

  # Overwrite the default C compiler if CC is explicitly specified.
  # Otherwise, select the compiler based on the detection logic.
  if (DEFINED ENV{CC})
    get_filename_component(C_COMPILER $ENV{CC} NAME)
  else ()
    detect_compiler(${OE_BINDIR} C)
  endif ()

  if (EXISTS "${OE_BINDIR}/${C_COMPILER}")
    set(CMAKE_C_COMPILER
        ${OE_BINDIR}/${C_COMPILER}
        PARENT_SCOPE)
  else ()
    message(FATAL_ERROR "-- ${OE_BINDIR}/${C_COMPILER} is not found.")
  endif ()

  # Overwrite the default C++ compiler if CXX is explicitly specified.
  # Otherwise, select the compiler based on the detection logic.
  if (DEFINED ENV{CXX})
    get_filename_component(CXX_COMPILER $ENV{CXX} NAME)
  else ()
    detect_compiler(${OE_BINDIR} CXX)
  endif ()

  if (EXISTS "${OE_BINDIR}/${CXX_COMPILER}")
    set(CMAKE_CXX_COMPILER
        ${OE_BINDIR}/${CXX_COMPILER}
        PARENT_SCOPE)
  else ()
    message(FATAL_ERROR "-- ${OE_BINDIR}/${CXX_COMPILER} is not supported.")
  endif ()
endfunction ()
