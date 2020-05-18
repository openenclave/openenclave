# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Adopt customized compiler wrappers for LVI mitigation.
function (configure_lvi_mitigation_build LVI_MITIGATION_BINDIR)
  if (NOT EXISTS "${LVI_MITIGATION_BINDIR}")
    message(FATAL_ERROR "${LVI_MITIGATION_BINDIR} does not exist.")
  endif ()
  # Perfer clang over gcc.
  if (EXISTS "${LVI_MITIGATION_BINDIR}/clang-7")
    set(CMAKE_C_COMPILER
        ${LVI_MITIGATION_BINDIR}/clang-7
        PARENT_SCOPE)
    set(CMAKE_CXX_COMPILER
        ${LVI_MITIGATION_BINDIR}/clang++-7
        PARENT_SCOPE)
  else ()
    set(CMAKE_C_COMPILER
        ${LVI_MITIGATION_BINDIR}/gcc
        PARENT_SCOPE)
    set(CMAKE_CXX_COMPILER
        ${LVI_MITIGATION_BINDIR}/g++
        PARENT_SCOPE)
  endif ()
endfunction ()
