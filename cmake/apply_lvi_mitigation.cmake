# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Helper to obtain the version of glibc
macro (get_glibc_version)
  execute_process(
    COMMAND ldd --version
    OUTPUT_VARIABLE LDD_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_VARIABLE LDD_ERROR
    ERROR_STRIP_TRAILING_WHITESPACE
  )
  if (LDD_ERROR)
    message(FATAL_ERROR "Failed to get glibc version: ${LDD_ERROR}")
  endif ()
  string(REGEX MATCH "GLIBC ([0-9]+\\.[0-9]+)" _ ${LDD_OUTPUT})
  set(GLIBC_VERSION ${CMAKE_MATCH_1})
  if (NOT GLIBC_VERSION MATCHES "^[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR "Glibc version is unknown: ${GLIBC_VERSION}")
  endif ()
  message(VERBOSE "Found Glibc version: ${GLIBC_VERSION}")
endmacro ()

# Usage
# apply_lvi_mitigation(
#     <target>
# )
function (apply_lvi_mitigation TARGET)
  # alias ControlFlow to ControlFlow-GNU
  if (LVI_MITIGATION STREQUAL "ControlFlow")
    set(LVI_MITIGATION "ControlFlow-GNU")
  endif ()

  # Add LVI mitigation compliation options.
  if (UNIX)
    if (LVI_MITIGATION STREQUAL ControlFlow-Clang)
      if (NOT (CMAKE_C_COMPILER_ID MATCHES Clang AND CMAKE_C_COMPILER_VERSION
                                                     VERSION_GREATER_EQUAL 11))
        message(
          FATAL_ERROR
            "ControlFlow-Clang requires Clang and Clang++ version >= 11 but got ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}."
        )
      endif ()

      # Enable clang-11 built-in LVI mitigation
      target_compile_options(${TARGET} PRIVATE -mlvi-cfi)
    elseif (LVI_MITIGATION STREQUAL ControlFlow-GNU)
      # Enable custom LVI mitigation
      if (CMAKE_C_COMPILER_ID MATCHES Clang)
        # Enforce clang to invoke the gnu assembler instead of the integrated one.
        target_compile_options(
          ${TARGET}
          PRIVATE
            # Use the customized `as` for LVI mitigation instead of LLVM-integrated one.
            -no-integrated-as)
      elseif (CMAKE_C_COMPILER_ID MATCHES GNU)
        # For GNU, use the following switch to ensure indirect branches via
        # register only. This property is ensured by the `-x86-speculative-load-hardending`,
        # which OE enables by default, on Clang.
        target_compile_options(${TARGET} PRIVATE -mindirect-branch-register)
      endif ()

      # Options for the GNU assembler.
      target_compile_options(
        ${TARGET} PRIVATE -Wa,-mlfence-before-indirect-branch=register
                          -Wa,-mlfence-before-ret=not)

      # Obtain the version of glibc.
      if (NOT GLIBC_VERSION)
        get_glibc_version()
        set(GLIBC_VERSION
            ${GLIBC_VERSION}
            PARENT_SCOPE)
      endif ()

      # The customized `ld` depends on GLIBC 2.27.
      if (GLIBC_VERSION GREATER_EQUAL 2.27)
        # Add a linker option to tell gcc/clang wrappers to invoke customized `as` and `ld`.
        # Note that the option is for the wrappers only. Wrappers will discard the option
        # (i.e., not feeding it to the linker).
        target_link_options(${TARGET} PRIVATE -link-lvi-mitigation)
      else ()
        # For system with older version of GLIBC, the compilers will invoke the default `ld`
        # instead of the customized one. However, the version mismatch between the customized `as`
        # (version >= 2.32) and the older version of `ld` (< 32) cause the compilation to fail with
        # the `-g` option (see https://sourceware.org/bugzilla/show_bug.cgi?id=23919). Therefore,
        # the workaround is to disable the `-g` option by using `-g0`.
        target_compile_options(${TARGET} PRIVATE -g0)
      endif ()
    endif ()
  else ()
    # Option for the python script (Windows build only).
    target_compile_options(${TARGET} PRIVATE -lvi-mitigation-control-flow)
  endif ()
endfunction ()
