# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Helper to obtain the version of glibc.
macro (get_glibc_version)
  execute_process(
    COMMAND ${CMAKE_C_COMPILER} -print-file-name=libc.so.6
    OUTPUT_VARIABLE GLIBC_PATH
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  get_filename_component(GLIBC_PATH ${GLIBC_PATH} REALPATH)
  get_filename_component(GLIBC_VERSION ${GLIBC_PATH} NAME)
  string(REGEX REPLACE "libc-(.*).so" \\1 GLIBC_VERSION ${GLIBC_VERSION})
  if (NOT GLIBC_VERSION MATCHES "^[0-9]+\.[0-9]+$")
    message(FATAL_ERROR "Glibc version is unknown: ${GLIBC_VERSION}")
  endif ()
endmacro ()

function (apply_lvi_mitigation NAME)
  # Add LVI mitigation compliation options.
  if (UNIX)
    if (CMAKE_C_COMPILER_ID MATCHES Clang)
      # Enforce clang to invoke the gnu assembler instead of the integrated one.
      target_compile_options(
        ${NAME}
        PRIVATE
          # Use the customized `as` for LVI mitigation instead of LLVM-integrated one.
          -no-integrated-as)
    elseif (CMAKE_C_COMPILER_ID MATCHES GNU)
      # For GNU, use the following switch to ensure indirect branches via
      # register only. This property is ensured by the `-x86-speculative-load-hardending`,
      # which OE enables by default, on Clang.
      target_compile_options(${NAME} PRIVATE -mindirect-branch-register)
    endif ()
    # Options for the GNU assembler.
    target_compile_options(
      ${NAME} PRIVATE -Wa,-mlfence-before-indirect-branch=register
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
      target_link_options(${NAME} PRIVATE -link-lvi-mitigation)
    else ()
      # For system with older version of GLIBC, the compilers will invoke the default `ld`
      # instead of the customized one. However, the version mismatch between the customized `as`
      # (version >= 2.32) and the older version of `ld` (< 32) cause the compilation to fail with
      # the `-g` option (see https://sourceware.org/bugzilla/show_bug.cgi?id=23919). Therefore,
      # the workaround is to disable the `-g` option by using `-g0`.
      target_compile_options(${NAME} PRIVATE -g0)
    endif ()
  else ()
    # Option for the python script (Windows build only).
    target_compile_options(${NAME} PRIVATE -lvi-mitigation-control-flow)
  endif ()
endfunction ()
