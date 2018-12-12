# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

configure_file(
  libunwind/include/libunwind-x86_64.h
  libunwind.h
  COPYONLY)

configure_file(
  libunwind/src/x86_64/Gstep.c
  Gstep.inc
  COPYONLY)

add_custom_command(
  OUTPUT Gtrace.c
  # TODO: We are doing this ugly workaround since we don't support
  # thread local storage (__thread). Once the PR for Thread Local
  # Storage goes in (#1157), we can remove this.
  COMMAND grep -v "^static __thread"
    ${CMAKE_CURRENT_SOURCE_DIR}/libunwind/src/x86_64/Gtrace.c >
    ${CMAKE_CURRENT_BINARY_DIR}/Gtrace.inc
  COMMAND ${CMAKE_COMMAND} -E copy
    ${CMAKE_CURRENT_SOURCE_DIR}/Gtrace.c
    ${CMAKE_CURRENT_BINARY_DIR}/Gtrace.c
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libunwind/src/x86_64/Gtrace.c)

file(GENERATE OUTPUT config.h CONTENT "/* Empty file */\n")

set(PKG_MAJOR 1)
set(PKG_MINOR 3)
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/libunwind/include/libunwind-common.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/libunwind-common.inc
  COPYONLY)

file(COPY libunwind/include/tdep-x86_64/ DESTINATION tdep)

add_library(libunwind OBJECT
  # Total 67 items
  libunwind/src/dwarf/global.c
  libunwind/src/dwarf/Lexpr.c
  libunwind/src/dwarf/Lfde.c
  libunwind/src/dwarf/Lfind_proc_info-lsb.c
  libunwind/src/dwarf/Lfind_unwind_table.c
  libunwind/src/dwarf/Lparser.c
  libunwind/src/dwarf/Lpe.c
  libunwind/src/dwarf/Lstep.c
  libunwind/src/mi/_ReadULEB.c
  libunwind/src/mi/_ReadSLEB.c
  libunwind/src/mi/backtrace.c
  libunwind/src/mi/dyn-cancel.c
  libunwind/src/mi/dyn-info-list.c
  libunwind/src/mi/dyn-register.c
  libunwind/src/mi/flush_cache.c
  libunwind/src/mi/init.c
  libunwind/src/mi/Ldestroy_addr_space.c
  libunwind/src/mi/Ldyn-extract.c
  libunwind/src/mi/Lfind_dynamic_proc_info.c
  libunwind/src/mi/Lget_accessors.c
  libunwind/src/mi/Lget_fpreg.c
  libunwind/src/mi/Lget_proc_info_by_ip.c
  libunwind/src/mi/Lget_proc_name.c
  libunwind/src/mi/Lget_reg.c
  libunwind/src/mi/Lput_dynamic_unwind_info.c
  libunwind/src/mi/Lset_caching_policy.c
  libunwind/src/mi/Lset_fpreg.c
  libunwind/src/mi/Lset_reg.c
  libunwind/src/mi/mempool.c
  libunwind/src/mi/strerror.c
  libunwind/src/unwind/Backtrace.c
  libunwind/src/unwind/DeleteException.c
  libunwind/src/unwind/FindEnclosingFunction.c
  libunwind/src/unwind/ForcedUnwind.c
  libunwind/src/unwind/GetBSP.c
  libunwind/src/unwind/GetCFA.c
  libunwind/src/unwind/GetDataRelBase.c
  libunwind/src/unwind/GetGR.c
  libunwind/src/unwind/GetIPInfo.c
  libunwind/src/unwind/GetIP.c
  libunwind/src/unwind/GetLanguageSpecificData.c
  libunwind/src/unwind/GetRegionStart.c
  libunwind/src/unwind/GetTextRelBase.c
  libunwind/src/unwind/RaiseException.c
  libunwind/src/unwind/Resume.c
  libunwind/src/unwind/Resume_or_Rethrow.c
  libunwind/src/unwind/SetGR.c
  libunwind/src/unwind/SetIP.c
  libunwind/src/x86_64/getcontext.S
  libunwind/src/x86_64/is_fpreg.c
  libunwind/src/x86_64/Los-linux.c
  libunwind/src/x86_64/Lcreate_addr_space.c
  libunwind/src/x86_64/Lget_save_loc.c
  libunwind/src/x86_64/Lglobal.c
  libunwind/src/x86_64/Linit.c
  libunwind/src/x86_64/Linit_local.c
  libunwind/src/x86_64/Linit_remote.c
  libunwind/src/x86_64/Lget_proc_info.c
  libunwind/src/x86_64/Lregs.c
  libunwind/src/x86_64/Lresume.c
  libunwind/src/x86_64/Lstash_frame.c
  Gstep.c  # libunwind/src/x86_64/Lstep.c
  Gtrace.c # libunwind/src/x86_64/Ltrace.c
  libunwind/src/x86_64/regname.c
  setcontext.S # libunwind/src/x86_64/setcontext.c
  libunwind/src/os-linux.c
  libunwind/src/elf64.c

  # Add dependency to libunwind.h generation.
  ${CMAKE_CURRENT_BINARY_DIR}/libunwind.h)

set_target_properties(libunwind PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_options(libunwind PRIVATE
  -Wall
  -Werror
  -Wno-pointer-to-int-cast
  -Wno-unused-function
  -Wno-unused-variable
  -Wno-cpp
  -fno-builtin
  -include ${CMAKE_CURRENT_SOURCE_DIR}/stubs.h)

if (CMAKE_C_COMPILER_ID MATCHES GNU)
  target_compile_options(libunwind PRIVATE
    # TODO: GCC does not have the equivalent of -Wno-macro-redefined,
    # and currently we define `UNW_LOCAL_ONLY` a bit more liberally
    # than necessary. When this is cleaned up, we can go back to
    # `-Werror`.
    -Wno-error
    -Wno-unused-but-set-variable
    -Wno-maybe-uninitialized)
elseif (CMAKE_C_COMPILER_ID MATCHES Clang)
  target_compile_options(libunwind PRIVATE
    -Wno-header-guard
    -Wno-uninitialized
    -Wno-unused-variable
    -Wno-macro-redefined)
endif ()

# Allow arithmetic on void*
set_source_files_properties(libunwind/src/elf64.c PROPERTIES COMPILE_FLAGS -Wno-pointer-arith)

target_compile_definitions(libunwind PRIVATE
  HAVE_ELF_H
  HAVE_ENDIAN_H
  HAVE_LINK_H
  _GNU_SOURCE
  UNW_LOCAL_ONLY=1
  #__x86_64__
  HAVE_DL_ITERATE_PHDR
  PACKAGE_STRING=\"libunwind-1.3\"
  PACKAGE_BUGREPORT=\"unwind.org\")

target_link_libraries(libunwind PUBLIC oelibc)

target_include_directories(libunwind PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/libunwind/include
  ${CMAKE_CURRENT_SOURCE_DIR}/libunwind/src/x86_64
  ${CMAKE_CURRENT_SOURCE_DIR}/libunwind/src
  ${CMAKE_CURRENT_BINARY_DIR}/tdep
  ${CMAKE_CURRENT_BINARY_DIR})
