# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (OE_SGX)
  set(ARCH "x86_64")
  set(PLATFORM_SRC
    libunwind/src/x86_64/Los-linux.c
    Gstep.c  # libunwind/src/x86_64/Lstep.c
    setcontext.S # libunwind/src/x86_64/setcontext.c
  )
else()
  set(ARCH "aarch64")
  set(PLATFORM_SRC
    libunwind/src/aarch64/Lstep.c
  )
endif()

configure_file(
  libunwind/include/libunwind-${ARCH}.h
  libunwind.h
  COPYONLY)

configure_file(
  libunwind/src/${ARCH}/Gstep.c
  Gstep.inc
  COPYONLY)

file(GENERATE OUTPUT config.h CONTENT "/* Empty file */\n")

set(PKG_MAJOR 1)
set(PKG_MINOR 3)
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/libunwind/include/libunwind-common.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/libunwind-common.inc
  COPYONLY)

file(COPY libunwind/include/tdep-${ARCH}/ DESTINATION tdep)

add_enclave_library(libunwind OBJECT
  # Total 67 items
  libunwind/src/dwarf/global.c
  libunwind/src/dwarf/Lexpr.c
  libunwind/src/dwarf/Lfde.c
  libunwind/src/dwarf/Lfind_proc_info-lsb.c
  libunwind/src/dwarf/Lfind_unwind_table.c
  libunwind/src/dwarf/Lparser.c
  libunwind/src/dwarf/Lpe.c
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
  libunwind/src/mi/Lset_cache_size.c
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
  libunwind/src/${ARCH}/getcontext.S
  libunwind/src/${ARCH}/is_fpreg.c
  libunwind/src/${ARCH}/Lcreate_addr_space.c
  libunwind/src/${ARCH}/Lget_save_loc.c
  libunwind/src/${ARCH}/Lglobal.c
  libunwind/src/${ARCH}/Linit.c
  libunwind/src/${ARCH}/Linit_local.c
  libunwind/src/${ARCH}/Linit_remote.c
  libunwind/src/${ARCH}/Lget_proc_info.c
  libunwind/src/${ARCH}/Lregs.c
  libunwind/src/${ARCH}/Lresume.c
  libunwind/src/${ARCH}/Lstash_frame.c
  libunwind/src/${ARCH}/Ltrace.c
  libunwind/src/${ARCH}/regname.c
  libunwind/src/os-linux.c
  libunwind/src/elf64.c
  ${PLATFORM_SRC}

  # Add dependency to libunwind.h generation.
  ${CMAKE_CURRENT_BINARY_DIR}/libunwind.h)

maybe_build_using_clangw(libunwind)

set_source_files_properties(Gstep.c PROPERTIES COMPILE_FLAGS "-Werror")
set_source_files_properties(setcontext.S PROPERTIES COMPILE_FLAGS "-Werror")

enclave_compile_options(libunwind PRIVATE
  -Wno-error
  -include ${CMAKE_CURRENT_SOURCE_DIR}/stubs.h)

enclave_compile_definitions(libunwind PRIVATE
  HAVE_ELF_H
  HAVE_ENDIAN_H
  HAVE_LINK_H
  _GNU_SOURCE
  UNW_LOCAL_ONLY=1
  #__x86_64__
  HAVE_DL_ITERATE_PHDR
  PACKAGE_STRING=\"libunwind-1.3\"
  PACKAGE_BUGREPORT=\"unwind.org\")

enclave_link_libraries(libunwind PUBLIC oelibc)

enclave_include_directories(libunwind PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/libunwind/include
  ${CMAKE_CURRENT_SOURCE_DIR}/libunwind/src/${ARCH}
  ${CMAKE_CURRENT_SOURCE_DIR}/libunwind/src
  ${CMAKE_CURRENT_BINARY_DIR}/tdep
  ${CMAKE_CURRENT_BINARY_DIR})

install_enclaves(TARGETS libunwind EXPORT openenclave-targets)
