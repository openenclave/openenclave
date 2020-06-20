# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

##==============================================================================
##
## Prefix where Open Enclave is installed.
##
##==============================================================================

set(PREFIX "${CMAKE_INSTALL_PREFIX}")

##==============================================================================
##
## Enclave compiler flags:
##
##==============================================================================

set(ENCLAVE_CINCLUDES
    "-I\${includedir}/openenclave/3rdparty/libc -I\${includedir}/openenclave/3rdparty -I\${includedir}"
)

set(ENCLAVE_CXXINCLUDES
    "-I\${includedir}/openenclave/3rdparty/libcxx ${ENCLAVE_CINCLUDES}")

set(ENCLAVE_CFLAGS_LIST
    -nostdinc
    -m64
    -fPIE
    -ftls-model=local-exec
    -fvisibility=hidden
    -fstack-protector-strong
    -fno-omit-frame-pointer
    -ffunction-sections
    -fdata-sections)

set(ENCLAVE_CFLAGS_CLANG_LIST ${ENCLAVE_CFLAGS_LIST}
                              ${SPECTRE_MITIGATION_FLAGS})
list(JOIN ENCLAVE_CFLAGS_CLANG_LIST " " ENCLAVE_CFLAGS_CLANG)

list(JOIN ENCLAVE_CFLAGS_LIST " " ENCLAVE_CFLAGS_GCC)

# See `cmake/apply_lvi_mitigation.cmake`.
if (LVI_MITIGATION MATCHES ControlFlow)
  set(LVI_MITIGATION_FLAGS -Wa,-mlfence-before-indirect-branch=register
                           -Wa,-mlfence-before-ret=not)
  if (NOT GLIBC_VERSION)
    get_glibc_version()
  endif ()
  if (GLIBC_VERSION LESS 2.27)
    set(LVI_MITIGATION_FLAGS ${LVI_MITIGATION_FLAGS} -g0)
  endif ()
  set(LVI_MITIGATION_FLAGS_GCC ${ENCLAVE_CFLAGS_GCC} ${LVI_MITIGATION_FLAGS}
                               -mindirect-branch-register)
  list(JOIN LVI_MITIGATION_FLAGS_GCC " " ENCLAVE_LVI_MITIGATION_CFLAGS_GCC)

  set(LVI_MITIGATION_FLAGS_CLANG ${ENCLAVE_CFLAGS_CLANG_LIST}
                                 ${LVI_MITIGATION_FLAGS} -no-integrated-as)
  list(JOIN LVI_MITIGATION_FLAGS_CLANG " " ENCLAVE_LVI_MITIGATION_CFLAGS_CLANG)
endif ()

##==============================================================================
##
## Enclave linker flags:
##
##==============================================================================

set(ENCLAVE_CLIBS_1
    -nostdlib
    -nodefaultlibs
    -nostartfiles
    -Wl,--no-undefined
    -Wl,-Bstatic
    -Wl,-Bsymbolic
    -Wl,--export-dynamic
    -Wl,-pie
    -Wl,--build-id
    -Wl,-z,noexecstack
    -Wl,-z,now
    -Wl,-gc-sections
    -L\${libdir}/openenclave/enclave
    -loeenclave
    -loecryptombed
    -lmbedx509
    -lmbedcrypto)

set(ENCLAVE_CLIBS_2 -loelibc -loesyscall -loecore)

set(ENCLAVE_CLIBS_LIST ${ENCLAVE_CLIBS_1} ${ENCLAVE_CLIBS_2})
list(JOIN ENCLAVE_CLIBS_LIST " " ENCLAVE_CLIBS)

set(ENCLAVE_CXXLIBS_LIST ${ENCLAVE_CLIBS_1} -loelibcxx ${ENCLAVE_CLIBS_2})
list(JOIN ENCLAVE_CXXLIBS_LIST " " ENCLAVE_CXXLIBS)

if (LVI_MITIGATION MATCHES ControlFlow)
  set(LVI_MITIGATION_CLIBS_1
      -nostdlib
      -nodefaultlibs
      -nostartfiles
      -Wl,--no-undefined
      -Wl,-Bstatic
      -Wl,-Bsymbolic
      -Wl,--export-dynamic
      -Wl,-pie
      -Wl,--build-id
      -Wl,-z,noexecstack
      -Wl,-z,now
      -Wl,-gc-sections
      -L\${libdir}/openenclave/enclave
      -loeenclave-lvi-cfg
      -loecryptombed-lvi-cfg
      -lmbedx509-lvi-cfg
      -lmbedcrypto-lvi-cfg)

  # See `cmake/apply_lvi_mitigation.cmake`.
  if (GLIBC_VERSION GREATER_EQUAL 2.27)
    set(LVI_MITIGATION_CLIBS_1 ${LVI_MITIGATION_CLIBS_1} -link-lvi-mitigation)
  endif ()

  set(LVI_MITIGATION_CLIBS_2 -loelibc-lvi-cfg -loesyscall-lvi-cfg
                             -loecore-lvi-cfg)

  set(LVI_MITIGATION_CLIBS_LIST ${LVI_MITIGATION_CLIBS_1}
                                ${LVI_MITIGATION_CLIBS_2})
  list(JOIN LVI_MITIGATION_CLIBS_LIST " " ENCLAVE_LVI_MITIGATION_CLIBS)

  set(LVI_MITIGATION_CXXLIBS_LIST ${LVI_MITIGATION_CLIBS_1} -loelibcxx-lvi-cfg
                                  ${LVI_MITIGATION_CLIBS_2})
  list(JOIN LVI_MITIGATION_CXXLIBS_LIST " " ENCLAVE_LVI_MITIGATION_CXXLIBS)

endif ()

##==============================================================================
##
## Host compiler flags:
##
##==============================================================================

set(HOST_INCLUDES "-I\${includedir}")

set(HOST_CFLAGS_CLANG_LIST -fstack-protector-strong ${SPECTRE_MITIGATION_FLAGS})
list(JOIN HOST_CFLAGS_CLANG_LIST " " HOST_CFLAGS_CLANG)

set(HOST_CXXFLAGS_CLANG ${HOST_CFLAGS_CLANG})

set(HOST_CFLAGS_GCC_LIST -fstack-protector-strong -D_FORTIFY_SOURCE=2)
list(JOIN HOST_CFLAGS_GCC_LIST " " HOST_CFLAGS_GCC)

set(HOST_CXXFLAGS_GCC ${HOST_CFLAGS_GCC})

##==============================================================================
##
## Host linker flags:
##
##==============================================================================

set(HOSTVERIFY_CLIBS
    "-rdynamic -Wl,-z,noexecstack -L\${libdir}/openenclave/host -loehostverify -ldl -lpthread"
)
set(HOST_CLIBS
    "-Wl,-z,noexecstack -L\${libdir}/openenclave/host -loehost -ldl -lpthread")

set(HOSTVERIFY_CXXLIBS "${HOSTVERIFY_CLIBS}")
set(HOST_CXXLIBS "${HOST_CLIBS}")

##==============================================================================
##
## oeenclave-gcc.pc:
##
##==============================================================================

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-gcc.pc
  ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-gcc.pc @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-gcc.pc
        DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oeenclave-g++.pc:
##
##==============================================================================

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-g++.pc
  ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-g++.pc @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-g++.pc
        DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oeenclave-gcc-lvi-cfg.pc:
##
##==============================================================================

if (LVI_MITIGATION MATCHES ControlFlow)
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-gcc-lvi-cfg.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-gcc-lvi-cfg.pc @ONLY)

  install(
    FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-gcc-lvi-cfg.pc
    DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig")
endif ()

##==============================================================================
##
## oeenclave-g++-lvi-cfg.pc:
##
##==============================================================================

if (LVI_MITIGATION MATCHES ControlFlow)
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-g++-lvi-cfg.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-g++-lvi-cfg.pc @ONLY)

  install(
    FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-g++-lvi-cfg.pc
    DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig")
endif ()

##==============================================================================
##
## oehost-gcc.pc:
##
##==============================================================================

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/oehost-gcc.pc
               ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-gcc.pc @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-gcc.pc
        DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oehost-g++.pc:
##
##==============================================================================

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/oehost-g++.pc
               ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-g++.pc @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-g++.pc
        DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oehostverify-gcc.pc:
##
##==============================================================================

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/oehostverify-gcc.pc
  ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehostverify-gcc.pc @ONLY)

install(
  FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehostverify-gcc.pc
  DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig"
  COMPONENT OEHOSTVERIFY)

##==============================================================================
##
## oehostverify-g++.pc:
##
##==============================================================================

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/oehostverify-g++.pc
  ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehostverify-g++.pc @ONLY)

install(
  FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehostverify-g++.pc
  DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig"
  COMPONENT OEHOSTVERIFY)

##==============================================================================
##
## oeenclave-clang.pc:
##
##==============================================================================

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-clang.pc
  ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-clang.pc @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-clang.pc
        DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oeenclave-clang++.pc:
##
##==============================================================================

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-clang++.pc
  ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-clang++.pc @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-clang++.pc
        DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oeenclave-clang-lvi-cfg.pc:
##
##==============================================================================

if (LVI_MITIGATION MATCHES ControlFlow)
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-clang-lvi-cfg.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-clang-lvi-cfg.pc @ONLY)

  install(
    FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-clang-lvi-cfg.pc
    DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig")
endif ()

##==============================================================================
##
## oeenclave-clang++-lvi-cfg.pc:
##
##==============================================================================

if (LVI_MITIGATION MATCHES ControlFlow)
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-clang++-lvi-cfg.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-clang++-lvi-cfg.pc
    @ONLY)

  install(
    FILES
      ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-clang++-lvi-cfg.pc
    DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig")
endif ()

##==============================================================================
##
## oehost-clang.pc:
##
##==============================================================================

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/oehost-clang.pc
               ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-clang.pc @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-clang.pc
        DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oehost-clang++.pc:
##
##==============================================================================

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/oehost-clang++.pc
  ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-clang++.pc @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-clang++.pc
        DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oehostverify-clang.pc:
##
##==============================================================================

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/oehostverify-clang.pc
  ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehostverify-clang.pc @ONLY)

install(
  FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehostverify-clang.pc
  DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig"
  COMPONENT OEHOSTVERIFY)

##==============================================================================
##
## oehostverify-clang++.pc:
##
##==============================================================================

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/oehostverify-clang++.pc
  ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehostverify-clang++.pc @ONLY)

install(
  FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehostverify-clang++.pc
  DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig"
  COMPONENT OEHOSTVERIFY)
