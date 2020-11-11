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
    -loeenclave)

set(ENCLAVE_MBEDTLS_CRYPTO_WRAPPER_LIBS -loecryptombedtls -lmbedx509 -lmbedtls
                                        -lmbedcrypto)

set(ENCLAVE_OPENSSL_CRYPTO_WRAPPER_LIBS -loecryptoopenssl -lopensslssl
                                        -lopensslcrypto)

set(ENCLAVE_CLIBS_2 -loelibc -loesyscall -loecore)

set(ENCLAVE_CLIBS_LIST ${ENCLAVE_CLIBS_1} ${ENCLAVE_CLIBS_2})
list(JOIN ENCLAVE_CLIBS_LIST " " ENCLAVE_CLIBS)

set(ENCLAVE_CXXLIBS_LIST ${ENCLAVE_CLIBS_1} -loelibcxx ${ENCLAVE_CLIBS_2})
list(APPEND ENCLAVE_MBEDTLS_CRYPTO_WRAPPER_LIBS ${ENCLAVE_CLIBS_2})
list(APPEND ENCLAVE_OPENSSL_CRYPTO_WRAPPER_LIBS ${ENCLAVE_CLIBS_2})

list(JOIN ENCLAVE_CXXLIBS_LIST " " ENCLAVE_CXXLIBS)
list(JOIN ENCLAVE_MBEDTLS_CRYPTO_WRAPPER_LIBS " " ENCLAVE_MBEDTLS_CRYPTO_LIBS)
list(JOIN ENCLAVE_OPENSSL_CRYPTO_WRAPPER_LIBS " " ENCLAVE_OPENSSL_CRYPTO_LIBS)

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
      -loeenclave-lvi-cfg)

  set(LVI_MITIGATION_MBEDTLS_CRYPTO_WRAPPER_LIBS
      -loecryptombedtls-lvi-cfg -lmbedx509-lvi-cfg -lmbedtls-lvi-cfg
      -lmbedcrypto-lvi-cfg)

  set(LVI_MITIGATION_OPENSSL_CRYPTO_WRAPPER_LIBS
      -loecryptoopenssl-lvi-cfg -lopensslssl-lvi-cfg -lopensslcrypto-lvi-cfg)

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

  list(APPEND LVI_MITIGATION_MBEDTLS_CRYPTO_WRAPPER_LIBS
       ${LVI_MITIGATION_CLIBS_2})
  list(APPEND LVI_MITIGATION_OPENSSL_CRYPTO_WRAPPER_LIBS
       ${LVI_MITIGATION_CLIBS_2})

  list(JOIN LVI_MITIGATION_MBEDTLS_CRYPTO_WRAPPER_LIBS " "
       LVI_MITIGATION_MBEDTLS_CRYPTO_LIBS)
  list(JOIN LVI_MITIGATION_OPENSSL_CRYPTO_WRAPPER_LIBS " "
       LVI_MITIGATION_OPENSSL_CRYPTO_LIBS)

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
## Function to configure and install package config file in mentioned component
##
##==============================================================================

function (configure_and_install_pkg_config PKG_CONFIG_FILE_NAME COMPONENT_NAME)

  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/${PKG_CONFIG_FILE_NAME}
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/${PKG_CONFIG_FILE_NAME} @ONLY)

  if (NOT COMPONENT_NAME)
    install(
      FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/${PKG_CONFIG_FILE_NAME}
      DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig")
  else ()
    install(
      FILES ${CMAKE_BINARY_DIR}/output/share/pkgconfig/${PKG_CONFIG_FILE_NAME}
      DESTINATION "${CMAKE_INSTALL_DATADIR}/pkgconfig"
      COMPONENT ${COMPONENT_NAME})
  endif ()
endfunction ()

##==============================================================================
##
## package config file list
##
##==============================================================================

set(PACKAGE_CONFIG_FILES_LIST oehost-gcc.pc oehost-g++.pc
                              oehost-clang.pc oehost-clang++.pc
                              oeenclave-gcc.pc oeenclave-g++.pc
                              oeenclave-clang.pc oeenclave-clang++.pc)

##==============================================================================
##
## package config file list with LVI mitigation
##
##==============================================================================

set(LVI_MITIGATION_PACKAGE_CONFIG_FILES_LIST
    oeenclave-gcc-lvi-cfg.pc oeenclave-g++-lvi-cfg.pc
    oeenclave-clang-lvi-cfg.pc oeenclave-clang++-lvi-cfg.pc)

##==============================================================================
##
## host verify package config file list
##
##==============================================================================

set(HOST_VERIFY_PACKAGE_CONFIG_FILES_LIST
    oehostverify-gcc.pc oehostverify-g++.pc
    oehostverify-clang.pc oehostverify-clang++.pc)

foreach (file_name ${PACKAGE_CONFIG_FILES_LIST})
  configure_and_install_pkg_config(${file_name} "")
endforeach (file_name)

if (LVI_MITIGATION MATCHES ControlFlow)
  foreach (file_name ${LVI_MITIGATION_PACKAGE_CONFIG_FILES_LIST})
    configure_and_install_pkg_config(${file_name} "")
  endforeach (file_name)
endif ()

foreach (file_name ${HOST_VERIFY_PACKAGE_CONFIG_FILES_LIST})
  configure_and_install_pkg_config(${file_name} OEHOSTVERIFY)
endforeach (file_name)
