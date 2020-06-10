# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (HAS_QUOTE_PROVIDER)
  install(
    DIRECTORY remote_attestation
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    PATTERN
      "gen_pubkey_header.sh"
      PERMISSIONS
        OWNER_EXECUTE
        OWNER_WRITE
        OWNER_READ
        GROUP_EXECUTE
        GROUP_READ
        WORLD_EXECUTE
        WORLD_READ)
  install(
    DIRECTORY attested_tls
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    PATTERN
      "gen_pubkey_header.sh"
      PERMISSIONS
        OWNER_EXECUTE
        OWNER_WRITE
        OWNER_READ
        GROUP_EXECUTE
        GROUP_READ
        WORLD_EXECUTE
        WORLD_READ)
endif ()

if (BUILD_ENCLAVES)
  install(
    DIRECTORY local_attestation
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    PATTERN
      "gen_pubkey_header.sh"
      PERMISSIONS
        OWNER_EXECUTE
        OWNER_WRITE
        OWNER_READ
        GROUP_EXECUTE
        GROUP_READ
        WORLD_EXECUTE
        WORLD_READ)

  install(DIRECTORY helloworld file-encryptor data-sealing switchless
          DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples)
endif ()

if (OE_SGX)
  set(BUILD_HOSTVERIFY_INLINE ON)
  add_subdirectory(host_verify)
endif ()

install(
  DIRECTORY host_verify
  DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
  COMPONENT OEHOSTVERIFY)

if (WIN32)
  install(
    FILES README_Windows.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    RENAME README.md)
else ()
  install(FILES config.mk
          DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples)
  install(
    FILES README_Linux.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    RENAME README.md)
endif ()

if (WIN32)
  add_test(
    NAME samples
    COMMAND
      ${CMAKE_COMMAND} -DHAS_QUOTE_PROVIDER=${HAS_QUOTE_PROVIDER}
      -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
      -DBUILD_DIR=${PROJECT_BINARY_DIR} -DPREFIX_DIR=${CMAKE_INSTALL_PREFIX}
      -DNUGET_PACKAGE_PATH=${NUGET_PACKAGE_PATH} -P
      ${CMAKE_CURRENT_SOURCE_DIR}/test-samples.cmake)
else ()
  add_test(
    NAME samples
    COMMAND
      ${CMAKE_COMMAND} -DHAS_QUOTE_PROVIDER=${HAS_QUOTE_PROVIDER}
      -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
      -DBUILD_DIR=${PROJECT_BINARY_DIR} -DPREFIX_DIR=${CMAKE_INSTALL_PREFIX} -P
      ${CMAKE_CURRENT_SOURCE_DIR}/test-samples.cmake)
endif ()
