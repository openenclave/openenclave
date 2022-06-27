# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
  install(
    DIRECTORY attestation
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

  install(DIRECTORY data-sealing debugmalloc file-encryptor helloworld
                    log_callback switchless
          DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples)

  if (UNIX)
    install(DIRECTORY apkman
            DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples)
  endif ()

  if (COMPILER_SUPPORTS_SNMALLOC)
    install(DIRECTORY pluggable_allocator
            DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples)
  endif ()
endif ()

install(
  DIRECTORY host_verify
  DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
  COMPONENT OEHOSTVERIFY)

install(FILES README.md BuildSamplesWindows.md BuildSamplesLinux.md
        DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples)

if (UNIX)
  install(
    FILES config.mk
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    COMPONENT OEHOSTVERIFY)
endif ()

if (WIN32)
  add_test(
    NAME samples
    COMMAND
      ${CMAKE_COMMAND} -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
      -DBUILD_ENCLAVES=${BUILD_ENCLAVES} -DBUILD_DIR=${PROJECT_BINARY_DIR}
      -DPREFIX_DIR=${CMAKE_INSTALL_PREFIX}
      -DNUGET_PACKAGE_PATH=${NUGET_PACKAGE_PATH}
      -DCOMPILER_SUPPORTS_SNMALLOC=on -DUSE_DEBUG_MALLOC=${USE_DEBUG_MALLOC} -P
      ${CMAKE_CURRENT_SOURCE_DIR}/test-samples.cmake)
else ()
  add_test(
    NAME samples
    COMMAND
      ${CMAKE_COMMAND} -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
      -DBUILD_ENCLAVES=${BUILD_ENCLAVES} -DBUILD_DIR=${PROJECT_BINARY_DIR}
      -DPREFIX_DIR=${CMAKE_INSTALL_PREFIX}
      -DCOMPILER_SUPPORTS_SNMALLOC=${COMPILER_SUPPORTS_SNMALLOC}
      -DUSE_DEBUG_MALLOC=${USE_DEBUG_MALLOC} -P
      ${CMAKE_CURRENT_SOURCE_DIR}/test-samples.cmake)
endif ()
