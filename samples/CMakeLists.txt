# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (USE_LIBSGX)
  install(DIRECTORY remote_attestation
          DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
          PATTERN "gen_pubkey_header.sh"
            PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
              GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)
  if(NOT WIN32)
    install(DIRECTORY attested_tls
          DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
          PATTERN "gen_pubkey_header.sh"
            PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
              GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)
  endif()
endif ()

install(DIRECTORY helloworld file-encryptor data-sealing local_attestation switchless
        DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
        PATTERN "gen_pubkey_header.sh"
          PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
            GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)

if (WIN32)
  install(FILES README_Windows.md
        DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
        RENAME README.md)
else ()
  install(FILES README_Linux.md
        DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
        RENAME README.md)
endif ()

if (NOT USE_LIBSGX)
  set(WITHOUT_DCAP_LINK ON)
else ()
  set(WITHOUT_DCAP_LINK OFF)
endif()

if (WIN32)
  add_test(NAME samples
           COMMAND ${CMAKE_COMMAND} -DUSE_LIBSGX=${USE_LIBSGX} -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR} -DBUILD_DIR=${PROJECT_BINARY_DIR} -DPREFIX_DIR=${CMAKE_INSTALL_PREFIX} -DNUGET_PACKAGE_PATH=${NUGET_PACKAGE_PATH} -DWITHOUT_DCAP_LINK=${WITHOUT_DCAP_LINK} -P ${CMAKE_CURRENT_SOURCE_DIR}/test-samples.cmake)
else ()
  add_test(NAME samples
           COMMAND ${CMAKE_COMMAND} -DUSE_LIBSGX=${USE_LIBSGX} -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR} -DBUILD_DIR=${PROJECT_BINARY_DIR} -DPREFIX_DIR=${CMAKE_INSTALL_PREFIX} -P ${CMAKE_CURRENT_SOURCE_DIR}/test-samples.cmake)
endif ()
