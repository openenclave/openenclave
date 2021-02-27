# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/tools/apkman/lua1 lua_host lua_enc
                 ${CMAKE_CURRENT_SOURCE_DIR}/scripts/sieve.lua)

add_enclave_test(tests/tools/apkman/lua2 lua_host lua_enc
                 ${CMAKE_CURRENT_SOURCE_DIR}/scripts/bisect.lua)
