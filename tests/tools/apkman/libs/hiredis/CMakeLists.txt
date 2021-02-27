# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

# TODO: This test requires redis-server to be running.
# add_enclave_test(tests/tools/apkman/hiredis hiredis_host hiredis_enc)
