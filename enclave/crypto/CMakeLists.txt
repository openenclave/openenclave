# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(mbedtls)
if (BUILD_OPENSSL)
  add_subdirectory(openssl)
endif ()
