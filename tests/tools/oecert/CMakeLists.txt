# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
  # oecert host depends on a key pair generated during the enclave building.
  # private key is used to sign the enclave while public key is written in the
  # header of the oecert executable
  add_subdirectory(host)
endif ()
