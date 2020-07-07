# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# oesign tests need to build a target enclave to sign
if (BUILD_ENCLAVES AND (NOT COMPONENT MATCHES OEHOSTVERIFY))
  add_subdirectory(test-enclave)
  add_subdirectory(test-digest)
  add_subdirectory(test-inputs)
  add_subdirectory(test-sign)

  if (NOT WIN32)
    # Windows version of oesign does not use openssl, therefore there is no openssl engine support and
    # not much sense in trying to test it.
    add_subdirectory(test-engine)
  endif ()
endif ()
