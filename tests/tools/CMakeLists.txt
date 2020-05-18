# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (OE_SGX)
  add_subdirectory(oecert)
  add_subdirectory(oecertdump)
  if (NOT WIN32)
    # Windows version of oesign does not use openssl, therefore there is no openssl engine support and
    # not much sense in trying to test it.
    add_subdirectory(oesign-engine)
  endif ()
endif ()
