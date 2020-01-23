# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (OE_SGX)
    add_subdirectory(oecert)
    add_subdirectory(oecertdump)
if (NOT WIN32)
    add_subdirectory(oesign-engine)
endif()
endif()
