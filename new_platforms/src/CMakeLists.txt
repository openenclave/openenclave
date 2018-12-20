# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(Untrusted)
if((UNIX AND TZ) OR (WIN32 AND SGX) OR (WIN32 AND TZ AND SIM))
    add_subdirectory(Trusted)
endif()
