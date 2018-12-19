# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(oeedger8r)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
add_subdirectory(oesgx)
add_subdirectory(oesign)
endif()
