# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(oeedger8r)

if (OE_SGX)
add_subdirectory(oesgx)
add_subdirectory(oesign)
endif()
