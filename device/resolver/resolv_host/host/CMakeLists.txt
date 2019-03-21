# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (WIN32)
    add_subdirectory(win32)
else()
    add_subdirectory(linux)
endif()
