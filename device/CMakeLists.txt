# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(socket)
add_subdirectory(fs)
add_subdirectory(eventfd)

install(FILES
    edl/sgxfs.edl
    DESTINATION
    "${CMAKE_INSTALL_DATADIR}/edl")
