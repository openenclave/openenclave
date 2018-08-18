# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(gethostenclave_host host.c)
target_link_libraries(gethostenclave_host oehostapp)
