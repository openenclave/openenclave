# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(ricochet_host host.c)
target_link_libraries(ricochet_host oehostapp)
