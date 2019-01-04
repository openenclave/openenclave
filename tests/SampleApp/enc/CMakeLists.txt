# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(SampleApp CallWrappers.cpp SampleApp.cpp)
target_link_libraries(SampleApp oeenclave)
