# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(invalid_image main.cpp)
target_link_libraries(invalid_image oehost)
set_property(TARGET invalid_image PROPERTY POSITION_INDEPENDENT_CODE OFF)
target_link_options(invalid_image PRIVATE -no-pie)
add_test(tests/invalid_image invalid_image)
