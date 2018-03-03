# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(enc)
add_subdirectory(host)

add_test(samples/cmake/sort host/samples-sorthost ./enc/samples-sortenc.signed.so)
