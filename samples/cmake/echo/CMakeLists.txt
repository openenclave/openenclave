# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(enc)
add_subdirectory(host)

add_test(samples/cmake/echo host/samples-echohost ./enc/samples-echoenc.signed.so)
