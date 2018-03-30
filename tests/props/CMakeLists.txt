# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/props1 host/propshost ./enc/propsenc.signed.so)
add_test(tests/props2 host/propshost ./enc/propsenc)
