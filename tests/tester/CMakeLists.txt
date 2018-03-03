# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/tester host/testerhost ./enc/testerenc.signed.so)
