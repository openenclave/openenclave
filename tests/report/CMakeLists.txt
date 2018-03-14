# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/report host/reporthost ./enc/reportenc.signed.so)
set_tests_properties(tests/report PROPERTIES SKIP_RETURN_CODE 2)
