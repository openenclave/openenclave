# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(SampleAppCRT)
add_subdirectory(SampleAppCRTHost)

add_test(tests/SampleAppCRT SampleAppCRTHost/SampleAppCRTHost SampleAppCRT/SampleAppCRT.signed.so)
