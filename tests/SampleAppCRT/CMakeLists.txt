# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(SampleAppCRTHost)

if (UNIX)
	add_subdirectory(SampleAppCRT)
endif()

add_enclave_test(tests/SampleAppCRT SampleAppCRTHost SampleAppCRT)
