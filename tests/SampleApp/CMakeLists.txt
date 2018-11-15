# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(SampleAppHost)

if (UNIX)
	add_subdirectory(SampleApp)
endif()

add_enclave_test(tests/SampleApp SampleAppHost SampleApp)
