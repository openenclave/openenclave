# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/cpuid cpuid_host cpuid_enc)
set_tests_properties(tests/cpuid PROPERTIES SKIP_RETURN_CODE 2)
