# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/getenclave.nondebugenc.flagdebug.typesgx getenclavend_host getenclavend_enc 0)
add_enclave_test(tests/getenclave.nondebugenc.flagdebug.typeauto getenclavend_host getenclavend_enc 1)
add_enclave_test(tests/getenclave.nondebugenc.flagsimulate.typesgx getenclavend_host getenclavend_enc 2)
add_enclave_test(tests/getenclave.nondebugenc.flagsimulate.typeauto getenclavend_host getenclavend_enc 3)
