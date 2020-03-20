# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/getenclave.debugenc.flagdebug.typesgx getenclaveext_host getenclaveext_enc 0)
add_enclave_test(tests/getenclave.debugenc.flagdebug.typeauto getenclaveext_host getenclaveext_enc 1)
add_enclave_test(tests/getenclave.debugenc.flagsimulate.typesgx getenclaveext_host getenclaveext_enc 2)
add_enclave_test(tests/getenclave.debugenc.flagsimulate.typeauto getenclaveext_host getenclaveext_enc 3)
