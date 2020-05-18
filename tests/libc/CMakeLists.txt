# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

include(./tests.cmake)

if (OE_SEPARATE_LIBC_TESTS)
  foreach (test_file ${LIBC_TESTS})
    string(MAKE_C_IDENTIFIER ${test_file} name)
    add_enclave_test(tests/libc${name} libc_host libc_enc ${name})
  endforeach ()
else ()
  add_enclave_test(tests/libc libc_host libc_enc)
endif ()
