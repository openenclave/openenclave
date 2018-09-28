# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

include(tests.cmake)

add_executable(
    libc2_enc 
    enc.cpp
    ../../../3rdparty/musl/libc-test/src/common/mtest.c
    ../../../3rdparty/musl/libc-test/src/common/rand.c
    ../../../3rdparty/musl/libc-test/src/functional/tls_align_dso.c
    ${TESTS}
    )

target_compile_options(libc2_enc PRIVATE 
    -fpermissive
    -Wno-error
    -Wno-unknown-pragmas
    -Wno-unused-function
    -Wno-return-type
    -Wno-macro-redefined
    -Wno-unused-variable
    -Wno-literal-range
    -Wno-missing-braces
    -Wno-writable-strings)

target_include_directories(
    libc2_enc PRIVATE
    -I ../../../3rdparty/musl/libc-test/src/common)

target_link_libraries(libc2_enc oelibc oeenclave)
