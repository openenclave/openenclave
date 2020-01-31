// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
//
#ifndef _TEST_LIBC_HELPERS_H
#define _TEST_LIBC_HELPERS_H

typedef int (*libc_test_function_t)(int argc, const char* argv[]);
int run_single_test(const char* test_name, libc_test_function_t test_function);

// Run all tests in this enclave
int run_tests();

#endif
