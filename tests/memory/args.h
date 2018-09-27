// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _MEMORY_TESTS_H
#define _MEMORY_TESTS_H

typedef struct _malloc_stress_test_args
{
    int threads;
} malloc_stress_test_args;

typedef struct _buffer
{
    unsigned char* buf;
    size_t size;
} buffer;

typedef struct _boundary_args
{
    buffer host_stack;
    buffer host_heap;
    buffer enclave_memory;
    buffer enclave_host_memory;
} boundary_args;

#endif /* _MEMORY_TESTS_H */
