// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _MEMORY_TESTS_H
#define _MEMORY_TESTS_H

typedef struct _MallocStressTestArgs
{
    int threads;
} MallocStressTestArgs;

typedef struct _Buffer
{
    unsigned char* buf;
    size_t size;
} Buffer;

typedef struct _BoundaryArgs
{
    Buffer hostStack;
    Buffer hostHeap;
    Buffer enclaveMemory;
    Buffer enclaveHostMemory;
} BoundaryArgs;

#endif /* _MEMORY_TESTS_H */
