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

/* Defintions for checking global variables. */
#define GLOBAL_ARRAY_SIZE 4

typedef struct _DummyStruct
{
    int32_t a;
    int32_t b;
} DummyStruct;

typedef union _DummyUnion {
    DummyStruct x;
    int64_t y;
} DummyUnion;

typedef struct _GlobalArgs
{
    int globalInt;
    float globalFloat;
    int* globalPtr;
    DummyStruct globalStruct;
    DummyUnion globalUnion;
    int globalArray[GLOBAL_ARRAY_SIZE];
    bool getDefault;
} GlobalArgs;

#endif /* _MEMORY_TESTS_H */
