// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _stdc_args_h
#define _stdc_args_h

#include <openenclave/bits/types.h>

typedef struct _TestMutexArgs
{
    size_t count1;
    size_t count2;
} TestMutexArgs;

typedef struct _WaitArgs
{
    /* The number of threads that will call wait */
    size_t numThreads;
} WaitArgs;

typedef struct _TestRWLockArgs
{
    // Number of simultaneously active readers
    size_t readers;

    // Number of simultaneously active writers
    size_t writers;

    // Maximum number of simultaneously active readers
    size_t maxReaders;

    // Maximum number of simultaneously active writers
    size_t maxWriters;

    // Readers and writers active at same time
    bool readersAndWriters;
} TestRWLockArgs;

#endif /* _stdc_args_h */
