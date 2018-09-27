// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _INITIALIZER_TESTS_H
#define _INITIALIZER_TESTS_H

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

#endif /* _INITIALIZER_TESTS_H */
