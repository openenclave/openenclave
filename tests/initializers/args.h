// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _INITIALIZER_TESTS_H
#define _INITIALIZER_TESTS_H

/* Defintions for checking global variables. */
#define GLOBAL_ARRAY_SIZE 4

typedef struct _dummy_struct
{
    int32_t a;
    int32_t b;
} dummy_struct;

typedef union _dummy_union {
    dummy_struct x;
    int64_t y;
} dummy_union;

typedef struct _global_args
{
    int global_int;
    float global_float;
    int* global_ptr;
    dummy_struct global_struct;
    dummy_union global_union;
    int global_array[GLOBAL_ARRAY_SIZE];
    bool get_default;
} global_args;

#endif /* _INITIALIZER_TESTS_H */
