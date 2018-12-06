// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/properties.h>
#include <openenclave/enclave.h>
#include <string.h>

#include <stdio.h>

#include "initializers_t.h"

/* C static initialization defaults to the 0 / NULL type. */
static int default_int;
static float default_float;
static int* default_ptr;
static dummy_struct default_struct;
static dummy_union default_union;
static int default_array[4];

/* Explicit C static initialization. */
static int explicit_int = 1;
static float explicit_float = 1.0;
static int* explicit_ptr = (int*)0x1;
static dummy_struct explicit_struct = {1, 1};
static dummy_union explicit_union = {.y = 1};
static int explicit_array[4] = {1, 1, 1, 1};

void get_globals(
    int* global_int,
    float* global_float,
    int** global_ptr,
    dummy_struct* global_struct,
    dummy_union* global_union,
    int global_array[4],
    bool get_default)
{
    if (get_default)
    {
        *global_int = default_int;
        *global_float = default_float;
        *global_ptr = default_ptr;
        *global_struct = default_struct;
        *global_union = default_union;
        memcpy(global_array, default_array, 4 * sizeof(int));
    }
    else
    {
        *global_int = explicit_int;
        *global_float = explicit_float;
        *global_ptr = explicit_ptr;
        *global_struct = explicit_struct;
        *global_union = explicit_union;
        memcpy(global_array, explicit_array, 4 * sizeof(int));
    }
}

void set_globals(
    int global_int,
    float global_float,
    int* global_ptr,
    dummy_struct global_struct,
    dummy_union global_union,
    int global_array[4],
    bool set_default)
{
    if (set_default)
    {
        default_int = global_int;
        default_float = global_float;
        default_ptr = global_ptr;
        default_struct = global_struct;
        default_union = global_union;
        memcpy(default_array, global_array, 4 * sizeof(int));
    }
    else
    {
        explicit_int = global_int;
        explicit_float = global_float;
        explicit_ptr = global_ptr;
        explicit_struct = global_struct;
        explicit_union = global_union;
        memcpy(explicit_array, global_array, 4 * sizeof(int));
    }
}

OE_SET_ENCLAVE_SGX(
    1234, /* ProductID */
    5678, /* SecurityVersion */
    true, /* AllowDebug */
    128,  /* HeapPageCount */
    64,   /* StackPageCount */
    4);   /* TCSCount */
