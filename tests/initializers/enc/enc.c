// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/properties.h>
#include <openenclave/enclave.h>
#include <string.h>

#include "../args.h"

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

OE_ECALL void get_globals(void* args)
{
    global_args* gargs = (global_args*)args;
    if (!gargs)
        return;

    if (gargs->get_default)
    {
        gargs->global_int = default_int;
        gargs->global_float = default_float;
        gargs->global_ptr = default_ptr;
        gargs->global_struct = default_struct;
        gargs->global_union = default_union;
        memcpy(
            gargs->global_array,
            default_array,
            GLOBAL_ARRAY_SIZE * sizeof(int));
    }
    else
    {
        gargs->global_int = explicit_int;
        gargs->global_float = explicit_float;
        gargs->global_ptr = explicit_ptr;
        gargs->global_struct = explicit_struct;
        gargs->global_union = explicit_union;
        memcpy(
            gargs->global_array,
            explicit_array,
            GLOBAL_ARRAY_SIZE * sizeof(int));
    }
}

OE_ECALL void set_globals(void* args)
{
    global_args* gargs = (global_args*)args;
    if (!gargs)
        return;

    if (gargs->get_default)
    {
        default_int = gargs->global_int;
        default_float = gargs->global_float;
        default_ptr = gargs->global_ptr;
        default_struct = gargs->global_struct;
        default_union = gargs->global_union;
        memcpy(
            default_array,
            gargs->global_array,
            GLOBAL_ARRAY_SIZE * sizeof(int));
    }
    else
    {
        explicit_int = gargs->global_int;
        explicit_float = gargs->global_float;
        explicit_ptr = gargs->global_ptr;
        explicit_struct = gargs->global_struct;
        explicit_union = gargs->global_union;
        memcpy(
            explicit_array,
            gargs->global_array,
            GLOBAL_ARRAY_SIZE * sizeof(int));
    }
}

OE_SET_ENCLAVE_SGX(
    1234,   /* ProductID */
    5678,   /* SecurityVersion */
    true,   /* AllowDebug */
    131072, /* HeapPageCount */
    512,    /* StackPageCount */
    4);     /* TCSCount */
