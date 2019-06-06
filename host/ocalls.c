// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>

#include <openenclave/internal/calls.h>
#include <openenclave/internal/trace.h>

#include "ocalls.h"

void HandleMalloc(uint64_t arg_in, uint64_t* arg_out)
{
    if (arg_out)
        *arg_out = (uint64_t)malloc(arg_in);
}

void HandleRealloc(uint64_t arg_in, uint64_t* arg_out)
{
    oe_realloc_args_t* args = (oe_realloc_args_t*)arg_in;

    if (args)
    {
        if (arg_out)
            *arg_out = (uint64_t)realloc(args->ptr, args->size);
    }
}

void HandleFree(uint64_t arg)
{
    free((void*)arg);
}

void HandlePrint(uint64_t arg_in)
{
    oe_print_args_t* args = (oe_print_args_t*)arg_in;

    if (args)
    {
        if (args->device == 0)
        {
            fprintf(stdout, "%s", args->str);
            fflush(stdout);
        }
        else if (args->device == 1)
        {
            fprintf(stderr, "%s", args->str);
            fflush(stderr);
        }
    }
}
