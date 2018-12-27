// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ocalls.h"
#include <openenclave/internal/calls.h>
#include <stdio.h>

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
