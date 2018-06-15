// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <openenclave/internal/calls.h>

typedef struct
{
    oe_result_t result;
    oe_call_host_args_t call_host;
    char _fn_name_buffer[50];
} TestORArgs;
