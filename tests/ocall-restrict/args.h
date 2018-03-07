// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <openenclave/bits/calls.h>

typedef struct
{
    OE_Result result;
    OE_CallHostArgs callHost;
    char _fnNameBuffer[50];
} TestORArgs;
