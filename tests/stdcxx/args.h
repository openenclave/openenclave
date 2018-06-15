// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _stdc_args_h
#define _stdc_args_h

#include <stddef.h>

typedef struct _test_args
{
    int ret;
    bool caught;
    bool dynamicCastWorks;
    size_t numConstructions;
} TestArgs;

#endif /* _stdc_args_h */
