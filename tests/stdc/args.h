// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _stdc_args_h
#define _stdc_args_h

#include <stddef.h>

typedef struct _test_args
{
    char buf1[1024];
    char buf2[1024];
    int strdupOk;
} TestArgs;

#endif /* _stdc_args_h */
