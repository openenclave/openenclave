// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _cpp_exception_args_h
#define _cpp_exception_args_h

#include <stddef.h>

typedef enum _unhandled_exception_func_num {
    EXCEPTION_SPECIFICATION,
    EXCEPTION_IN_UNWIND,
    UNHANDLED_EXCEPTION,
} unhandled_exception_func_num;

typedef struct _args
{
    unhandled_exception_func_num func_num;
    int ret;
} Args;

#endif /* _stdc_args_h */
