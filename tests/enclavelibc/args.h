// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H

typedef struct _args
{
    int ret;

    const char* ctype_func;
    int ctype_arg;
    int ctype_value;
} args_t;

typedef struct _ctype_args
{
    int c;
    int ret;
} ctype_args_t;

#endif /* _ARGS_H */
