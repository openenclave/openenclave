// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H

typedef struct _args
{
    const char* in;
    int testEh;
    int depth;
    char* out;
    int ret;
} Args;

#endif /* _ARGS_H */
