// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _RUNTEST_ARGS_H
#define _RUNTEST_ARGS_H

typedef struct _args
{
    const char* test;
    int ret;
    int passed;
    int skipped;
    int total;
} Args;

#endif /* _RUNTEST_ARGS_H */
