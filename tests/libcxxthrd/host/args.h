// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _RUNTEST_ARGS_H
#define _RUNTEST_ARGS_H

typedef struct _Args
{
    const char* test;
    int ret;
} Args;

typedef struct _my_pthread_args
{
    pthread_t* thread;
    const pthread_attr_t* attr;
    void* (*enc_func_ptr)(void*);
    void* arg;
} my_pthread_args_t;
  
#endif /* _RUNTEST_ARGS_H */
