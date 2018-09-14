// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _libcxxthrd_args_h
#define _libcxxthrd_args_h

typedef struct _my_pthread_args
{
    int ret;
    pthread_t host_thread_id;
} my_pthread_args_t;

#endif /* _libcxxthrd_args_h */
