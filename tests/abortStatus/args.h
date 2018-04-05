// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _cpp_exception_args_h
#define _cpp_exception_args_h

#include <stddef.h>

typedef struct _AbortStatusArgs
{
    volatile uint32_t* thread_ready_count;
    volatile uint32_t* is_enclave_crashed;
    int divisor;

    int ret;
} AbortStatusArgs;

enum
{
    TAG_START_HOST,
    TAG_END_HOST,
    TAG_START_ENC,
    TAG_END_ENC,
};

/*
* Used for recursion tests as in/outcall/out buffer in host memory. Host
* provides fresh one with each new recursion.
*/
struct AbortStatusEncRecursionArg
{
    void* enclave;
    volatile uint32_t* thread_ready_count;
    volatile uint32_t* is_enclave_crashed;
    unsigned flowId;         // In
    unsigned recursionsLeft; // InOut
    unsigned initialCount;   // InOut
    uint32_t crc;            // InOut
};

#endif /* _stdc_args_h */
