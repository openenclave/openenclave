// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _cpp_exception_args_h
#define _cpp_exception_args_h

#include <stddef.h>
#include <atomic>

typedef struct _abort_status_args
{
    std::atomic<uint32_t>* thread_ready_count;
    std::atomic<bool>* is_enclave_crashed;
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
    std::atomic<uint32_t>* thread_ready_count;
    std::atomic<bool>* is_enclave_crashed;
    unsigned flow_id;         // In
    unsigned recursions_left; // InOut
    unsigned initial_count;   // InOut
    uint32_t crc;             // InOut
};

#endif /* _stdc_args_h */
