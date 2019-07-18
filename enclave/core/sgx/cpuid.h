// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CPUID_ENCLAVE_H
#define _OE_CPUID_ENCLAVE_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/calls.h>

int oe_emulate_cpuid(
    uint64_t* rax,
    uint64_t* rbx,
    uint64_t* rcx,
    uint64_t* rdx);

oe_result_t oe_initialize_cpuid(void);

#endif /* _OE_CPUID_ENCLAVE_H */
