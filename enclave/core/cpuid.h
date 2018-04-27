// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CPUID_ENCLAVE_H
#define _OE_CPUID_ENCLAVE_H

#include <openenclave/types.h>

void OE_InitializeCpuid(uint64_t argIn);

int OE_EmulateCpuid(uint64_t* rax, uint64_t* rbx, uint64_t* rcx, uint64_t* rdx);

#endif /* _OE_CPUID_ENCLAVE_H */
