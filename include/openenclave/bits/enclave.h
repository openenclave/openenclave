// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_ENCLAVE_H
#define _OE_BITS_ENCLAVE_H

/*
**==============================================================================
**
** oe_init_enclave_args_t
**
**     Runtime state to initialize enclave state with, includes
**     - First 8 leaves of CPUID for enclave emulation
**
**==============================================================================
*/

typedef struct _oe_init_enclave_args
{
    uint32_t cpuidTable[OE_CPUID_LEAF_COUNT][OE_CPUID_REG_COUNT];
} oe_init_enclave_args_t;

#endif//_OE_BITS_ENCLAVE_H