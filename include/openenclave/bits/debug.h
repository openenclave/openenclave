// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_DEBUG_H
#define _OE_DEBUG_H

#include "sgxtypes.h"

OE_EXTERNC_BEGIN

typedef struct _OE_Enclave OE_Enclave;

void _OE_NotifyGdbEnclaveCreation(
    const OE_Enclave* enclave,
    const char* enclavePath,
    uint32_t enclavePathLength);

void _OE_NotifyGdbEnclaveTermination(
    const OE_Enclave* enclave,
    const char* enclavePath,
    uint32_t enclavePathLength);

OE_EXTERNC_END

#endif /* _OE_DEBUG_H */
