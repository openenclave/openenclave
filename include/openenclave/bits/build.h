// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BUILD_H
#define _OE_BUILD_H

#include <openenclave/bits/sha.h>
#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>
#include "sgxtypes.h"

OE_EXTERNC_BEGIN

typedef struct _OE_Enclave OE_Enclave;

typedef enum _OE_SGXLoadType {
    OE_SGX_LOADTYPE_UNDEFINED,
    OE_SGX_LOADTYPE_CREATE,
    OE_SGX_LOADTYPE_MEASURE
} OE_SGXLoadType;

typedef enum _OE_SGXLoadState {
    OE_SGX_LOADSTATE_UNINITIALIZED,
    OE_SGX_LOADSTATE_INITIALIZED,
    OE_SGX_LOADSTATE_ENCLAVE_CREATED,
    OE_SGX_LOADSTATE_ENCLAVE_INITIALIZED,
} OE_SGXLoadState;

typedef struct _OE_SGXLoadContext
{
    OE_SGXLoadType type;
    OE_SGXLoadState state;

    /* OE_FLAG bits to be applied to the enclave such as debug */
    uint32_t attributes;

    /* Fields used when attributes contain OE_FLAG_SIMULATION */
    struct
    {
        /* Base address of enclave */
        void* addr;

        /* Size of enclave in bytes */
        size_t size;
    } sim;

    /* Handle to isgx driver when creating enclave on Linux */
    int dev;

    /* Hash context used to measure enclave as it is loaded */
    OE_SHA256Context hashContext;
} OE_SGXLoadContext;

OE_Result OE_SGXInitializeLoadContext(
    OE_SGXLoadContext* context,
    OE_SGXLoadType type,
    uint32_t attributes);

void OE_SGXCleanupLoadContext(OE_SGXLoadContext* context);

OE_Result OE_SGXBuildEnclave(
    OE_SGXLoadContext* context,
    const char* path,
    const OE_EnclaveSettings* settings,
    OE_Enclave* enclave);

void _OE_NotifyGdbEnclaveCreation(
    const OE_Enclave* enclave,
    const char* enclavePath,
    uint32_t enclavePathLength);

void _OE_NotifyGdbEnclaveTermination(
    const OE_Enclave* enclave,
    const char* enclavePath,
    uint32_t enclavePathLength);

OE_EXTERNC_END

#endif /* _OE_BUILD_H */
