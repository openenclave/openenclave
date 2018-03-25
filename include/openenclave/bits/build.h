// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BUILD_H
#define _OE_BUILD_H

#include <openenclave/bits/sha.h>
#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>
#include "sgxdev.h"
#include "sgxtypes.h"

OE_EXTERNC_BEGIN

typedef struct _OE_Enclave OE_Enclave;

typedef enum _OE_SgxLoadType {
    OE_SGXLOAD_UNDEFINED,
    OE_SGXLOAD_CREATE,
    OE_SGXLOAD_MEASURE
} OE_SgxLoadType;

typedef enum _OE_SgxLoadState {
    OE_SGXLOAD_UNINITIALIZED,
    OE_SGXLOAD_INITIALIZED,
    OE_SGXLOAD_ENCLAVE_CREATED,
    OE_SGXLOAD_ENCLAVE_INITIALIZED,
} OE_SgxLoadState;

typedef struct _OE_SgxLoadContext
{
    OE_SgxLoadType type;
    OE_SgxLoadState state;

    /* OE_FLAG bits to be applied to the enclave such as debug */
    uint32_t attributes;

    /* Fields used when attributes contain OE_FLAG_SIMULATION */
    struct _Simulate
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
} OE_SgxLoadContext;

OE_Result _InitializeLoadContext(
    OE_SgxLoadContext* context,
    OE_SgxLoadType type,
    uint32_t attributes);

void _CleanupLoadContext(OE_SgxLoadContext* context);

OE_Result __OE_BuildEnclave(
    OE_SgxLoadContext* context,
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
