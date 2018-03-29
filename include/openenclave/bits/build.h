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
#include "elf.h"

OE_EXTERNC_BEGIN

#define OE_SGX_MAX_TCS 32

typedef struct _OE_Enclave OE_Enclave;

OE_SGXDevice* __OE_OpenSGXDriver(bool simulate);

OE_SGXDevice* __OE_OpenSGXMeasurer(void);

OE_Result __OE_BuildEnclave(
    OE_SGXDevice* dev,
    const char* path,
    const OE_EnclaveProperties_SGX* properties,
    bool debug,
    bool simulate,
    OE_Enclave* enclave);

void _OE_NotifyGdbEnclaveCreation(
    const OE_Enclave* enclave,
    const char* enclavePath,
    uint32_t enclavePathLength);

void _OE_NotifyGdbEnclaveTermination(
    const OE_Enclave* enclave,
    const char* enclavePath,
    uint32_t enclavePathLength);

/**
 * Find OE_EnclaveProperties_SGX struct within .oeinfo section
 *
 * This function attempts to find the OE_EnclaveProperties_SGX struct within
 * the .oeinfo section of an ELF binary.
 *
 * @param elf ELF instance
 * @param properties pointer to properties struct on successful return
 *
 * @returns OE_OK
 * @returns OE_INVALID_PARAMETER null parameter
 * @returns OE_FAILURE .oeinfo section not found
 * @returns OE_NOT_FOUND SGX properties struct not found
 *
 */
OE_Result OE_LoadSGXEnclaveProperties(
    const Elf64* elf,
    OE_EnclaveProperties_SGX** properties);

OE_EXTERNC_END

#endif /* _OE_BUILD_H */
