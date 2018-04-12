// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BUILD_H
#define _OE_BUILD_H

#include <openenclave/bits/sha.h>
#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>
#include "elf.h"
#include "sgxdev.h"
#include "sgxtypes.h"

OE_EXTERNC_BEGIN

#define OE_SGX_MAX_TCS 32

typedef struct _OE_Enclave OE_Enclave;

OE_SGXDevice* __OE_OpenSGXDriver(bool simulate);

OE_SGXDevice* __OE_OpenSGXMeasurer(void);

OE_Result __OE_BuildEnclave(
    OE_SGXDevice* dev,
    const char* path,
    const OE_SGXEnclaveProperties* properties,
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
 * Find the OE_SGXEnclaveProperties struct within the given section
 *
 * This function attempts to find the **OE_SGXEnclaveProperties** struct within
 * the specified section of the ELF binary.
 *
 * @param elf ELF instance
 * @param sectionName name of section to search for enclave properties
 * @param properties pointer where enclave properties are copied
 *
 * @returns OE_OK
 * @returns OE_INVALID_PARAMETER null parameter
 * @returns OE_FAILURE section was not found
 * @returns OE_NOT_FOUND enclave properties struct not found
 *
 */
OE_Result OE_SGXLoadProperties(
    const Elf64* elf,
    const char* sectionName,
    OE_SGXEnclaveProperties* properties);

/**
 * Update the OE_SGXEnclaveProperties struct within the given section
 *
 * This function attempts to update the **OE_SGXEnclaveProperties** struct
 * within the specified section of the ELF binary. If found, the section is
 * updated with the value of the **properties** parameter.
 *
 * @param elf ELF instance
 * @param sectionName name of section to search for enclave properties
 * @param properties new value of enclave properties
 *
 * @returns OE_OK
 * @returns OE_INVALID_PARAMETER null parameter
 * @returns OE_FAILURE section was not found
 * @returns OE_NOT_FOUND enclave properties struct not found
 *
 */
OE_Result OE_SGXUpdateEnclaveProperties(
    const Elf64* elf,
    const char* sectionName,
    const OE_SGXEnclaveProperties* properties);

/**
 * Validate certain fields of an SGX enclave properties structure.
 *
 * This function checks whether the following fields of the
 * **OE_SGXEnclaveProperties** structure have valid values.
 *
 *     - productID
 *     - securityVersion
 *     - numStackPages
 *     - numHeapPages
 *     - numTCS
 *
 * If not the **fieldName** output parameter points to the name of the first
 * field with an invalid value.
 *
 * @param properties SGX enclave properties
 * @param fieldName[output] name of first invalid field (may be null)
 *
 * @returns OE_OK
 * @returns OE_INVALID_PARAMETER a parameter is null
 * @returns OE_FAILURE at least one field is invalid
 *
 */
OE_Result OE_SGXValidateEnclaveProperties(
    const OE_SGXEnclaveProperties* properties,
    const char** fieldName);

OE_EXTERNC_END

#endif /* _OE_BUILD_H */
