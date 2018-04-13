// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SGXCREATE_H
#define _OE_SGXCREATE_H

#include <openenclave/result.h>
#include "elf.h"
#include "sgxtypes.h"
#include "sha.h"

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
    const OE_SGXEnclaveProperties* properties,
    OE_Enclave* enclave);

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

#endif /* _OE_SGXCREATE_H */
