// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SGXCREATE_H
#define _OE_SGXCREATE_H

#include <openenclave/result.h>
#include "elf.h"
#include "sgxtypes.h"
#include "sha.h"

OE_EXTERNC_BEGIN

typedef struct _oe_enclave oe_enclave_t;

typedef enum _oe_sgx_load_type {
    OE_SGX_LOAD_TYPE_UNDEFINED,
    OE_SGX_LOAD_TYPE_CREATE,
    OE_SGX_LOAD_TYPE_MEASURE
} oe_sgx_load_type_t;

typedef enum _oe_sgx_load_state {
    OE_SGX_LOAD_STATE_UNINITIALIZED,
    OE_SGX_LOAD_STATE_INITIALIZED,
    OE_SGX_LOAD_STATE_ENCLAVE_CREATED,
    OE_SGX_LOAD_STATE_ENCLAVE_INITIALIZED,
} oe_sgx_load_state_t;

typedef struct _oe_sgx_load_context
{
    oe_sgx_load_type_t type;
    oe_sgx_load_state_t state;

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
    oe_sha256_context_t hashContext;
} oe_sgx_load_context_t;

oe_result_t oe_sgx_initialize_load_context(
    oe_sgx_load_context_t* context,
    oe_sgx_load_type_t type,
    uint32_t attributes);

void oe_sgx_cleanup_load_context(oe_sgx_load_context_t* context);

oe_result_t oe_sgx_build_enclave(
    oe_sgx_load_context_t* context,
    const char* path,
    const oe_sgx_enclave_properties_t* properties,
    oe_enclave_t* enclave);

/**
 * Find the oe_sgx_enclave_properties_t struct within the given section
 *
 * This function attempts to find the **oe_sgx_enclave_properties_t** struct within
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
oe_result_t oe_sgx_load_properties(
    const Elf64* elf,
    const char* sectionName,
    oe_sgx_enclave_properties_t* properties);

/**
 * Update the oe_sgx_enclave_properties_t struct within the given section
 *
 * This function attempts to update the **oe_sgx_enclave_properties_t** struct
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
oe_result_t oe_sgx_update_enclave_properties(
    const Elf64* elf,
    const char* sectionName,
    const oe_sgx_enclave_properties_t* properties);

/**
 * Validate certain fields of an SGX enclave properties structure.
 *
 * This function checks whether the following fields of the
 * **oe_sgx_enclave_properties_t** structure have valid values.
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
oe_result_t oe_sgx_validate_enclave_properties(
    const oe_sgx_enclave_properties_t* properties,
    const char** fieldName);

OE_EXTERNC_END

#endif /* _OE_SGXCREATE_H */
