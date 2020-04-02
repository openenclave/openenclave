// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file properties.h
 *
 * This file defines the properties for an enclave.
 *
 * Only enclave properties that are common to all enclave types should be
 * defined in this file. These properties can be overwritten at sign time by the
 * oesign tool.
 */

#ifndef _OE_BITS_PROPERTIES_H
#define _OE_BITS_PROPERTIES_H

#include "defs.h"
#include "result.h"
#include "types.h"

OE_EXTERNC_BEGIN

/**
 * @cond DEV
 */
/* Injected by OE_SET_ENCLAVE_SGX macro and by the signing tool (oesign) */
#define OE_INFO_SECTION_NAME ".oeinfo"

typedef struct _oe_enclave_size_settings
{
    uint64_t num_heap_pages;
    uint64_t num_stack_pages;
    uint64_t num_tcs;
} oe_enclave_size_settings_t;

/* Base type for enclave properties */
typedef struct _oe_enclave_properties_header
{
    uint32_t size; /**< (0) Size of the extended structure */

    oe_enclave_type_t enclave_type; /**< (4) Enclave type */

    oe_enclave_size_settings_t size_settings; /**< (8) Enclave settings */
} oe_enclave_properties_header_t;

/**
 * @endcond
 */

/**
 * define the OE_SET_ENCLAVE_SGX macro. Only define on platforms that SGX is
 * supported on, otherwise define it to be nothing.
 */
#if __x86_64__ || _M_X64
#include "sgx/sgxproperties.h"
#else
#define OE_SET_ENCLAVE_SGX( \
    PRODUCT_ID,             \
    SECURITY_VERSION,       \
    ALLOW_DEBUG,            \
    HEAP_PAGE_COUNT,        \
    STACK_PAGE_COUNT,       \
    TCS_COUNT)
#endif

#if __aarch64__
#include "optee/opteeproperties.h"
#else
#define OE_SET_ENCLAVE_OPTEE( \
    UUID, HEAP_SIZE, STACK_SIZE, FLAGS, VERSION, DESCRIPTION)
#endif

/**
 * @cond DEV
 */

/**
 * This function sets the minimum value of issue dates of CRL and TCB info
 * accepted by the enclave. CRL and TCB info issued before this date
 * are rejected for attestation.
 * This function is not thread safe.
 * Results of calling this function multiple times from within an enclave
 * are undefined.
 */
oe_result_t __oe_sgx_set_minimum_crl_tcb_issue_date(
    uint32_t year,
    uint32_t month,
    uint32_t day,
    uint32_t hours,
    uint32_t minutes,
    uint32_t seconds);

/**
 * @endcond
 */
OE_EXTERNC_END

#endif /* _OE_BITS_PROPERTIES_H */
