// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_TCBINFO_H
#define _OE_COMMON_TCBINFO_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/sgxtypes.h>

OE_EXTERNC_BEGIN

#ifdef OE_USE_LIBSGX

typedef enum _oe_tcb_level_status
{
    OE_TCB_LEVEL_STATUS_UNKNOWN,
    OE_TCB_LEVEL_STATUS_REVOKED,
    OE_TCB_LEVEL_STATUS_OUT_OF_DATE,
    OE_TCB_LEVEL_STATUS_CONFIGURATION_NEEDED,
    OE_TCB_LEVEL_STATUS_UP_TO_DATE,
    __OE_TCB_LEVEL_MAX = OE_ENUM_MAX,
} oe_tcb_level_status_t;

typedef struct _oe_tcb_level
{
    uint8_t sgx_tcb_comp_svn[16];
    uint16_t pce_svn;
    oe_tcb_level_status_t status;
} oe_tcb_level_t;

typedef struct _oe_parsed_tcb_info
{
    uint32_t version;
    oe_datetime_t issue_date;
    oe_datetime_t next_update;
    uint8_t fmspc[6];
    uint8_t pceid[2];
    uint8_t signature[64];
    const uint8_t* tcb_info_start;
    size_t tcb_info_size;
} oe_parsed_tcb_info_t;

/**
 * oe_parse_tcb_info_json parses the given tcb info json string
 * and populates the parsed_info structure.
 * Additionally, the status field of the platform_tcb_level parameter is
 * populated.
 *
 * The TCB info is expected to confirm to the TCB Info Json schema published by
 * Intel. For the given platform_tcb_level, the correct status is determined
 * using the following algorithm:
 *
 *    1. Go over the sorted collection of TCB levels in the JSON.
 *    2. Choose the first tcb level for which  all of the platform's comp svn
 *       values and pcesvn values are greater than or equal to corresponding
 *       values of the tcb level.
 *    3. The status of the platform's tcb level is the status of the chosen tcb
 *       level.
 *    4. If no tcb level was chosen, then the status of the platform is unknown.
 *
 * If the plaform's tcb level status was determined to be not uptodate,
 * then OE_TCB_LEVEL_INVALID is returned.
 *
 */
oe_result_t oe_parse_tcb_info_json(
    const uint8_t* tcb_info_json,
    size_t tcb_info_json_size,
    oe_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_info);

oe_result_t oe_verify_ecdsa256_signature(
    const uint8_t* tcb_info_start,
    size_t tcb_info_size,
    sgx_ecdsa256_signature_t* signature,
    oe_cert_chain_t* tcb_cert_chain);

typedef struct _oe_parsed_qe_identity_info
{
    uint32_t version;
    oe_datetime_t issue_date;
    oe_datetime_t next_update;
    uint32_t miscselect;         // The MISCSELECT that must be set
    uint32_t miscselect_mask;    // Mask of MISCSELECT to enforce
    sgx_attributes_t attributes; // flags and xfrm (XSAVE-Feature Request Mask)
    uint64_t attributes_flags_mask;   // mask for attributes.flags
    uint64_t attributes_xfrm_mask;    // mask for attributes.xfrm
    uint8_t mrsigner[OE_SHA256_SIZE]; // MRSIGNER of the enclave
    uint16_t isvprodid;               // ISV assigned Product ID
    uint16_t isvsvn;                  // ISV assigned SVN
    uint8_t signature[64];
    const uint8_t* info_start;
    size_t info_size;
} oe_parsed_qe_identity_info_t;

oe_result_t oe_parse_qe_identity_info_json(
    const uint8_t* info_json,
    size_t info_json_size,
    oe_parsed_qe_identity_info_t* parsed_info);
#endif

OE_EXTERNC_END

#endif // _OE_COMMON_TCBINFO_H
