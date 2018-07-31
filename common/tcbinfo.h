// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_TCBINFO_H
#define _OE_COMMON_TCBINFO_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/sgxtypes.h>

OE_EXTERNC_BEGIN

typedef enum _oe_tcb_level_status {
    OE_TCB_LEVEL_STATUS_UNKNOWN,
    OE_TCB_LEVEL_STATUS_REVOKED,
    OE_TCB_LEVEL_STATUS_OUT_OF_DATE,
    OE_TCB_LEVEL_STATUS_UP_TO_DATE,
    __OE_TCB_LEVEL_MAX = OE_MAX_UINT,
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
    const uint8_t* issue_date;
    uint32_t issue_date_size;
    uint8_t fmspc[6];
    uint8_t signature[64];
    const uint8_t* tcb_info_start;
    uint32_t tcb_info_size;
} oe_parsed_tcb_info_t;

oe_result_t oe_parse_tcb_info_json(
    const uint8_t* tcb_info_json,
    uint32_t tcb_info_json_size,
    oe_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_info);

oe_result_t oe_verify_tcb_signature(
    const uint8_t* tcb_info_start,
    uint32_t tcb_info_size,
    sgx_ecdsa256_signature_t* signature,
    oe_cert_chain_t* tcb_cert_chain);

OE_EXTERNC_END

#endif // _OE_COMMON_TCBINFO_H
