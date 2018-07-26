// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_TCBINFO_H
#define _OE_COMMON_TCBINFO_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/sgxcertextensions.h>

OE_EXTERNC_BEGIN

typedef enum _oe_tcb_status {
    OE_TCB_STATUS_REVOKED,
    OE_TCB_STATUS_OUT_OF_DATE,
    OE_TCB_STATUS_UP_TO_DATE
} oe_tcb_status_t;

typedef struct _oe_tcb
{
    bool is_specified;
    uint64_t sgx_tcb_comp_svn[16];
    uint64_t pce_svn;
    oe_tcb_status_t status;
} oe_tcb_t;

typedef struct _oe_parsed_tcb_info
{
    uint32_t version;
    const uint8_t* issue_date;
    uint32_t issue_date_size;
    uint8_t fmspc[6];
    oe_tcb_t aggregated_uptodate_tcb;
    oe_tcb_t aggregated_outofdate_tcb;
    oe_tcb_t aggregated_revoked_tcb;
    uint8_t signature[64];
    const uint8_t* tcb_info_start;
    const uint8_t* tcb_info_end;
} oe_parsed_tcb_info_t;

oe_result_t oe_parse_tcb_info_json(
    const uint8_t* tcb_info_json,
    uint32_t tcb_info_json_size,
    oe_parsed_tcb_info_t* parsed_info);

oe_result_t oe_enforce_tcb_info(
    const uint8_t* tcb_info_json,
    uint32_t tcb_info_json_size,
    ParsedExtensionInfo* parsed_extention_info,
    bool require_uptodate,
    oe_parsed_tcb_info_t* parsed_tcb_info);

oe_result_t oe_verify_tcb_signature(
    const uint8_t* tcb_info_json,
    uint32_t tcb_info_json_size,
    oe_parsed_tcb_info_t* parsed_tcb_info,
    uint8_t* buffer,
    uint32_t bufferSize,
    oe_cert_chain_t* tcb_cert_chain);

OE_EXTERNC_END

#endif // _OE_COMMON_TCBINFO_H
