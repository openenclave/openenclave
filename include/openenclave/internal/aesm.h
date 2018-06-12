// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_AESM_H
#define _OE_AESM_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include "sgxtypes.h"

OE_EXTERNC_BEGIN

typedef struct _AESM AESM;
typedef struct _sgx_target_info sgx_target_info_t;
typedef struct _sgx_epid_group_id sgx_epid_group_id_t;

AESM* AESMConnect(void);

void AESMDisconnect(AESM* aesm);

oe_result_t AESMGetLaunchToken(
    AESM* aesm,
    uint8_t mrenclave[OE_SHA256_SIZE],
    uint8_t modulus[OE_KEY_SIZE],
    const sgx_attributes_t* attributes,
    sgx_launch_token_t* launchToken);

oe_result_t AESMInitQuote(
    AESM* aesm,
    sgx_target_info_t* targetInfo,
    sgx_epid_group_id_t* epidGroupID);

oe_result_t AESMGetQuote(
    AESM* aesm,
    const sgx_report_t* report,
    sgx_quote_type_t quoteType,
    const sgx_spid_t* spid,
    const sgx_nonce_t* nonce,
    const uint8_t* signatureRevocationList,
    uint32_t signatureRevocationListSize,
    sgx_report_t* reportOut,
    sgx_quote_t* quote,
    size_t quoteSize);

OE_EXTERNC_END

#endif /* _OE_AESM_H */
