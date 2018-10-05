// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_AESM_H
#define _OE_AESM_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include "sgxtypes.h"

OE_EXTERNC_BEGIN

typedef struct _aesm aesm_t;
typedef struct _sgx_target_info sgx_target_info_t;
typedef struct _sgx_epid_group_id sgx_epid_group_id_t;

aesm_t* aesm_connect(void);

void aesm_disconnect(aesm_t* aesm);

oe_result_t aesm_get_launch_token(
    aesm_t* aesm,
    uint8_t mrenclave[OE_SHA256_SIZE],
    uint8_t modulus[OE_KEY_SIZE],
    const sgx_attributes_t* attributes,
    sgx_launch_token_t* launch_token);

oe_result_t aesm_init_quote(
    aesm_t* aesm,
    sgx_target_info_t* target_info,
    sgx_epid_group_id_t* epid_group_id);

oe_result_t aesm_get_quote(
    aesm_t* aesm,
    const sgx_report_t* report,
    sgx_quote_type_t quote_type,
    const sgx_spid_t* spid,
    const sgx_nonce_t* nonce,
    const uint8_t* signature_revocation_list,
    uint32_t signature_revocation_list_size,
    sgx_report_t* report_out,
    sgx_quote_t* quote,
    size_t quote_size);

OE_EXTERNC_END

#endif /* _OE_AESM_H */
