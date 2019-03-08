// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_REVOCATION_H
#define _OE_COMMON_REVOCATION_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/report.h>

OE_EXTERNC_BEGIN

oe_result_t oe_enforce_revocation(
    oe_cert_t* leaf_cert,
    oe_cert_t* intermediate_cert,
    oe_cert_chain_t* pck_cert_chain);

// Fetch revocation info using the specified args structure.
oe_result_t oe_get_revocation_info(oe_get_revocation_info_args_t* args);

// Cleanup the args structure.
void oe_cleanup_get_revocation_info_args(oe_get_revocation_info_args_t* args);

OE_EXTERNC_END

#endif // _OE_COMMON_REVOCATION_H
