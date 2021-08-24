// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_COMMON_TLSPARSER_H
#define _OE_COMMON_TLSPARSER_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

oe_result_t oe_parse_evidence_with_inittime_claims(
    uint8_t* evidence_with_inittime_claims,
    size_t evidence_with_inittime_claims_size,
    uint8_t** output_evidence_buffer,
    size_t* output_evidence_buffer_size,
    uint8_t** output_inittime_custom_claims_buffer,
    size_t* output_inittime_custom_claims_buffer_size,
    uint8_t** output_runtime_custom_claims_buffer,
    size_t* output_runtime_custom_claims_buffer_size);

OE_EXTERNC_END

#endif // _OE_COMMON_TLSPARSER_H
