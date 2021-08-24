// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../tlsparser.h"

oe_result_t oe_parse_evidence_with_inittime_claims(
    uint8_t* evidence_with_inittime_claims,
    size_t evidence_with_inittime_claims_size,
    uint8_t** output_evidence_buffer,
    size_t* output_evidence_buffer_size,
    uint8_t** output_inittime_custom_claims_buffer,
    size_t* output_inittime_custom_claims_buffer_size,
    uint8_t** output_runtime_custom_claims_buffer,
    size_t* output_runtime_custom_claims_buffer_size)
{
    OE_UNUSED(evidence_with_inittime_claims);
    OE_UNUSED(evidence_with_inittime_claims_size);
    OE_UNUSED(output_evidence_buffer);
    OE_UNUSED(output_evidence_buffer_size);
    OE_UNUSED(output_inittime_custom_claims_buffer);
    OE_UNUSED(output_inittime_custom_claims_buffer_size);
    OE_UNUSED(output_runtime_custom_claims_buffer);
    OE_UNUSED(output_runtime_custom_claims_buffer_size);

    return OE_UNSUPPORTED;
}
