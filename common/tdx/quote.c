// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/tdx/evidence.h>
#include <openenclave/bits/tdx/tdxquote.h>
#include <openenclave/internal/raise.h>

#include "../common.h"
#include "quote.h"

#ifdef OE_BUILD_ENCLAVE
#include "../../enclave/sgx/tdx_verifier.h"
#else
#include "../../host/tdx/quote.h"
#endif

// Max length of SGX DCAP QVL/QvE returned supplemental data
#define MAX_SUPPLEMENTAL_DATA_SIZE 1000

static const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_TDX_QUOTE_ECDSA};

oe_result_t oe_verify_quote_with_tdx_endorsements(
    const uint8_t* quote,
    size_t quote_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    oe_datetime_t* input_validation_time,
    uint32_t* verification_result,
    uint8_t** supplemental_data,
    size_t* supplemental_data_size)
{
    oe_result_t result = OE_UNEXPECTED;

    uint32_t collateral_expiration_status;
    uint32_t quote_verification_result;
    uint8_t supplemental_data_out[MAX_SUPPLEMENTAL_DATA_SIZE] = {0};
    uint32_t supplemental_data_size_out = 0;
    oe_datetime_t validation_time = {0};
    time_t expiration_check_date = 0;

    // quote size should fit into uint32 required by QVL/QvE
    if (quote_size > OE_UINT32_MAX || endorsements_size > OE_UINT32_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (input_validation_time)
    {
        validation_time = *input_validation_time;
    }
    else
    {
        // Use untrusted time if we cannot get time from inputs
        OE_CHECK(oe_datetime_now(&validation_time));
    }

    oe_datetime_log("Validation datetime: ", &validation_time);

    // Convert validation time to time_t
    OE_CHECK(oe_datetime_to_time_t(&validation_time, &expiration_check_date));

    // Call SGX DCAP QVL/QvE to verify quote
    OE_CHECK(tdx_verify_quote(
        &_ecdsa_uuid,
        NULL,
        0,
        quote,
        (uint32_t)quote_size,
        endorsements,
        (uint32_t)endorsements_size,
        expiration_check_date,
        &collateral_expiration_status,
        &quote_verification_result,
        NULL,
        0,
        supplemental_data_out,
        MAX_SUPPLEMENTAL_DATA_SIZE,
        &supplemental_data_size_out));

    OE_TRACE_INFO(
        "collateral_expiration_status: %d\n", collateral_expiration_status);

    if (verification_result)
        *verification_result = quote_verification_result;

    if (supplemental_data && supplemental_data_size)
    {
        *supplemental_data = (uint8_t*)oe_malloc(supplemental_data_size_out);
        if (!*supplemental_data)
            OE_RAISE(OE_OUT_OF_MEMORY);

        memcpy(
            *supplemental_data,
            supplemental_data_out,
            supplemental_data_size_out);

        *supplemental_data_size = supplemental_data_size_out;
    }

    if (collateral_expiration_status == 0)
    {
        result = OE_OK;
    }
    else
    {
        OE_TRACE_ERROR(
            "Collateral possibly expired! Expected status: 0, got: %u\n",
            collateral_expiration_status);
        result = OE_VERIFY_FAILED;
    }

done:
    return result;
}
