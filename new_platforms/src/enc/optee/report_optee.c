/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openenclave/enclave.h>
#include <mbedtls/x509_crt.h>

#include "cyres_optee.h"
#include "enclavelibc.h"

oe_result_t oe_parse_report_internal(
    mbedtls_x509_crt* chain,
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    oe_report_t* parsed_report);

oe_result_t oe_get_report_v2(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    if (report_buffer == NULL || report_buffer_size == NULL)
        return OE_INVALID_PARAMETER;

    return get_cyres_cert_chain(report_buffer, report_buffer_size);
}

// TODO add support for remote attestation
oe_result_t oe_verify_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_OK;

    mbedtls_x509_crt chain = {0};
    mbedtls_x509_crt local_chain = {0};

    mbedtls_x509_crt_init(&chain);
    int res = mbedtls_x509_crt_parse(&chain, report, report_size);
    if (res != 0)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    // validate the cert chain contains CyReS measurements

    result = oe_parse_report_internal(&chain, report, report_size, parsed_report);
    if (result != OE_OK)
    {
        goto Cleanup;
    }

    // validate the chain is properly rooted
    {
        mbedtls_x509_crt* root = &chain;
        while (root->next)
            root = root->next;

        uint32_t validation_flags = 0;
        res = mbedtls_x509_crt_verify(
            &chain, root, NULL, NULL, &validation_flags, NULL, NULL);
        if (res != 0 || validation_flags != 0)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }
    }

    // validate the parent cert is matching
    {
        uint8_t* local_report;
        size_t local_report_size;
        result = oe_get_report_v2(
            0, NULL, 0, NULL, 0, &local_report, &local_report_size);
        if (result != OE_OK)
        {
            goto Cleanup;
        }

        mbedtls_x509_crt_init(&local_chain);
        res = mbedtls_x509_crt_parse(&local_chain, local_report, local_report_size);
        if (res != 0)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }

        if (local_chain.next == NULL)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }

        if (memcmp(chain.next->raw.p, local_chain.next->raw.p, local_chain.next->raw.len))
        {
            result = OE_FAILURE;
            goto Cleanup;
        }
    }

Cleanup:
    mbedtls_x509_crt_free(&chain);
    mbedtls_x509_crt_free(&local_chain);

    return result;
}
