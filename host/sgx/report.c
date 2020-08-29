// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>

#include "platform_u.h"

static const oe_uuid_t _uuid_sgx_ecdsa = {OE_FORMAT_UUID_SGX_ECDSA};
// Host version, supports ECDSA remote attestation natively.
// for SGX local attestation, it makes ecall to the enclave.
oe_result_t oe_verify_report(
    oe_enclave_t* enclave,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_header_t* header = (oe_report_header_t*)report;
    oe_verifier_t* verifier = NULL;

    if (!report || !report_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        const oe_uuid_t* uuid = &_uuid_sgx_ecdsa;

        OE_UNUSED(enclave);

        oe_verifier_initialize();

        OE_CHECK(oe_find_verifier_plugin(uuid, &verifier));

        OE_CHECK(verifier->verify_report(
            verifier, report, report_size, parsed_report));

        result = OE_OK;
    }
    else if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
    {
        if (!enclave)
            OE_RAISE(OE_INVALID_PARAMETER);

        OE_CHECK(oe_verify_local_report_ecall(
            enclave, &result, report, report_size, parsed_report));
        OE_CHECK(result);
    }
    else
        OE_RAISE(OE_UNSUPPORTED);

done:
    if (result == OE_UNSUPPORTED)
        OE_TRACE_WARNING("oe_verify_local_report_ecall is not supported. To "
                         "enable, please add\n\n"
                         "from \"openenclave/edl/sgx/attestation.edl\" import "
                         "oe_verify_local_report_ecall;\n\n"
                         "in the edl file.\n");

    return result;
}

oe_result_t oe_get_report_v2(
    oe_enclave_t* enclave,
    uint32_t flags,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* report = NULL;
    size_t report_size = 0;

    if (!enclave || !report_buffer || !report_buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_get_report_v2_ecall(
        enclave,
        &result,
        flags,
        opt_params,
        opt_params_size,
        &report,
        &report_size));
    OE_CHECK(result);

    *report_buffer = report;
    *report_buffer_size = report_size;
    report = NULL;

    result = OE_OK;

done:
    if (report)
        oe_free_report(report);

    if (result == OE_UNSUPPORTED)
        OE_TRACE_WARNING(
            "SGX remote attestation is not enabled. To enable, please add\n\n"
            "from \"openenclave/edl/sgx/attestation.edl\" import *;\n\n"
            "in the edl file.\n");

    return result;
}
