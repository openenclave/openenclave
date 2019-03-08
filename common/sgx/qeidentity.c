// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "qeidentity.h"
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include "../common.h"
#include "tcbinfo.h"

// hardcoded property values used for validating quoting enclave when qe
// identity info is not available
// The mrsigner value of Intel's Production quoting enclave.
static const uint8_t g_qe_mrsigner[32] = {
    0x8c, 0x4f, 0x57, 0x75, 0xd7, 0x96, 0x50, 0x3e, 0x96, 0x13, 0x7f,
    0x77, 0xc6, 0x8a, 0x82, 0x9a, 0x00, 0x56, 0xac, 0x8d, 0xed, 0x70,
    0x14, 0x0b, 0x08, 0x1b, 0x09, 0x44, 0x90, 0xc5, 0x7b, 0xff};

// The isvprodid value of Intel's Production quoting enclave.
static const uint32_t g_qe_isvprodid = 1;

// The isvsvn value of Intel's Production quoting enclave.
static const uint32_t g_qeisvsvn = 1;

extern oe_datetime_t _sgx_minimim_crl_tcb_issue_date;

void dump_info(char* title, uint8_t* data, uint8_t count)
{
    OE_TRACE_INFO("%s\n", title);
    for (uint8_t i = 0; i < count; i++)
    {
        OE_TRACE_INFO("[%d] = %x\n", i, data[i]);
    }
}

oe_result_t oe_enforce_qe_identity(sgx_report_body_t* qe_report_body)
{
    oe_result_t result = OE_FAILURE;
    oe_get_qe_identity_info_args_t qe_id_args = {0};
    const uint8_t* pem_pck_certificate = NULL;
    size_t pem_pck_certificate_size = 0;
    oe_cert_chain_t pck_cert_chain = {0};
    oe_parsed_qe_identity_info_t parsed_info = {0};

    OE_TRACE_INFO("Calling %s\n", __FUNCTION__);

    // fetch qe identity information
    result = oe_get_qe_identity_info(&qe_id_args);
    if (result == OE_QUOTE_PROVIDER_CALL_ERROR)
    {
        // No qe_identity info returned from the quote provider, this could be
        // because either get_qe_identity_info API was not supported or
        // unexpected error. In both cases, check against hardcoded quoting
        // enclave properties instead Assert that the qe report's MRSIGNER
        // matches Intel's quoting. We will remove these hardcoded values once
        // the libdcap_quoteprov.so was updated to support qe identity feature.

        // enclave's mrsigner.
        if (!oe_constant_time_mem_equal(
                qe_report_body->mrsigner, g_qe_mrsigner, sizeof(g_qe_mrsigner)))
            OE_RAISE_MSG(OE_VERIFY_FAILED, "mrsigner mismatch");

        if (qe_report_body->isvprodid != g_qe_isvprodid)
            OE_RAISE_MSG(OE_VERIFY_FAILED, "isvprodid mismatch");

        if (qe_report_body->isvsvn < g_qeisvsvn)
            OE_RAISE_MSG(OE_VERIFY_FAILED, "isvsvn is out-of-date");

        // Ensure that the QE is not a debug supporting enclave.
        if (qe_report_body->attributes.flags & SGX_FLAGS_DEBUG)
            OE_RAISE_MSG(OE_VERIFY_FAILED, "QE has SGX_FLAGS_DEBUG set!!");

        result = OE_OK;
        goto done;
    }
    OE_CHECK(result);

    // Use QE Identity info to validate QE
    // Check against fetched qe identityinfo
    OE_TRACE_INFO("qe_identity.issuer_chain:[%s]\n", qe_id_args.issuer_chain);
    pem_pck_certificate = qe_id_args.issuer_chain;
    pem_pck_certificate_size = qe_id_args.issuer_chain_size;

    // validate the cert chain.
    OE_CHECK(oe_cert_chain_read_pem(
        &pck_cert_chain, pem_pck_certificate, pem_pck_certificate_size));

    // parse identity info json blob
    OE_TRACE_INFO("*qe_identity.qe_id_info:[%s]\n", qe_id_args.qe_id_info);
    OE_CHECK(oe_parse_qe_identity_info_json(
        qe_id_args.qe_id_info, qe_id_args.qe_id_info_size, &parsed_info));

    // verify qe identity signature
    OE_TRACE_INFO("Calling oe_verify_ecdsa256_signature\n");
    OE_CHECK(oe_verify_ecdsa256_signature(
        parsed_info.info_start,
        parsed_info.info_size,
        (sgx_ecdsa256_signature_t*)parsed_info.signature,
        &pck_cert_chain));
    OE_TRACE_INFO("oe_verify_ecdsa256_signature succeeded\n");

    // Check that issue_date and next_update are after the earliest date that
    // the enclave accepts.
    if (oe_datetime_compare(
            &parsed_info.issue_date, &_sgx_minimim_crl_tcb_issue_date) != 1)
        OE_RAISE(OE_INVALID_QE_IDENTITY_INFO);

    if (oe_datetime_compare(
            &parsed_info.next_update, &_sgx_minimim_crl_tcb_issue_date) != 1)
        OE_RAISE(OE_INVALID_QE_IDENTITY_INFO);

    // Assert that the qe report's MRSIGNER matches Intel's quoting enclave's
    // mrsigner.
    if (!oe_constant_time_mem_equal(
            qe_report_body->mrsigner,
            parsed_info.mrsigner,
            sizeof(parsed_info.mrsigner)))
    {
        dump_info(
            "parsed_info.mrsigner:",
            parsed_info.mrsigner,
            sizeof(parsed_info.mrsigner));
        dump_info(
            "qe_report_body->mrsigner:",
            qe_report_body->mrsigner,
            sizeof(qe_report_body->mrsigner));
        OE_RAISE(OE_VERIFY_FAILED);
    }

    if (qe_report_body->isvprodid != parsed_info.isvprodid)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "qe_report_body->isvprodid = 0x%x isvprodid = 0x%x",
            qe_report_body->isvprodid,
            parsed_info.isvprodid);

    if (qe_report_body->isvsvn < parsed_info.isvsvn)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "qe_report_body->isvsvn = 0x%x isvsvn = 0x%x",
            qe_report_body->isvsvn,
            parsed_info.isvsvn);

    if ((qe_report_body->miscselect & parsed_info.miscselect_mask) !=
        parsed_info.miscselect)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "qe_report_body->miscselect = 0x%x miscselect_mask = 0x%x "
            "miscselect = 0x%x",
            qe_report_body->miscselect,
            parsed_info.miscselect_mask,
            parsed_info.miscselect);

    // validate attributes
    // validate attributes.flags
    if ((qe_report_body->attributes.flags &
         parsed_info.attributes_flags_mask) != parsed_info.attributes.flags)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "qe_report_body->attributes.flags = 0x%lx attributes_flags_mask = "
            "0x%lx attributes.flags = 0x%lx",
            qe_report_body->attributes.flags,
            parsed_info.attributes_flags_mask,
            parsed_info.attributes_flags_mask);

    // validate attributes.xfrm
    if ((qe_report_body->attributes.xfrm & parsed_info.attributes_xfrm_mask) !=
        parsed_info.attributes.xfrm)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "qe_report_body->attributes.xfrm = 0x%lx attributes_xfrm_mask = "
            "0x%lx attributes.xfrm = 0x%lx",
            qe_report_body->attributes.xfrm,
            parsed_info.attributes_xfrm_mask,
            parsed_info.attributes.xfrm);

    oe_cleanup_qe_identity_info_args(&qe_id_args);
    result = OE_OK;

done:
    oe_cert_chain_free(&pck_cert_chain);
    return result;
}
