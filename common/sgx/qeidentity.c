// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "qeidentity.h"
#include <openenclave/bits/attestation.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include "../common.h"
#include "tcbinfo.h"

extern oe_datetime_t _sgx_minimim_crl_tcb_issue_date;

static void dump_info(
    const char* title,
    const uint8_t* data,
    const uint8_t count)
{
    OE_TRACE_INFO("%s\n", title);
    for (uint8_t i = 0; i < count; i++)
    {
        OE_TRACE_INFO("[%d] = %x\n", i, data[i]);
    }
}

oe_result_t oe_validate_qe_identity(
    const sgx_report_body_t* qe_report_body,
    const oe_sgx_endorsements_t* sgx_endorsements,
    oe_datetime_t* validity_from,
    oe_datetime_t* validity_until)
{
    oe_result_t result = OE_FAILURE;
    const uint8_t* pem_pck_certificate = NULL;
    size_t pem_pck_certificate_size = 0;
    oe_cert_chain_t pck_cert_chain = {0};
    oe_cert_t leaf_cert = {0};
    oe_parsed_qe_identity_info_t parsed_info = {0};
    oe_qe_identity_info_tcb_level_t platform_tcb_level = {{0}};
    oe_datetime_t from = {0};
    oe_datetime_t until = {0};

    OE_TRACE_INFO("Calling %s\n", __FUNCTION__);

    if ((sgx_endorsements == NULL) || (validity_from == NULL) ||
        (validity_until == NULL))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Use QE Identity info to validate QE
    // Check against fetched qe identityinfo
    OE_TRACE_INFO(
        "qe_identity.issuer_chain:[%s]\n",
        (const char*)sgx_endorsements
            ->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN]
            .data);
    pem_pck_certificate =
        sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN]
            .data;
    pem_pck_certificate_size =
        sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN]
            .size;

    // validate the cert chain.
    OE_CHECK(oe_cert_chain_read_pem(
        &pck_cert_chain, pem_pck_certificate, pem_pck_certificate_size));

    // parse identity info json blob
    OE_TRACE_INFO(
        "*qe_identity.qe_id_info:[%s]\n",
        sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO].data);
    OE_CHECK(oe_parse_qe_identity_info_json(
        sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO].data,
        sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO].size,
        &platform_tcb_level,
        &parsed_info));

    // verify qe identity signature
    OE_TRACE_INFO("Calling oe_verify_ecdsa256_signature\n");
    OE_CHECK(oe_verify_ecdsa256_signature(
        parsed_info.info_start,
        parsed_info.info_size,
        (sgx_ecdsa256_signature_t*)parsed_info.signature,
        &pck_cert_chain));
    OE_TRACE_INFO("oe_verify_ecdsa256_signature succeeded\n");

    // Get leaf certificate
    OE_CHECK_MSG(
        oe_cert_chain_get_leaf_cert(&pck_cert_chain, &leaf_cert),
        "Failed to get leaf certificate. %s",
        oe_result_str(result));
    OE_CHECK_MSG(
        oe_cert_get_validity_dates(&leaf_cert, &from, &until),
        "Failed to get validity dates from cert. %s",
        oe_result_str(result));

    oe_datetime_log("QE identity cert issue date: ", &from);
    oe_datetime_log("QE identity cert next update: ", &until);

    // Check that issue_date and next_update are after the earliest date that
    // the enclave accepts.
    if (oe_datetime_compare(
            &parsed_info.issue_date, &_sgx_minimim_crl_tcb_issue_date) < 0)
        OE_RAISE_MSG(
            OE_INVALID_QE_IDENTITY_INFO,
            "QE identity info issue date does not meet CRL/TCB minimum issue "
            "date.");

    if (oe_datetime_compare(
            &parsed_info.next_update, &_sgx_minimim_crl_tcb_issue_date) < 0)
        OE_RAISE_MSG(
            OE_INVALID_QE_IDENTITY_INFO,
            "QE identity info next update does not meet CRL/TCB minimum issue "
            "date.");

    // Assert that the qe report's MRSIGNER matches Intel's quoting enclave's
    // mrsigner.
    if (!oe_constant_time_mem_equal(
            qe_report_body->mrsigner,
            parsed_info.mrsigner,
            sizeof(parsed_info.mrsigner)))
    {
        dump_info(
            "Expected mrsigner, parsed_info.mrsigner:",
            parsed_info.mrsigner,
            sizeof(parsed_info.mrsigner));
        dump_info(
            "Actual mrsigner, qe_report_body->mrsigner:",
            qe_report_body->mrsigner,
            sizeof(qe_report_body->mrsigner));
        OE_RAISE(OE_QUOTE_ENCLAVE_IDENTITY_UNIQUEID_MISMATCH);
    }

    if (qe_report_body->isvprodid != parsed_info.isvprodid)
        OE_RAISE_MSG(
            QE_QUOTE_ENCLAVE_IDENTITY_PRODUCTID_MISMATCH,
            "isvprodid mismatch. Expected 0x%04X, actual 0x%04X",
            parsed_info.isvprodid,
            qe_report_body->isvprodid);

    if (qe_report_body->isvsvn < parsed_info.isvsvn)
        OE_RAISE_MSG(
            OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED,
            "isvsvn is out-of-date. Required SVN 0x%08X, actual SVN 0x%08X",
            parsed_info.isvsvn,
            qe_report_body->isvsvn);

    if ((qe_report_body->miscselect & parsed_info.miscselect_mask) !=
        parsed_info.miscselect)
        OE_RAISE_MSG(
            OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED,
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
            OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED,
            "qe_report_body->attributes.flags = 0x%lx attributes_flags_mask = "
            "0x%lx attributes.flags = 0x%lx",
            qe_report_body->attributes.flags,
            parsed_info.attributes_flags_mask,
            parsed_info.attributes_flags_mask);

    // validate attributes.xfrm
    if ((qe_report_body->attributes.xfrm & parsed_info.attributes_xfrm_mask) !=
        parsed_info.attributes.xfrm)
        OE_RAISE_MSG(
            OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED,
            "qe_report_body->attributes.xfrm = 0x%lx attributes_xfrm_mask = "
            "0x%lx attributes.xfrm = 0x%lx",
            qe_report_body->attributes.xfrm,
            parsed_info.attributes_xfrm_mask,
            parsed_info.attributes.xfrm);

    if (qe_report_body->attributes.flags & SGX_FLAGS_DEBUG)
        OE_RAISE_MSG(
            OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED,
            "QE has SGX_FLAGS_DEBUG set!!");

    if (oe_datetime_compare(&parsed_info.issue_date, &from) > 0)
        from = parsed_info.issue_date;
    if (oe_datetime_compare(&parsed_info.next_update, &until) < 0)
        until = parsed_info.next_update;

    oe_datetime_log("QE identity issue date: ", &parsed_info.issue_date);
    oe_datetime_log("QE identity next update date: ", &parsed_info.next_update);
    oe_datetime_log("QE identity overall issue date: ", &from);
    oe_datetime_log("QE identity overall next update: ", &until);
    if (oe_datetime_compare(&from, &until) > 0)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD,
            "Failed to find an overall QE identity validity period.");

    *validity_from = from;
    *validity_until = until;

    result = OE_OK;

done:
    if (pck_cert_chain.impl[0] != 0)
        oe_cert_chain_free(&pck_cert_chain);
    oe_cert_free(&leaf_cert);

    return result;
}
