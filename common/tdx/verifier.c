// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "verifier.h"
#include <openenclave/attestation/tdx/evidence.h>
#include <openenclave/bits/evidence.h>
#include <openenclave/bits/tdx/tdxquote.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safemath.h>

#include "../common.h"
#include "../sgx/quote.h"
#include "collateral.h"
#include "quote.h"

// Copied from common/sgx/verifier.c:25
#ifdef OE_BUILD_ENCLAVE
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/thread.h>
#include "../../enclave/core/sgx/report.h"
#include "../enclave/sgx/report.h"
#else
#include "../../host/hostthread.h"
#include "../../host/sgx/quote.h"
typedef oe_mutex oe_mutex_t;
#define OE_MUTEX_INITIALIZER OE_H_MUTEX_INITIALIZER
#endif

static oe_mutex_t init_mutex = OE_MUTEX_INITIALIZER;
static const oe_uuid_t _uuid_tdx_quote_ecdsa = {OE_FORMAT_UUID_TDX_QUOTE_ECDSA};

/* Convert Intel-defined verification result to OE tcb status */
static oe_sgx_tcb_status_t _verification_result_to_tcb_status(
    sgx_ql_qv_result_t verification_result)
{
    switch (verification_result)
    {
        case SGX_QL_QV_RESULT_OK:
            return OE_SGX_TCB_STATUS_UP_TO_DATE;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
            return OE_SGX_TCB_STATUS_CONFIGURATION_NEEDED;
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
            return OE_SGX_TCB_STATUS_OUT_OF_DATE;
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
            return OE_SGX_TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED;
        case SGX_QL_QV_RESULT_REVOKED:
            return OE_SGX_TCB_STATUS_REVOKED;
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
            return OE_SGX_TCB_STATUS_SW_HARDENING_NEEDED;
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            return OE_SGX_TCB_STATUS_CONFIGURATION_AND_SW_HARDENING_NEEDED;
        case SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED:
            return OE_SGX_TCB_STATUS_TD_RELAUNCH_ADVISED;
        case SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
            return OE_SGX_TCB_STATUS_TD_RELAUNCH_ADVISED_CONFIG_NEEDED;
        default:
            return OE_SGX_TCB_STATUS_INVALID;
    }
}

static oe_result_t _on_register(
    oe_attestation_role_t* context,
    const void* configuration_data,
    size_t configuration_data_size)
{
    OE_UNUSED(context);
    OE_UNUSED(configuration_data);
    OE_UNUSED(configuration_data_size);

    return OE_OK;
}

static oe_result_t _on_unregister(oe_attestation_role_t* context)
{
    OE_UNUSED(context);
    return OE_OK;
}

static void _free_claim(oe_claim_t* claim)
{
    oe_free(claim->name);
    oe_free(claim->value);
}

static oe_result_t _free_claims_list(
    oe_verifier_t* context,
    oe_claim_t* claims,
    size_t claims_length)
{
    OE_UNUSED(context);

    if (!claims)
        return OE_OK;

    for (size_t i = 0; i < claims_length; i++)
        _free_claim(&claims[i]);
    oe_free(claims);

    return OE_OK;
}

static oe_result_t _add_claim(
    oe_claim_t* claim,
    const void* name,
    size_t name_size, // Must cover the '\0' at end of string
    const void* value,
    size_t value_size)
{
    if (*((uint8_t*)name + name_size - 1) != '\0')
        return OE_CONSTRAINT_FAILED;

    claim->name = (char*)oe_malloc(name_size);
    if (claim->name == NULL)
        return OE_OUT_OF_MEMORY;
    memcpy(claim->name, name, name_size);

    claim->value = (uint8_t*)oe_malloc(value_size);
    if (claim->value == NULL)
    {
        oe_free(claim->name);
        claim->name = NULL;
        return OE_OUT_OF_MEMORY;
    }
    memcpy(claim->value, value, value_size);
    claim->value_size = value_size;

    return OE_OK;
}

static oe_result_t _fill_with_known_tdx_claims(
    const oe_uuid_t* format_id,
    const uint8_t* quote,
    uint32_t verification_result,
    const uint8_t* supplemental_data,
    size_t supplemental_data_size,
    oe_claim_t* claims,
    size_t claims_length,
    size_t* claims_added)
{
    oe_sgx_tcb_status_t tcb_status = OE_SGX_TCB_STATUS_INVALID;
    const tdx_report_body_t* tdx_report = NULL;
    const tdx_report_body_v5_t* tdx_report_v5 = NULL;
    const tdx_attributes_t* attributes = NULL;
    oe_result_t result = OE_UNEXPECTED;
    tdx_quote_t* tdx_quote = NULL;
    tdx_quote_v5_t* tdx_quote_v5 = NULL;
    size_t claims_index = 0;
    oe_identity_t id = {0};
    size_t sa_list_size = 0;
    char* sa_list = NULL;
    bool flag;

    if (claims_length < OE_REQUIRED_CLAIMS_COUNT +
                            OE_TDX_REQUIRED_CLAIMS_COUNT +
                            OE_TDX_ADDITIONAL_CLAIMS_COUNT)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* TDX quote versions 4 and 5 have the same header, which contains version
     * number */
    tdx_quote = (tdx_quote_t*)quote;
    if (tdx_quote->version == 4)
    {
        tdx_report = &tdx_quote->report_body;
    }
    else if (tdx_quote->version == 5)
    {
        /* If quote version is 5, then recast to TDX quote v5 struct */
        tdx_quote_v5 = (tdx_quote_v5_t*)quote;
        /* Type 1 is SGX, which is not handled here */
        if (tdx_quote_v5->type == 1)
            OE_RAISE(OE_UNEXPECTED);
        /* Type 2 is TDX V4 report body */
        tdx_report = (tdx_report_body_t*)tdx_quote_v5->body;
        /* Type 3 is TDX V5 report body */
        if (tdx_quote_v5->type == 3)
            tdx_report_v5 = (tdx_report_body_v5_t*)tdx_quote_v5->body;
    }

    /* OE-specific claims. Not applicable to TDX so just fill with zeros */

    // ID version.
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_ID_VERSION,
        sizeof(OE_CLAIM_ID_VERSION),
        &id.id_version,
        sizeof(id.id_version)));

    // Security version.
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_SECURITY_VERSION,
        sizeof(OE_CLAIM_SECURITY_VERSION),
        &id.security_version,
        sizeof(id.security_version)));

    // Attributes.
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_ATTRIBUTES,
        sizeof(OE_CLAIM_ATTRIBUTES),
        &id.attributes,
        sizeof(id.attributes)));

    // Unique ID
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_UNIQUE_ID,
        sizeof(OE_CLAIM_UNIQUE_ID),
        &id.unique_id,
        sizeof(id.unique_id)));

    // Signer ID
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_SIGNER_ID,
        sizeof(OE_CLAIM_SIGNER_ID),
        &id.signer_id,
        sizeof(id.signer_id)));

    // Product ID
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_PRODUCT_ID,
        sizeof(OE_CLAIM_PRODUCT_ID),
        &id.product_id,
        sizeof(id.product_id)));

    // Plugin UUID
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_FORMAT_UUID,
        sizeof(OE_CLAIM_FORMAT_UUID),
        format_id,
        sizeof(*format_id)));

    /* TDX claims. Values extracted from the TDX report inside the quote */

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TEE_TCB_SVN,
        sizeof(OE_CLAIM_TDX_TEE_TCB_SVN),
        (uint8_t*)&tdx_report->tee_tcb_svn,
        sizeof(tdx_report->tee_tcb_svn)));
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_MRSEAM,
        sizeof(OE_CLAIM_TDX_MRSEAM),
        tdx_report->mrseam,
        sizeof(tdx_report->mrseam)));
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_MRSEAMSIGNER,
        sizeof(OE_CLAIM_TDX_MRSEAMSIGNER),
        tdx_report->mrseamsigner,
        sizeof(tdx_report->mrseamsigner)));
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_SEAM_ATTRIBUTES,
        sizeof(OE_CLAIM_TDX_SEAM_ATTRIBUTES),
        tdx_report->seam_attributes,
        sizeof(tdx_report->seam_attributes)));

    attributes = &tdx_report->td_attributes;

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TD_ATTRIBUTES,
        sizeof(OE_CLAIM_TDX_TD_ATTRIBUTES),
        attributes,
        sizeof(tdx_attributes_t)));

    flag = !!attributes->tud_tup.d.debug;
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TD_ATTRIBUTES_DEBUG,
        sizeof(OE_CLAIM_TDX_TD_ATTRIBUTES_DEBUG),
        &flag,
        sizeof(flag)));

    flag = !!attributes->tud_tup.d.hgs_plus_prof;
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TD_ATTRIBUTES_HGS_PLUS_PROF,
        sizeof(OE_CLAIM_TDX_TD_ATTRIBUTES_HGS_PLUS_PROF),
        &flag,
        sizeof(flag)));

    flag = !!attributes->tud_tup.d.perf_prof;
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TD_ATTRIBUTES_PERF_PROF,
        sizeof(OE_CLAIM_TDX_TD_ATTRIBUTES_PERF_PROF),
        &flag,
        sizeof(flag)));

    flag = !!attributes->tud_tup.d.pmt_prof;
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TD_ATTRIBUTES_PMT_PROF,
        sizeof(OE_CLAIM_TDX_TD_ATTRIBUTES_PMT_PROF),
        &flag,
        sizeof(flag)));

    flag = !!attributes->sec.d.icssd;
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TD_ATTRIBUTES_ICSSD,
        sizeof(OE_CLAIM_TDX_TD_ATTRIBUTES_ICSSD),
        &flag,
        sizeof(flag)));

    flag = !!attributes->sec.d.servtd_ext;
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TD_ATTRIBUTES_SERVTD_EXT,
        sizeof(OE_CLAIM_TDX_TD_ATTRIBUTES_SERVTD_EXT),
        &flag,
        sizeof(flag)));

    flag = !!attributes->sec.d.lass;
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TD_ATTRIBUTES_LASS,
        sizeof(OE_CLAIM_TDX_TD_ATTRIBUTES_LASS),
        &flag,
        sizeof(flag)));

    flag = !!attributes->sec.d.sept_ve_disable;
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE,
        sizeof(OE_CLAIM_TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE),
        &flag,
        sizeof(flag)));

    flag = !!attributes->sec.d.migratable;
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TD_ATTRIBUTES_MIGRATABLE,
        sizeof(OE_CLAIM_TDX_TD_ATTRIBUTES_MIGRATABLE),
        &flag,
        sizeof(flag)));

    flag = !!attributes->sec.d.pks;
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TD_ATTRIBUTES_PROTECTION_KEYS,
        sizeof(OE_CLAIM_TDX_TD_ATTRIBUTES_PROTECTION_KEYS),
        &flag,
        sizeof(flag)));

    flag = !!attributes->sec.d.kl;
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TD_ATTRIBUTES_KEY_LOCKER,
        sizeof(OE_CLAIM_TDX_TD_ATTRIBUTES_KEY_LOCKER),
        &flag,
        sizeof(flag)));

    flag = !!attributes->other.d.perfmon;
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_TD_ATTRIBUTES_PERFMON,
        sizeof(OE_CLAIM_TDX_TD_ATTRIBUTES_PERFMON),
        &flag,
        sizeof(flag)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_XFAM,
        sizeof(OE_CLAIM_TDX_XFAM),
        tdx_report->xfam,
        sizeof(tdx_report->xfam)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_MRTD,
        sizeof(OE_CLAIM_TDX_MRTD),
        tdx_report->mrtd,
        sizeof(tdx_report->mrtd)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_MRCONFIGID,
        sizeof(OE_CLAIM_TDX_MRCONFIGID),
        tdx_report->mrconfigid,
        sizeof(tdx_report->mrconfigid)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_MROWNER,
        sizeof(OE_CLAIM_TDX_MROWNER),
        tdx_report->mrowner,
        sizeof(tdx_report->mrowner)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_MROWNERCONFIG,
        sizeof(OE_CLAIM_TDX_MROWNERCONFIG),
        tdx_report->mrownerconfig,
        sizeof(tdx_report->mrownerconfig)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_RTMR0,
        sizeof(OE_CLAIM_TDX_RTMR0),
        tdx_report->rtmr0,
        sizeof(tdx_report->rtmr0)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_RTMR1,
        sizeof(OE_CLAIM_TDX_RTMR1),
        tdx_report->rtmr1,
        sizeof(tdx_report->rtmr1)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_RTMR2,
        sizeof(OE_CLAIM_TDX_RTMR2),
        tdx_report->rtmr2,
        sizeof(tdx_report->rtmr2)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_RTMR3,
        sizeof(OE_CLAIM_TDX_RTMR3),
        tdx_report->rtmr3,
        sizeof(tdx_report->rtmr3)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_REPORT_DATA,
        sizeof(OE_CLAIM_TDX_REPORT_DATA),
        tdx_report->report_data,
        sizeof(tdx_report->report_data)));

    /* Two additional attributes introduced in TDX V5 report body. Above is the
     * same for both versions. */
    if (tdx_report_v5 != NULL)
    {
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TDX_TEE_TCB_SVN_2,
            sizeof(OE_CLAIM_TDX_TEE_TCB_SVN_2),
            (uint8_t*)&tdx_report_v5->tee_tcb_svn2,
            sizeof(tdx_report_v5->tee_tcb_svn2)));

        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TDX_MRSERVICETD,
            sizeof(OE_CLAIM_TDX_MRSERVICETD),
            tdx_report_v5->mrservicetd,
            sizeof(tdx_report_v5->mrservicetd)));
    }

    /* Additional claims */

    tcb_status = _verification_result_to_tcb_status(
        (sgx_ql_qv_result_t)verification_result);

    // TCB status.
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TCB_STATUS,
        sizeof(OE_CLAIM_TCB_STATUS),
        &tcb_status,
        sizeof(tcb_status)));

    if (supplemental_data && supplemental_data_size)
    {
        sa_list = ((sgx_ql_qv_supplemental_t*)supplemental_data)->sa_list;
        sa_list_size = oe_strlen(sa_list);

        /* Include the null terminator when the list is not empty */
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TDX_SA_LIST,
            sizeof(OE_CLAIM_TDX_SA_LIST),
            sa_list,
            sa_list_size == 0 ? 0 : sa_list_size + 1));
    }

    // TDX quote PCESVN
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TDX_PCE_SVN,
        sizeof(OE_CLAIM_TDX_PCE_SVN),
        &tdx_quote->pce_svn,
        sizeof(tdx_quote->pce_svn)));

    *claims_added = claims_index;
    result = OE_OK;

done:
    if (result != OE_OK)
    {
        for (size_t i = 0; i < claims_index; i++)
            _free_claim(&claims[i]);
    }

    return result;
}

static oe_result_t _extract_claims(
    const oe_uuid_t* format_id,
    const uint8_t* report_body,
    size_t report_body_size,
    uint32_t verification_result,
    const uint8_t* supplemental_data,
    size_t supplemental_data_size,
    oe_claim_t** claims_out,
    size_t* claims_length_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_claim_t* claims = NULL;
    uint64_t claims_length = 0;
    uint64_t claims_size = 0;
    size_t claims_added = 0;

    // Note: some callers can have custom_claims_buffer pointing to a non-NULL
    // buffer containing a zero-sized array.
    if (!format_id || !report_body || !report_body_size || !claims_out ||
        !claims_length_out)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Get the number of claims we need and allocate the claims.
    // Include OE_REQUIRED_CLAIM_COUNT for compability with SGX plugins
    claims_length = OE_REQUIRED_CLAIMS_COUNT + OE_TDX_REQUIRED_CLAIMS_COUNT +
                    OE_TDX_ADDITIONAL_CLAIMS_COUNT;

    OE_CHECK(oe_safe_mul_u64(claims_length, sizeof(oe_claim_t), &claims_size));

    claims = (oe_claim_t*)oe_malloc(claims_size);
    if (claims == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Fill the list with the known claims.
    OE_CHECK(_fill_with_known_tdx_claims(
        format_id,
        report_body,
        verification_result,
        supplemental_data,
        supplemental_data_size,
        claims,
        claims_length,
        &claims_added));

    /* To accommodate the new claims introduced by the newer quote
       versions, we allow the number of added claims to be less than or
       equal to the number of allocated claim slots (the upper bound). */
    if (claims_added > claims_length)
        OE_RAISE(OE_UNEXPECTED);

    *claims_out = claims;
    *claims_length_out = claims_added;
    claims = NULL;
    result = OE_OK;

done:
    _free_claims_list(NULL, claims, claims_length);

    return result;
}

static oe_result_t _get_format_settings(
    oe_verifier_t* context,
    uint8_t** settings,
    size_t* settings_size)
{
    OE_UNUSED(context);
    OE_UNUSED(settings);
    OE_UNUSED(settings_size);
    return OE_UNSUPPORTED;
}

static oe_result_t _verify_report(
    oe_verifier_t* context,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    OE_UNUSED(context);
    OE_UNUSED(report);
    OE_UNUSED(report_size);
    OE_UNUSED(parsed_report);
    return OE_UNSUPPORTED;
}

static oe_result_t _get_input_time(
    const oe_policy_t* policies,
    size_t policies_size,
    oe_datetime_t** time)
{
    if (!policies)
    {
        *time = NULL;
        return OE_OK;
    }

    for (size_t i = 0; i < policies_size; i++)
    {
        if (policies[i].type == OE_POLICY_ENDORSEMENTS_TIME)
        {
            if (policies[i].policy_size != sizeof(**time))
                return OE_INVALID_PARAMETER;

            *time = (oe_datetime_t*)policies[i].policy;
            return OE_OK;
        }
    }

    // Time not found, which is fine since it's an optional parameter.
    *time = NULL;
    return OE_OK;
}

static oe_result_t _verify_evidence(
    oe_verifier_t* context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* supplemental_data = NULL;
    size_t supplemental_data_size = 0;
    uint32_t verification_result = 0;
    oe_uuid_t* format_id = NULL;
    oe_datetime_t* time = NULL;

    if (!context || !evidence_buffer || !evidence_buffer_size ||
        (!endorsements_buffer != !endorsements_buffer_size) ||
        (!policies != !policies_size) || (!claims != !claims_length))
        OE_RAISE(OE_INVALID_PARAMETER);

    format_id = &context->base.format_id;

    OE_CHECK(_get_input_time(policies, policies_size, &time));

    if (!memcmp(format_id, &_uuid_tdx_quote_ecdsa, sizeof(oe_uuid_t)))
    {
        size_t total_size = 0;
        tdx_quote_t* quote = (tdx_quote_t*)evidence_buffer;
        if (quote->version == 4)
        {
            total_size = sizeof(*quote) + quote->signature_len;
        }
        else if (quote->version == 5)
        {
            tdx_quote_v5_t* quote_v5 = (tdx_quote_v5_t*)evidence_buffer;
            total_size = sizeof(*quote_v5) + quote_v5->size;
        }
        // TDX quote should have either version 4 or 5
        if (evidence_buffer_size < total_size ||
            (quote->version != SGX_QE4_QUOTE_VERSION &&
             quote->version != SGX_QE5_QUOTE_VERSION) ||
            quote->sign_type != SGX_QL_ALG_ECDSA_P256 ||
            quote->tee_type != TDX_QUOTE_TYPE)
            OE_RAISE(OE_INVALID_PARAMETER);
    }
    else
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_verify_quote_with_tdx_endorsements(
        evidence_buffer,
        evidence_buffer_size,
        endorsements_buffer,
        endorsements_buffer_size,
        time,
        &verification_result,
        &supplemental_data,
        &supplemental_data_size));

    // Last step is to return claims.
    if (claims)
    {
        OE_CHECK(_extract_claims(
            format_id,
            evidence_buffer,
            evidence_buffer_size,
            verification_result,
            supplemental_data,
            supplemental_data_size,
            claims,
            claims_length));
    }

    result = OE_OK;

done:
    oe_free(supplemental_data);

    return result;
}

static oe_verifier_t _verifier = {
    .base =
        {
            .format_id = {OE_FORMAT_UUID_TDX_QUOTE_ECDSA},
            .on_register = &_on_register,
            .on_unregister = &_on_unregister,
        },
    .get_format_settings = &_get_format_settings,
    .verify_evidence = &_verify_evidence,
    .verify_report = &_verify_report,
    .free_claims = &_free_claims_list};

oe_result_t oe_tdx_verifier_initialize(void)
{
    oe_result_t result = OE_UNEXPECTED;

    if (oe_mutex_lock(&init_mutex))
        OE_RAISE(OE_UNEXPECTED);

    result = oe_register_verifier_plugin(&_verifier, NULL, 0);
    OE_CHECK(result);

done:
    oe_mutex_unlock(&init_mutex);
    return result;
}

// Registration of plugins does not allocate any resources to them.
oe_result_t oe_tdx_verifier_shutdown(void)
{
    oe_result_t result = OE_UNEXPECTED;

    if (oe_mutex_lock(&init_mutex))
        OE_RAISE(OE_UNEXPECTED);

    result = oe_unregister_verifier_plugin(&_verifier);
    OE_CHECK(result);

done:
    oe_mutex_unlock(&init_mutex);
    return result;
}

oe_result_t oe_get_tdx_endorsements(
    const uint8_t* evidence_buffer,
    uint32_t evidence_buffer_size,
    uint8_t** endorsements_buffer,
    uint32_t* endorsements_buffer_size)
{
    return oe_get_tdx_quote_verification_collateral(
        evidence_buffer,
        evidence_buffer_size,
        endorsements_buffer,
        endorsements_buffer_size);
}

void oe_free_tdx_endorsements(uint8_t* endorsements_buffer)
{
    oe_free_tdx_quote_verification_collateral(endorsements_buffer);
}
