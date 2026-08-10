// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "verifier.h"
#include <openenclave/attestation/tdx/evidence.h>
#include <openenclave/bits/evidence.h>
#include <openenclave/bits/tdx/tdxquote.h>
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safemath.h>

#include "../common.h"
#include "../sgx/quote.h"
#include "../sgx/tcbinfo.h"
#include "collateral.h"
#include "quote.h"

#include <openenclave/internal/datetime.h>

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

static bool _is_terminal_tcb_status(oe_sgx_tcb_status_t status)
{
    return status == OE_SGX_TCB_STATUS_OUT_OF_DATE ||
           status == OE_SGX_TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED ||
           status == OE_SGX_TCB_STATUS_REVOKED ||
           status == OE_SGX_TCB_STATUS_INVALID;
}

oe_sgx_tcb_status_t oe_tdx_get_effective_tcb_status(
    oe_sgx_tcb_status_t current_status,
    oe_sgx_tcb_status_t init_status,
    bool* uses_init_status)
{
    if (uses_init_status)
        *uses_init_status = false;

    if (_is_terminal_tcb_status(current_status))
        return current_status;

    if (_is_terminal_tcb_status(init_status) ||
        (current_status == OE_SGX_TCB_STATUS_UP_TO_DATE &&
         init_status != OE_SGX_TCB_STATUS_UP_TO_DATE))
    {
        if (uses_init_status)
            *uses_init_status = true;
        return init_status;
    }

    return current_status;
}

/* Enable OE's own evaluation of the Service-TD's initial platform TCB.
 *
 * This is a temporary capability. Once Intel's verification library evaluates
 * the Service-TD initial TCB natively, this OE-side evaluation can be disabled
 * (or removed) by building with -DOE_TDX_ENABLE_SERVTD_INIT_TCB_EVAL=0. When
 * disabled, the Service-TD extension report fields are still emitted as claims,
 * but the tdx_curr_platform_tcb_status/date and tdx_init_platform_tcb_status/
 * date claims are omitted, the init-TCB baseline-date gating is not applied,
 * and the aggregate tcb_status reflects only the current platform TCB. Enabled
 * by default. */
#ifndef OE_TDX_ENABLE_SERVTD_INIT_TCB_EVAL
#define OE_TDX_ENABLE_SERVTD_INIT_TCB_EVAL 1
#endif

/* Result of evaluating the Service-TD's initial platform TCB (from the type-4
 * report body's init_cpu_svn/init_tee_tcb_svn against the platform TCB info).
 * Only meaningful when 'valid' is true. */
typedef struct _tdx_servtd_init_tcb
{
    bool required;
    bool valid;
    oe_sgx_tcb_status_t tcb_status;
    oe_datetime_t tcb_date;
    time_t tcb_date_time;
} tdx_servtd_init_tcb_t;

#if OE_TDX_ENABLE_SERVTD_INIT_TCB_EVAL
typedef struct _tdx_collateral_header
{
    uint32_t version;
    uint32_t tee_type;
    char* pck_crl_issuer_chain;
    uint32_t pck_crl_issuer_chain_size;
    char* root_ca_crl;
    uint32_t root_ca_crl_size;
    char* pck_crl;
    uint32_t pck_crl_size;
    char* tcb_info_issuer_chain;
    uint32_t tcb_info_issuer_chain_size;
    char* tcb_info;
    uint32_t tcb_info_size;
    char* qe_identity_issuer_chain;
    uint32_t qe_identity_issuer_chain_size;
    char* qe_identity;
    uint32_t qe_identity_size;
} tdx_collateral_header_t;

static oe_result_t _advance_collateral_cursor(
    const uint8_t** cursor,
    const uint8_t* end,
    uint32_t size)
{
    if ((size_t)(end - *cursor) < size)
        return OE_OUT_OF_BOUNDS;

    *cursor += size;
    return OE_OK;
}

/* Extract TCB info from the flattened tdx_ql_qve_collateral_t representation
 * produced by host/sgx/sgxquote.c. */
static oe_result_t _get_tdx_tcb_info(
    const uint8_t* endorsements,
    size_t endorsements_size,
    const uint8_t** tcb_info,
    size_t* tcb_info_size,
    const uint8_t** tcb_issuer_chain,
    size_t* tcb_issuer_chain_size)
{
    oe_result_t result = OE_UNEXPECTED;
    tdx_collateral_header_t header = {0};
    const uint8_t* cursor = NULL;
    const uint8_t* end = NULL;

    if (!endorsements || !tcb_info || !tcb_info_size || !tcb_issuer_chain ||
        !tcb_issuer_chain_size || endorsements_size < sizeof(header))
        OE_RAISE(OE_INVALID_PARAMETER);

    memcpy(&header, endorsements, sizeof(header));
    if ((header.version != 0x00000003 && header.version != 0x00010003 &&
         header.version != 0x00000004) ||
        header.tee_type != TDX_QUOTE_TYPE)
        OE_RAISE(OE_INVALID_ENDORSEMENT);

    cursor = endorsements + sizeof(header);
    end = endorsements + endorsements_size;

    OE_CHECK(_advance_collateral_cursor(
        &cursor, end, header.pck_crl_issuer_chain_size));
    OE_CHECK(_advance_collateral_cursor(&cursor, end, header.root_ca_crl_size));
    OE_CHECK(_advance_collateral_cursor(&cursor, end, header.pck_crl_size));
    if ((size_t)(end - cursor) < header.tcb_info_issuer_chain_size)
        OE_RAISE(OE_OUT_OF_BOUNDS);
    *tcb_issuer_chain = cursor;
    *tcb_issuer_chain_size = header.tcb_info_issuer_chain_size;
    OE_CHECK(_advance_collateral_cursor(
        &cursor, end, header.tcb_info_issuer_chain_size));

    if ((size_t)(end - cursor) < header.tcb_info_size)
        OE_RAISE(OE_OUT_OF_BOUNDS);
    *tcb_info = cursor;
    *tcb_info_size = header.tcb_info_size;

    OE_CHECK(_advance_collateral_cursor(&cursor, end, header.tcb_info_size));
    OE_CHECK(_advance_collateral_cursor(
        &cursor, end, header.qe_identity_issuer_chain_size));
    OE_CHECK(_advance_collateral_cursor(&cursor, end, header.qe_identity_size));
    if (cursor != end)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    result = OE_OK;

done:
    return result;
}

/* Evaluate the Service-TD's initial platform TCB.
 *
 * When the evidence is a TDX v5 type-4 (v1.5_ex) quote whose SERVTD_EXT bit is
 * set, the report body records the platform TCB (init_cpu_svn,
 * init_tee_tcb_svn, init_tee_fmspc) captured when the Service-TD was first
 * bound. Intel QVL only evaluates the current platform TCB, so this routine
 * performs an additional, OE-side TCB-info evaluation of that initial TCB and
 * reports its status and date. The evaluation is gated on the
 * ATTRIBUTES.SERVTD_EXT bit (not the body type alone); when the bit is not set
 * the routine skips (out->valid = false).
 *
 * The TCB info is taken from the already-fetched endorsements, authenticated
 * by the successful QVL verification of those exact endorsements, and required
 * to match the platform FMSPC. Cross-platform initial TCB evaluation is not
 * supported by this stopgap.
 * PCESVN is not carried by the Service-TD extension, so the evaluation matches
 * only the recorded SGX and TDX component SVNs. The caller treats a required
 * but indeterminate evaluation as an invalid aggregate TCB status. */
static oe_result_t _evaluate_servtd_init_tcb(
    const uint8_t* quote,
    size_t quote_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    tdx_servtd_init_tcb_t* out)
{
    oe_result_t result = OE_UNEXPECTED;
    const tdx_quote_t* tdx_quote = (const tdx_quote_t*)quote;
    const tdx_quote_v5_t* tdx_quote_v5 = NULL;
    const tdx_report_body_v1_5_ex_t* body = NULL;
    oe_tcb_info_tcb_level_t platform_tcb_level = {0};
    oe_parsed_tcb_info_t parsed_info = {0};
    oe_cert_chain_t tcb_issuer_chain = {0};
    const uint8_t* tcb_info = NULL;
    size_t tcb_info_size = 0;
    const uint8_t* tcb_issuer_chain_data = NULL;
    size_t tcb_issuer_chain_size = 0;
    uint8_t platform_fmspc[OE_TDX_FMSPC_SIZE] = {0};

    if (!out)
        OE_RAISE(OE_INVALID_PARAMETER);

    out->required = false;
    out->valid = false;

    /* Only TDX v5 type-4 (v1.5_ex) bodies carry the Service-TD init TCB. */
    if (tdx_quote->version != 5)
    {
        result = OE_OK;
        goto done;
    }
    tdx_quote_v5 = (const tdx_quote_v5_t*)quote;
    if (tdx_quote_v5->type != 4)
    {
        result = OE_OK;
        goto done;
    }
    body = (const tdx_report_body_v1_5_ex_t*)tdx_quote_v5->body;

    /* The Service-TD extension fields are only meaningful when the TD
     * ATTRIBUTES.SERVTD_EXT bit is set. The report body type alone is not
     * treated as sufficient (a type-4 body carries other fields too), so the
     * init TCB is evaluated only when the bit confirms the extension is active.
     * When it is not set, the evaluation is skipped (out->valid = false): the
     * raw type-4 field claims are still emitted, but the current/initial
     * platform TCB status/date pair (the evaluation results) is not. */
    if (!body->td_attributes.sec.d.servtd_ext)
    {
        OE_TRACE_WARNING(
            "Service-TD init TCB not evaluated: ATTRIBUTES.SERVTD_EXT not set");
        result = OE_OK;
        goto done;
    }
    out->required = true;

    /* The init TCB can only be evaluated when endorsements (which carry the TCB
     * info JSON) are available. If not, skip without failing verification. */
    if (!endorsements || !endorsements_size)
    {
        OE_TRACE_WARNING(
            "Service-TD init TCB not evaluated: endorsements unavailable");
        result = OE_OK;
        goto done;
    }

    result = _get_tdx_tcb_info(
        endorsements,
        endorsements_size,
        &tcb_info,
        &tcb_info_size,
        &tcb_issuer_chain_data,
        &tcb_issuer_chain_size);
    if (result != OE_OK)
    {
        OE_TRACE_WARNING(
            "Service-TD init TCB not evaluated: invalid TDX collateral (%s)",
            oe_result_str(result));
        result = OE_OK;
        goto done;
    }

    result = oe_cert_chain_read_pem(
        &tcb_issuer_chain, tcb_issuer_chain_data, tcb_issuer_chain_size);
    if (result != OE_OK)
    {
        OE_TRACE_WARNING(
            "Service-TD init TCB not evaluated: invalid TCB issuer chain (%s)",
            oe_result_str(result));
        result = OE_OK;
        goto done;
    }
    /* QVL has already authenticated this exact collateral, including its TCB
     * signing chain, using OE_POLICY_ENDORSEMENTS_TIME when supplied. Do not
     * revalidate the certificate against the current wall clock here. The
     * signature check below still binds the parsed TCB info to that chain. */

    /* Reuse the already-fetched (platform) TCB info only when the Service-TD's
     * recorded FMSPC matches the platform FMSPC. Production targets a single
     * platform, so this always holds; a mismatch (e.g. a cross-platform
     * migration this stopgap does not support) skips the init-TCB evaluation
     * rather than reporting a status/date matched against the wrong platform's
     * TCB-level table. */
    OE_CHECK(oe_get_tdx_fmspc_from_quote(
        quote, (uint32_t)quote_size, platform_fmspc, sizeof(platform_fmspc)));
    if (memcmp(body->init_tee_fmspc, platform_fmspc, OE_TDX_FMSPC_SIZE) != 0)
    {
        OE_TRACE_WARNING(
            "Service-TD init TCB not evaluated: init_tee_fmspc differs from "
            "platform FMSPC");
        result = OE_OK;
        goto done;
    }

    /* Build the platform TCB level from the Service-TD's initial TCB. The 16
     * init_cpu_svn bytes map to the SGX TCB components and the TEE TCB SVN
     * bytes map to the TDX TCB components. PCESVN is unavailable for the
     * initial TCB, so it is excluded from this component-level match. */
    OE_STATIC_ASSERT(
        sizeof(platform_tcb_level.sgx_tcb_comp_svn) ==
        sizeof(body->init_cpu_svn));
    OE_STATIC_ASSERT(
        sizeof(platform_tcb_level.tdx_tcb_comp_svn) ==
        sizeof(body->init_tee_tcb_svn));
    memcpy(
        platform_tcb_level.sgx_tcb_comp_svn,
        body->init_cpu_svn,
        sizeof(platform_tcb_level.sgx_tcb_comp_svn));
    memcpy(
        platform_tcb_level.tdx_tcb_comp_svn,
        &body->init_tee_tcb_svn,
        sizeof(platform_tcb_level.tdx_tcb_comp_svn));
    /* oe_parse_tcb_info_json returns OE_TCB_LEVEL_INVALID (with status and
     * tcb_date still populated) when the matched TCB level is not up-to-date.
     * That is a valid evaluation outcome for the Service-TD init TCB, not a
     * verification failure, so it is accepted here. Any other error means the
     * init TCB could not be evaluated and is treated as skipped (best-effort)
     * without affecting the primary verification result. */
    result = oe_parse_tcb_info_json_without_pce_svn(
        tcb_info, tcb_info_size, &platform_tcb_level, &parsed_info);
    if (result != OE_OK && result != OE_TCB_LEVEL_INVALID)
    {
        OE_TRACE_WARNING(
            "Service-TD init TCB not evaluated: failed to parse TCB info (%s)",
            oe_result_str(result));
        result = OE_OK;
        goto done;
    }

    if (memcmp(
            OE_TCB_INFO_GET(&parsed_info, fmspc),
            platform_fmspc,
            sizeof(platform_fmspc)) != 0)
    {
        OE_TRACE_WARNING(
            "Service-TD init TCB not evaluated: TCB info FMSPC mismatch");
        result = OE_OK;
        goto done;
    }

    if (platform_tcb_level.status.AsUINT32 == OE_TCB_LEVEL_STATUS_UNKNOWN)
    {
        OE_TRACE_WARNING(
            "Service-TD init TCB not evaluated: no component TCB level "
            "matched");
        result = OE_OK;
        goto done;
    }

    result = oe_verify_ecdsa256_signature(
        parsed_info.tcb_info_start,
        parsed_info.tcb_info_size,
        (sgx_ecdsa256_signature_t*)parsed_info.signature,
        &tcb_issuer_chain);
    if (result != OE_OK)
    {
        OE_TRACE_WARNING(
            "Service-TD init TCB not evaluated: TCB info signature invalid "
            "(%s)",
            oe_result_str(result));
        result = OE_OK;
        goto done;
    }

    out->tcb_status =
        oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status);
    out->tcb_date = platform_tcb_level.tcb_date;
    OE_CHECK(oe_datetime_to_time_t(
        &platform_tcb_level.tcb_date, &out->tcb_date_time));
    out->valid = true;

    result = OE_OK;

done:
    oe_cert_chain_free(&tcb_issuer_chain);
    return result;
}
#endif /* OE_TDX_ENABLE_SERVTD_INIT_TCB_EVAL */

/* Apply an optional TCB-date baseline policy to a single TCB status.
 *
 * When the status is out-of-date but the corresponding TCB level date is at or
 * after the caller-supplied baseline date, the status is upgraded:
 *   - OUT_OF_DATE                       -> UP_TO_DATE
 *   - OUT_OF_DATE_CONFIGURATION_NEEDED  -> CONFIGURATION_NEEDED
 * All other statuses, or cases where no baseline date is supplied or the TCB
 * date is unavailable (0) or older than the baseline, are returned unchanged.
 *
 * The policy is applied independently to the QVL aggregate, current platform
 * TCB, and (for a Service-TD extension quote) Service-TD initial platform TCB,
 * using each one's own TCB date.
 *
 * Note: this runs in the trusted component (inside the enclave for enclave
 * attestation) after the QvE report and result have already been validated, so
 * adjusting the status here does not weaken the QvE attestation guarantee. */
static oe_sgx_tcb_status_t _apply_tcb_baseline_date_policy(
    oe_sgx_tcb_status_t tcb_status,
    time_t tcb_date,
    const time_t* tcb_baseline_date)
{
    if (tcb_status != OE_SGX_TCB_STATUS_OUT_OF_DATE &&
        tcb_status != OE_SGX_TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED)
        return tcb_status;

    if (!tcb_baseline_date || tcb_date == 0 || tcb_date < *tcb_baseline_date)
        return tcb_status;

    return (tcb_status == OE_SGX_TCB_STATUS_OUT_OF_DATE)
               ? OE_SGX_TCB_STATUS_UP_TO_DATE
               : OE_SGX_TCB_STATUS_CONFIGURATION_NEEDED;
}

static bool _supplemental_field_available(
    size_t supplemental_data_size,
    size_t field_offset,
    size_t field_size)
{
    return field_offset <= supplemental_data_size &&
           field_size <= supplemental_data_size - field_offset;
}

static void _get_platform_tcb_data(
    uint32_t verification_result,
    const uint8_t* supplemental_data,
    size_t supplemental_data_size,
    oe_sgx_tcb_status_t* qvl_tcb_status,
    time_t* qvl_tcb_date,
    oe_sgx_tcb_status_t* current_tcb_status,
    time_t* current_tcb_date)
{
    const sgx_ql_qv_supplemental_t* supplemental =
        (const sgx_ql_qv_supplemental_t*)supplemental_data;

    *qvl_tcb_status = _verification_result_to_tcb_status(
        (sgx_ql_qv_result_t)verification_result);
    *qvl_tcb_date = 0;
    *current_tcb_status = *qvl_tcb_status;
    *current_tcb_date = 0;

    if (!supplemental_data ||
        !_supplemental_field_available(
            supplemental_data_size,
            OE_OFFSETOF(sgx_ql_qv_supplemental_t, tcb_level_date_tag),
            sizeof(supplemental->tcb_level_date_tag)))
        return;

    *qvl_tcb_date = supplemental->tcb_level_date_tag;
    *current_tcb_date = *qvl_tcb_date;

    /* Supplemental data version 3.5 separates the current TCB from the launch
     * TCB represented by the legacy status/date. A revoked aggregate may be a
     * launch-TCB result, so still expose the independently reported current
     * TCB while preserving the revoked aggregate status. */
    if (supplemental->major_version == 3 && supplemental->minor_version >= 5 &&
        verification_result != SGX_QL_QV_RESULT_INVALID_SIGNATURE &&
        verification_result != SGX_QL_QV_RESULT_UNSPECIFIED &&
        _supplemental_field_available(
            supplemental_data_size,
            OE_OFFSETOF(sgx_ql_qv_supplemental_t, tcb_status_current),
            sizeof(supplemental->tcb_status_current)))
    {
        oe_sgx_tcb_status_t status = _verification_result_to_tcb_status(
            supplemental->tcb_status_current);

        if (status != OE_SGX_TCB_STATUS_INVALID &&
            supplemental->tcb_date_current != 0)
        {
            *current_tcb_status = status;
            *current_tcb_date = supplemental->tcb_date_current;
        }
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
    const time_t* tcb_baseline_date,
    const tdx_servtd_init_tcb_t* init_tcb,
    oe_claim_t* claims,
    size_t claims_length,
    size_t* claims_added)
{
    oe_sgx_tcb_status_t tcb_status = OE_SGX_TCB_STATUS_INVALID;
    oe_sgx_tcb_status_t qvl_tcb_status = OE_SGX_TCB_STATUS_INVALID;
    oe_sgx_tcb_status_t curr_platform_tcb_status = OE_SGX_TCB_STATUS_INVALID;
    oe_sgx_tcb_status_t init_platform_tcb_status = OE_SGX_TCB_STATUS_INVALID;
    time_t platform_tcb_date = 0;
    time_t curr_platform_tcb_date = 0;
    bool init_tcb_evaluated = (init_tcb && init_tcb->valid);
    bool init_tcb_required = (init_tcb && init_tcb->required);
    bool aggregate_uses_init_tcb = false;
    bool aggregate_tcb_date_available = true;
    const tdx_report_body_t* tdx_report = NULL;
    const tdx_report_body_v5_t* tdx_report_v5 = NULL;
    const tdx_report_body_v1_5_ex_t* tdx_report_v5_ex = NULL;
    const tdx_attributes_t* attributes = NULL;
    oe_result_t result = OE_UNEXPECTED;
    tdx_quote_t* tdx_quote = NULL;
    tdx_quote_v5_t* tdx_quote_v5 = NULL;
    size_t claims_index = 0;
    oe_identity_t id = {0};
    size_t sa_list_size = 0;
    char* sa_list = NULL;
    bool flag;

    if (claims_length <
        OE_REQUIRED_CLAIMS_COUNT + OE_TDX_REQUIRED_CLAIMS_COUNT +
            OE_TDX_SERVTD_EXT_CLAIMS_COUNT + OE_TDX_ADDITIONAL_CLAIMS_COUNT)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Apply the baseline separately to the QVL aggregate (which includes any
     * launch-TCB implications), the current platform TCB, and the Service-TD
     * initial platform TCB. */
    _get_platform_tcb_data(
        verification_result,
        supplemental_data,
        supplemental_data_size,
        &qvl_tcb_status,
        &platform_tcb_date,
        &curr_platform_tcb_status,
        &curr_platform_tcb_date);

    qvl_tcb_status = _apply_tcb_baseline_date_policy(
        qvl_tcb_status, platform_tcb_date, tcb_baseline_date);
    curr_platform_tcb_status = _apply_tcb_baseline_date_policy(
        curr_platform_tcb_status, curr_platform_tcb_date, tcb_baseline_date);

    tcb_status = qvl_tcb_status;
    if (init_tcb_required && !init_tcb_evaluated)
    {
        tcb_status = OE_SGX_TCB_STATUS_INVALID;
        aggregate_tcb_date_available = false;
    }
    else if (init_tcb_evaluated)
    {
        init_platform_tcb_status = _apply_tcb_baseline_date_policy(
            init_tcb->tcb_status, init_tcb->tcb_date_time, tcb_baseline_date);
        tcb_status = oe_tdx_get_effective_tcb_status(
            tcb_status, init_platform_tcb_status, &aggregate_uses_init_tcb);
    }

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
        /* Type 3 is TDX V5 report body; type 4 is the V5 report body extended
         * with the Service-TD extension fields (v1.5_ex). Both share the same
         * first 648 bytes, so the V5 claims apply to type 4 as well. */
        if (tdx_quote_v5->type == 3 || tdx_quote_v5->type == 4)
            tdx_report_v5 = (tdx_report_body_v5_t*)tdx_quote_v5->body;
        /* Type 4 additionally carries the Service-TD extension fields */
        if (tdx_quote_v5->type == 4)
            tdx_report_v5_ex = (tdx_report_body_v1_5_ex_t*)tdx_quote_v5->body;
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

    /* Service-TD extension claims introduced in TDX report body type 4
     * (v1.5_ex). Present only when the TD ATTRIBUTES.SERVTD_EXT bit is set. */
    if (tdx_report_v5_ex != NULL)
    {
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TDX_VMID,
            sizeof(OE_CLAIM_TDX_VMID),
            &tdx_report_v5_ex->vmid,
            sizeof(tdx_report_v5_ex->vmid)));

        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TDX_TD_ID,
            sizeof(OE_CLAIM_TDX_TD_ID),
            tdx_report_v5_ex->td_id,
            sizeof(tdx_report_v5_ex->td_id)));

        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TDX_DEVINFO,
            sizeof(OE_CLAIM_TDX_DEVINFO),
            tdx_report_v5_ex->devinfo,
            sizeof(tdx_report_v5_ex->devinfo)));

        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TDX_INIT_SERVER_TD_HASH,
            sizeof(OE_CLAIM_TDX_INIT_SERVER_TD_HASH),
            tdx_report_v5_ex->init_server_td_hash,
            sizeof(tdx_report_v5_ex->init_server_td_hash)));

        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TDX_INIT_SERVER_TD_ATTR,
            sizeof(OE_CLAIM_TDX_INIT_SERVER_TD_ATTR),
            tdx_report_v5_ex->init_server_td_attr,
            sizeof(tdx_report_v5_ex->init_server_td_attr)));

        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TDX_INIT_CPU_SVN,
            sizeof(OE_CLAIM_TDX_INIT_CPU_SVN),
            tdx_report_v5_ex->init_cpu_svn,
            sizeof(tdx_report_v5_ex->init_cpu_svn)));

        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TDX_INIT_TEE_TCB_SVN,
            sizeof(OE_CLAIM_TDX_INIT_TEE_TCB_SVN),
            (uint8_t*)&tdx_report_v5_ex->init_tee_tcb_svn,
            sizeof(tdx_report_v5_ex->init_tee_tcb_svn)));

        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TDX_INIT_TEE_FMSPC,
            sizeof(OE_CLAIM_TDX_INIT_TEE_FMSPC),
            tdx_report_v5_ex->init_tee_fmspc,
            sizeof(tdx_report_v5_ex->init_tee_fmspc)));

        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TDX_CURR_SERVER_TD_HASH,
            sizeof(OE_CLAIM_TDX_CURR_SERVER_TD_HASH),
            tdx_report_v5_ex->curr_server_td_hash,
            sizeof(tdx_report_v5_ex->curr_server_td_hash)));

        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TDX_CURR_SERVER_TD_ATTR,
            sizeof(OE_CLAIM_TDX_CURR_SERVER_TD_ATTR),
            tdx_report_v5_ex->curr_server_td_attr,
            sizeof(tdx_report_v5_ex->curr_server_td_attr)));

        /* When the Service-TD's initial platform TCB could be evaluated, emit
         * the current-platform and initial-platform TCB status/date components
         * alongside the QVL aggregate. Each component status is the effective
         * status after the TCB-date baseline policy. */
        if (init_tcb_evaluated)
        {
            char tcb_date_str[OE_DATETIME_STRING_SIZE] = {0};
            size_t tcb_date_str_size = sizeof(tcb_date_str);
            oe_datetime_t curr_platform_date = {0};

            OE_CHECK(_add_claim(
                &claims[claims_index++],
                OE_CLAIM_TDX_CURR_PLATFORM_TCB_STATUS,
                sizeof(OE_CLAIM_TDX_CURR_PLATFORM_TCB_STATUS),
                &curr_platform_tcb_status,
                sizeof(curr_platform_tcb_status)));

            if (curr_platform_tcb_date != 0)
            {
                OE_CHECK(oe_datetime_from_time_t(
                    curr_platform_tcb_date, &curr_platform_date));
                OE_CHECK(oe_datetime_to_string(
                    &curr_platform_date, tcb_date_str, &tcb_date_str_size));
                OE_CHECK(_add_claim(
                    &claims[claims_index++],
                    OE_CLAIM_TDX_CURR_PLATFORM_TCB_DATE,
                    sizeof(OE_CLAIM_TDX_CURR_PLATFORM_TCB_DATE),
                    tcb_date_str,
                    tcb_date_str_size));
            }

            OE_CHECK(_add_claim(
                &claims[claims_index++],
                OE_CLAIM_TDX_INIT_PLATFORM_TCB_STATUS,
                sizeof(OE_CLAIM_TDX_INIT_PLATFORM_TCB_STATUS),
                &init_platform_tcb_status,
                sizeof(init_platform_tcb_status)));

            tcb_date_str_size = sizeof(tcb_date_str);
            OE_CHECK(oe_datetime_to_string(
                &init_tcb->tcb_date, tcb_date_str, &tcb_date_str_size));
            OE_CHECK(_add_claim(
                &claims[claims_index++],
                OE_CLAIM_TDX_INIT_PLATFORM_TCB_DATE,
                sizeof(OE_CLAIM_TDX_INIT_PLATFORM_TCB_DATE),
                tcb_date_str,
                tcb_date_str_size));
        }
    }

    /* Additional claims */

    /* The aggregate starts with the QVL status, which retains launch-TCB
     * implications, and includes the Service-TD initial platform TCB when that
     * is required to avoid a false UP_TO_DATE result. */

    // TCB status.
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_TCB_STATUS,
        sizeof(OE_CLAIM_TCB_STATUS),
        &tcb_status,
        sizeof(tcb_status)));

    if (platform_tcb_date && aggregate_tcb_date_available)
    {
        oe_datetime_t aggregate_tcb_date = {0};

        if (aggregate_uses_init_tcb)
            aggregate_tcb_date = init_tcb->tcb_date;
        else
            OE_CHECK(oe_datetime_from_time_t(
                platform_tcb_date, &aggregate_tcb_date));

        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TCB_DATE,
            sizeof(OE_CLAIM_TCB_DATE),
            &aggregate_tcb_date,
            sizeof(aggregate_tcb_date)));
    }

    if (tcb_baseline_date)
    {
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_TCB_BASELINE_DATE,
            sizeof(OE_CLAIM_TCB_BASELINE_DATE),
            tcb_baseline_date,
            sizeof(*tcb_baseline_date)));
    }

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
    const time_t* tcb_baseline_date,
    const tdx_servtd_init_tcb_t* init_tcb,
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
                    OE_TDX_SERVTD_EXT_CLAIMS_COUNT +
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
        tcb_baseline_date,
        init_tcb,
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

/* Extract the optional TCB-date baseline policy
 * (OE_POLICY_TCB_BASELINE_DATE). The policy value is a Unix epoch timestamp
 * (seconds since 1970-01-01T00:00:00Z) stored as an int64_t. */
static oe_result_t _get_tcb_baseline_date(
    const oe_policy_t* policies,
    size_t policies_size,
    time_t* tcb_baseline_date,
    bool* has_tcb_baseline_date)
{
    oe_result_t result = OE_UNEXPECTED;

    *has_tcb_baseline_date = false;

    if (!policies)
        return OE_OK;

    for (size_t i = 0; i < policies_size; i++)
    {
        if (policies[i].type == OE_POLICY_TCB_BASELINE_DATE)
        {
            int64_t baseline = 0;

            if (!policies[i].policy ||
                policies[i].policy_size != sizeof(baseline))
                OE_RAISE(OE_INVALID_PARAMETER);

            memcpy(&baseline, policies[i].policy, sizeof(baseline));

            *tcb_baseline_date = (time_t)baseline;
            *has_tcb_baseline_date = true;
            return OE_OK;
        }
    }

    // Baseline date not found, which is fine since it's optional.
    result = OE_OK;

done:
    return result;
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
    time_t tcb_baseline_date = 0;
    bool has_tcb_baseline_date = false;

    if (!context || !evidence_buffer || !evidence_buffer_size ||
        (!endorsements_buffer != !endorsements_buffer_size) ||
        (!policies != !policies_size) || (!claims != !claims_length))
        OE_RAISE(OE_INVALID_PARAMETER);

    format_id = &context->base.format_id;

    OE_CHECK(_get_input_time(policies, policies_size, &time));

    OE_CHECK(_get_tcb_baseline_date(
        policies, policies_size, &tcb_baseline_date, &has_tcb_baseline_date));

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
        tdx_servtd_init_tcb_t init_tcb = {0};

#if OE_TDX_ENABLE_SERVTD_INIT_TCB_EVAL
        /* Evaluate the Service-TD's initial platform TCB (type-4 quotes only).
         * This is best-effort: on any failure the init TCB is treated as not
         * evaluated and the primary verification result is unaffected. */
        OE_CHECK(_evaluate_servtd_init_tcb(
            evidence_buffer,
            evidence_buffer_size,
            endorsements_buffer,
            endorsements_buffer_size,
            &init_tcb));
#endif /* OE_TDX_ENABLE_SERVTD_INIT_TCB_EVAL */

        OE_CHECK(_extract_claims(
            format_id,
            evidence_buffer,
            evidence_buffer_size,
            verification_result,
            supplemental_data,
            supplemental_data_size,
            has_tcb_baseline_date ? &tcb_baseline_date : NULL,
            &init_tcb,
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
