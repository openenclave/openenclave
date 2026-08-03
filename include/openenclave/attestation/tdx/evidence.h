// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ATTESTATION_TDX_EVIDENCE_H
#define _OE_ATTESTATION_TDX_EVIDENCE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

#define OE_FORMAT_UUID_TDX_QUOTE_ECDSA                                    \
    {                                                                     \
        0x8b, 0xa7, 0x02, 0x86, 0xc1, 0xcf, 0x11, 0xed, 0xaf, 0xa1, 0x02, \
            0x42, 0xac, 0x12, 0x00, 0x02                                  \
    }

/*
 * Base claims from TDX report
 */
#define OE_CLAIM_TDX_TEE_TCB_SVN "tdx_tee_tcb_svn"
#define OE_CLAIM_TDX_MRSEAM "tdx_mrseam"
#define OE_CLAIM_TDX_MRSEAMSIGNER "tdx_mrseamsigner"
#define OE_CLAIM_TDX_SEAM_ATTRIBUTES "tdx_seam_attributes"
#define OE_CLAIM_TDX_TD_ATTRIBUTES "tdx_td_attributes"
#define OE_CLAIM_TDX_TD_ATTRIBUTES_DEBUG "tdx_td_attributes_debug"
#define OE_CLAIM_TDX_TD_ATTRIBUTES_HGS_PLUS_PROF \
    "tdx_td_attributes_hgs_plus_prof"
#define OE_CLAIM_TDX_TD_ATTRIBUTES_PERF_PROF "tdx_td_attributes_perf_prof"
#define OE_CLAIM_TDX_TD_ATTRIBUTES_PMT_PROF "tdx_td_attributes_pmt_prof"
#define OE_CLAIM_TDX_TD_ATTRIBUTES_ICSSD "tdx_td_attributes_icssd"
#define OE_CLAIM_TDX_TD_ATTRIBUTES_SERVTD_EXT "tdx_td_attributes_servtd_ext"
#define OE_CLAIM_TDX_TD_ATTRIBUTES_LASS "tdx_td_attributes_lass"
#define OE_CLAIM_TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE \
    "tdx_td_attributes_septve_disable"
#define OE_CLAIM_TDX_TD_ATTRIBUTES_MIGRATABLE "tdx_td_attributes_migratable"
#define OE_CLAIM_TDX_TD_ATTRIBUTES_PROTECTION_KEYS \
    "tdx_td_attributes_protection_keys"
#define OE_CLAIM_TDX_TD_ATTRIBUTES_KEY_LOCKER "tdx_td_attributes_key_locker"
#define OE_CLAIM_TDX_TD_ATTRIBUTES_PERFMON "tdx_td_attributes_perfmon"
#define OE_CLAIM_TDX_XFAM "tdx_xfam"
#define OE_CLAIM_TDX_MRTD "tdx_mrtd"
#define OE_CLAIM_TDX_MRCONFIGID "tdx_mrconfigid"
#define OE_CLAIM_TDX_MROWNER "tdx_mrowner"
#define OE_CLAIM_TDX_MROWNERCONFIG "tdx_mrownerconfig"
#define OE_CLAIM_TDX_RTMR0 "tdx_rtmr0"
#define OE_CLAIM_TDX_RTMR1 "tdx_rtmr1"
#define OE_CLAIM_TDX_RTMR2 "tdx_rtmr2"
#define OE_CLAIM_TDX_RTMR3 "tdx_rtmr3"
#define OE_CLAIM_TDX_REPORT_DATA "tdx_report_data"
#define OE_CLAIM_TDX_TEE_TCB_SVN_2 "tdx_tee_tcb_svn_2"
#define OE_CLAIM_TDX_MRSERVICETD "tdx_mrservicetd"
#define OE_TDX_REQUIRED_CLAIMS_COUNT 29

/*
 * Service-TD extension claims from the TDX report body type 4 (v1.5_ex).
 * Emitted for a type-4 report body (which carries these raw fields). They
 * describe the Service-TD bound to the TD both at build time (init_*) and
 * currently (curr_*), plus the platform TCB context recorded when the
 * Service-TD was first bound. The values are only semantically meaningful when
 * the TD ATTRIBUTES.SERVTD_EXT bit is set.
 */
#define OE_CLAIM_TDX_VMID "tdx_vmid"
#define OE_CLAIM_TDX_TD_ID "tdx_td_id"
#define OE_CLAIM_TDX_DEVINFO "tdx_devinfo"
#define OE_CLAIM_TDX_INIT_SERVER_TD_HASH "tdx_init_server_td_hash"
#define OE_CLAIM_TDX_INIT_SERVER_TD_ATTR "tdx_init_server_td_attr"
#define OE_CLAIM_TDX_INIT_CPU_SVN "tdx_init_cpu_svn"
#define OE_CLAIM_TDX_INIT_TEE_TCB_SVN "tdx_init_tee_tcb_svn"
#define OE_CLAIM_TDX_INIT_TEE_FMSPC "tdx_init_tee_fmspc"
#define OE_CLAIM_TDX_CURR_SERVER_TD_HASH "tdx_curr_server_td_hash"
#define OE_CLAIM_TDX_CURR_SERVER_TD_ATTR "tdx_curr_server_td_attr"
/*
 * Per-component TCB status and TCB date that feed the aggregate OE_CLAIM_TCB_STATUS
 * claim, emitted only for a Service-TD extension quote (type-4 body with the
 * ATTRIBUTES.SERVTD_EXT bit set) whose initial platform TCB could be evaluated
 * (see OE_TDX_ENABLE_SERVTD_INIT_TCB_EVAL; also requires init_tee_fmspc to match
 * the platform FMSPC). Each status is the
 * effective SGX TCB status after the OE_POLICY_TCB_BASELINE_DATE policy is
 * applied to that component's own TCB date. OE_CLAIM_TCB_STATUS preserves the
 * QVL result, including launch-TCB implications from a TD-preserving update,
 * unless it is UP_TO_DATE and the evaluated initial-platform status is not.
 * Consumers should use these component claims for the complete status details.
 *   - curr: the current platform TCB (from supplemental data version 3.5 when
 *     available; otherwise from the QVL result)
 *   - init: the Service-TD's initial platform TCB (from init_cpu_svn /
 *     init_tee_tcb_svn recorded when the Service-TD was first bound)
 */
#define OE_CLAIM_TDX_CURR_PLATFORM_TCB_STATUS "tdx_curr_platform_tcb_status"
#define OE_CLAIM_TDX_CURR_PLATFORM_TCB_DATE "tdx_curr_platform_tcb_date"
#define OE_CLAIM_TDX_INIT_PLATFORM_TCB_STATUS "tdx_init_platform_tcb_status"
#define OE_CLAIM_TDX_INIT_PLATFORM_TCB_DATE "tdx_init_platform_tcb_date"
#define OE_TDX_SERVTD_EXT_CLAIMS_COUNT 14

/*
 * Additional claims from other sources (e.g., data returned by QvE/QVL)
 */
#define OE_CLAIM_TDX_SA_LIST "tdx_sa_list"
#define OE_CLAIM_TDX_PCE_SVN "tdx_pce_svn"

// 2 above + TCB_STATUS + TCB_DATE + TCB_BASELINE_DATE
#define OE_TDX_ADDITIONAL_CLAIMS_COUNT 5

/**
 * oe_tdx_verifier_initialize
 *
 * Initializes the TDX verifier environment configured for the platform and
 * the calling application.
 *
 * This function is idempotent and can be called multiple times without
 * adverse effect.
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_tdx_verifier_initialize(void);

/**
 * oe_tdx_verifier_shutdown
 *
 * Shuts down the TDX verifier environment configured for the platform and
 * the calling application.
 *
 * This function is idempotent and can be called multiple times without
 * adverse effect.
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_tdx_verifier_shutdown(void);

/**
 * oe_get_tdx_endorsements
 *
 * Fetch serialized endorsements for the given evidence.
 *
 * @param[in] evidence_buffer Input evidence.
 * @param[in] evidence_buffer_size The size of evidence.
 * @param[out] endorsements_buffer Output endorsements.
 * @param[out] endorsements_buffer The size of output endorsements.
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_get_tdx_endorsements(
    const uint8_t* evidence_buffer,
    uint32_t evidence_buffer_size,
    uint8_t** endorsements_buffer,
    uint32_t* endorsements_buffer_size);

/**
 * oe_free_tdx_endorsements
 *
 * Free the endorsements obtained from oe_get_tdx_endorsements
 *
 * @param[in] endorsements_buffer Input endorsements.
 *
 */
void oe_free_tdx_endorsements(uint8_t* endorsements_buffer);

/**
 * Size in bytes of the FMSPC (Family-Model-Stepping-Platform-CustomSKU)
 * extracted from a TDX quote.
 */
#define OE_TDX_FMSPC_SIZE 6

/**
 * oe_get_tdx_fmspc_from_quote
 *
 * Extract the FMSPC (Family-Model-Stepping-Platform-CustomSKU) from a TDX
 * quote. The FMSPC identifies the platform's TCB and is used to look up the
 * matching TCB info collateral.
 *
 * @param[in] quote Input TDX quote.
 * @param[in] quote_size The size of the quote in bytes.
 * @param[out] fmspc Output buffer that receives the FMSPC bytes.
 * @param[in] fmspc_size The size of the output buffer. Must be at least
 * OE_TDX_FMSPC_SIZE.
 *
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER a parameter is NULL or fmspc_size is too small.
 * @retval other appropriate error code.
 */
oe_result_t oe_get_tdx_fmspc_from_quote(
    const uint8_t* quote,
    uint32_t quote_size,
    uint8_t* fmspc,
    uint32_t fmspc_size);

OE_EXTERNC_END

#endif /* _OE_ATTESTATION_TDX_EVIDENCE_H */
