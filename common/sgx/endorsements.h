// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_COMMON_OE_ENDORSEMENTS_H
#define _OE_COMMON_OE_ENDORSEMENTS_H

#include <openenclave/bits/attestation.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

/*! \struct SGX endorsement item
 */
typedef struct _oe_sgx_endorsement_item
{
    uint8_t* data;
    uint32_t size;
} oe_sgx_endorsement_item;

/*! \struct oe_sgx_endorsements
 *
 * \brief SGX endorsements structure
 *
 * The generic oe_endorsements_t structure is parsed and converted into this
 * internal structure.  The order of the generic data elements should
 * coincide with the order of the fields in this structure.
 *
 * Data format: All data comes from the Data Center Attestation Primitives(DCAP)
 * Client.
 *
 * For Azure DCAP Client
 * (https://github.com/microsoft/Azure-DCAP-Client/blob/master/src/dcap_provider.h)
 * see **sgx_ql_revocation_info_t** and sgx_qe_identity_info_t.
 *
 * For Intel DCAP Client
 * (https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/README.md)
 * see TBD.
 *
 */
typedef struct _oe_sgx_endorsements_t
{
    ///< OE_SGX_ENDORSEMENT_FIELD_VERSION
    ///<    Version of this SGX endorsement structure

    ///< OE_SGX_ENDORSEMENT_FIELD_TCB_INFO
    ///<    TCB info, null-terminated JSON string
    ///<    TCB Info size
    ///< OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN
    ///<    PEM format, null-terminated string
    ///<    Size of the tcb_issuer_chain

    ///< OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT to
    ///<    OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA
    ///< CRLs in DER format, null-terminated
    ///<     crl[0] = CRL for the SGX PCK Certificate
    ///<     crl[1] = CRL for the SGX PCK Processor CA

    ///< OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_CERT
    ///< CRLs issuer chains in PEM format, null-terminated string
    ///<     Issuer Chain for the SGX PCK Certificate

    ///< OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO
    ///<    QE Identity info, null-terminated JSON string
    ///<    QE Identity size
    ///< OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN
    ///<    PEM format, null-terminated string
    ///<    Size of qe_id_issuer_chain

    ///< OE_SGX_ENDORSEMENT_FIELD_CREATION_DATETIME
    ///<    Time the endorsements were generated, null-terminated string
    ///<    The size of creation_datetime.
    oe_sgx_endorsement_item items[OE_SGX_ENDORSEMENT_COUNT];

} oe_sgx_endorsements_t;

/**
 * Convert a oe_endorsement_t structure to a SGX endorsement structure
 * (oe_sgx_endorsements_t).
 *
 * @param[in] endorsements The endorsements in raw format (oe_endorsements_t)
 * @param[in] endorsements_size The size of the **endorsements**
 * @param[out] sgx_endorsements The parsed SGX endorsements.
 */
oe_result_t oe_parse_sgx_endorsements(
    const oe_endorsements_t* endorsements,
    const size_t endorsements_size,
    oe_sgx_endorsements_t* sgx_endorsements);

/**
 * Get the endorsements for the respective SGX remote report.
 *
 * @param[in] remote_report The remote report.
 * @param[in] remote_report_size The size of the remote report.
 * @param[out] endorsements_buffer The buffer where to store the endorsements.
 * @param[out] endorsements_buffer_size The size of the endorsements.
 */
oe_result_t oe_get_sgx_endorsements(
    const uint8_t* remote_report,
    size_t remote_report_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size);

/**
 * Free up any resources allocated by oe_get_sgx_endorsements()
 *
 * @param[in] endorsements_buffer The buffer containing the endorsements.
 */
void oe_free_sgx_endorsements(uint8_t* endorsements_buffer);

OE_EXTERNC_END

#endif /* _OE_COMMON_OE_ENDORSEMENTS_H */
