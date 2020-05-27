// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "endorsements.h"
#include <openenclave/bits/attestation.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include "../common.h"

#include "collateral.h"
#include "quote.h"

#define CREATION_DATETIME_SIZE 21

/**
 * Create oe_endorsements_t from the given SGX endorsements.
 *
 * @param[in] revocation_info SGX revocation information.
 * @param[in] qe_id_info SGX QE identity information.
 * @param[out] endorsements OE endorsement structure.
 */
static oe_result_t oe_create_sgx_endorsements(
    const oe_get_sgx_quote_verification_collateral_args_t*
        quote_verification_collateral,
    oe_endorsements_t** endorsements_buffer,
    size_t* endorsements_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_endorsements_t* endorsements = NULL;
    uint8_t* root_ca_crl_issuer_chain =
        oe_malloc(quote_verification_collateral->pck_crl_issuer_chain_size);
    char creation_datetime[CREATION_DATETIME_SIZE];
    uint32_t* buffer32 = NULL;
    uint8_t* buffer = NULL;
    uint32_t offset;
    uint32_t offsets_size;
    uint32_t size;
    uint32_t root_ca_crl_issuer_chain_size;
    uint32_t remaining_size;

    OE_TRACE_INFO("Enter call %s\n", __FUNCTION__);

    if (quote_verification_collateral == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    offsets_size = (uint32_t)sizeof(uint32_t) * OE_SGX_ENDORSEMENT_COUNT;
    size = (uint32_t)sizeof(oe_endorsements_t) + // Header
           offsets_size +                        // Array of offsets
           (uint32_t)(                           // Data
               sizeof(uint32_t) +                // Version
               quote_verification_collateral->tcb_info_size +
               quote_verification_collateral->tcb_info_issuer_chain_size +
               quote_verification_collateral->qe_identity_size +
               quote_verification_collateral->qe_identity_issuer_chain_size);

    size += (uint32_t)quote_verification_collateral->pck_crl_size;
    size += (uint32_t)quote_verification_collateral->root_ca_crl_size;
    size += (uint32_t)quote_verification_collateral->pck_crl_issuer_chain_size;

    root_ca_crl_issuer_chain_size =
        (uint32_t)quote_verification_collateral->pck_crl_issuer_chain_size;
    size += root_ca_crl_issuer_chain_size;

    OE_CHECK(oe_memcpy_s(
        root_ca_crl_issuer_chain,
        root_ca_crl_issuer_chain_size,
        quote_verification_collateral->pck_crl_issuer_chain,
        quote_verification_collateral->pck_crl_issuer_chain_size));

    size += CREATION_DATETIME_SIZE;
    if (size > OE_ATTESTATION_ENDORSEMENT_MAX_SIZE)
        OE_RAISE_MSG(
            OE_INVALID_PARAMETER,
            "SGX endorsements are too large. Size is %d bytes",
            size);

    // Allocate memory
    endorsements = (oe_endorsements_t*)oe_calloc(1, size);
    if (endorsements == NULL)
        OE_RAISE_MSG(
            OE_OUT_OF_MEMORY,
            "Out of memory while creating endorsements.",
            NULL);

    // Record creation datetime.
    {
        oe_datetime_t datetime_now = {0};
        size_t datetime_size = CREATION_DATETIME_SIZE;

        OE_CHECK(oe_datetime_now(&datetime_now));

        OE_CHECK_MSG(
            oe_datetime_to_string(
                &datetime_now, creation_datetime, &datetime_size),
            "Failed to update endorsement creation time. %s",
            oe_result_str(result));
    }

    // Initialize header
    endorsements->version = OE_ATTESTATION_ENDORSEMENT_VERSION;
    endorsements->enclave_type = OE_ENCLAVE_TYPE_SGX;
    endorsements->num_elements = OE_SGX_ENDORSEMENT_COUNT;
    endorsements->buffer_size = size - (uint32_t)sizeof(oe_endorsements_t);
    buffer32 = (uint32_t*)&endorsements->buffer[0];

    // Set offsets
    offset = 0;
    buffer32[OE_SGX_ENDORSEMENT_FIELD_VERSION] = offset;
    offset += (uint32_t)sizeof(uint32_t);
    buffer32[OE_SGX_ENDORSEMENT_FIELD_TCB_INFO] = offset;
    offset += (uint32_t)quote_verification_collateral->tcb_info_size;
    buffer32[OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN] = offset;
    offset +=
        (uint32_t)quote_verification_collateral->tcb_info_issuer_chain_size;

    buffer32[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT] = offset;
    offset += (uint32_t)quote_verification_collateral->pck_crl_size;

    buffer32[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA] = offset;
    offset += (uint32_t)quote_verification_collateral->root_ca_crl_size;

    buffer32[OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_CERT] = offset;
    offset +=
        (uint32_t)quote_verification_collateral->pck_crl_issuer_chain_size;

    buffer32[OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_PROC_CA] = offset;
    offset += root_ca_crl_issuer_chain_size;

    buffer32[OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO] = offset;
    offset += (uint32_t)quote_verification_collateral->qe_identity_size;
    buffer32[OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN] = offset;
    offset +=
        (uint32_t)quote_verification_collateral->qe_identity_issuer_chain_size;
    buffer32[OE_SGX_ENDORSEMENT_FIELD_CREATION_DATETIME] = offset;
    offset += CREATION_DATETIME_SIZE;

    // Sanity check
    if (offset != (endorsements->buffer_size - offsets_size))
        OE_RAISE_MSG(
            OE_FAILURE,
            "Encountered size mismatch when creating SGX endorsements. "
            "data size: %d bytes, expected: %d",
            offset,
            (endorsements->buffer_size - offsets_size));

    OE_TRACE_INFO(
        "SGX endorsements. Header size: %d, offsets size: %d, data size: %d",
        sizeof(oe_endorsements_t),
        offsets_size,
        offset);

    // Set version
    buffer = (uint8_t*)&buffer32[OE_SGX_ENDORSEMENT_COUNT];
    *((uint32_t*)buffer) = OE_SGX_ENDORSEMENTS_VERSION;
    buffer += sizeof(uint32_t);
    remaining_size =
        size - (uint32_t)((uint8_t*)buffer - (uint8_t*)endorsements);

    // Copy TCB Info
    OE_CHECK(oe_memcpy_s(
        buffer,
        remaining_size,
        quote_verification_collateral->tcb_info,
        quote_verification_collateral->tcb_info_size));
    buffer += quote_verification_collateral->tcb_info_size;
    remaining_size -= (uint32_t)quote_verification_collateral->tcb_info_size;

    // Copy TCB Issuer Chain
    OE_CHECK(oe_memcpy_s(
        buffer,
        remaining_size,
        quote_verification_collateral->tcb_info_issuer_chain,
        quote_verification_collateral->tcb_info_issuer_chain_size));
    buffer += quote_verification_collateral->tcb_info_issuer_chain_size;
    remaining_size -=
        (uint32_t)quote_verification_collateral->tcb_info_issuer_chain_size;

    // Copy CRLs
    OE_CHECK(oe_memcpy_s(
        buffer,
        remaining_size,
        quote_verification_collateral->pck_crl,
        quote_verification_collateral->pck_crl_size));
    buffer += quote_verification_collateral->pck_crl_size;
    remaining_size -= (uint32_t)quote_verification_collateral->pck_crl_size;

    OE_CHECK(oe_memcpy_s(
        buffer,
        remaining_size,
        quote_verification_collateral->root_ca_crl,
        quote_verification_collateral->root_ca_crl_size));
    buffer += quote_verification_collateral->root_ca_crl_size;
    remaining_size -= (uint32_t)quote_verification_collateral->root_ca_crl_size;

    // Copy CRLs Issuer Chain
    OE_CHECK(oe_memcpy_s(
        buffer,
        remaining_size,
        quote_verification_collateral->pck_crl_issuer_chain,
        quote_verification_collateral->pck_crl_issuer_chain_size));
    buffer += quote_verification_collateral->pck_crl_issuer_chain_size;
    remaining_size -=
        (uint32_t)quote_verification_collateral->pck_crl_issuer_chain_size;

    OE_CHECK(oe_memcpy_s(
        buffer,
        remaining_size,
        root_ca_crl_issuer_chain,
        root_ca_crl_issuer_chain_size));
    buffer += root_ca_crl_issuer_chain_size;
    remaining_size -= (uint32_t)root_ca_crl_issuer_chain_size;

    // Copy QE ID Info
    OE_CHECK(oe_memcpy_s(
        buffer,
        remaining_size,
        quote_verification_collateral->qe_identity,
        quote_verification_collateral->qe_identity_size));
    buffer += quote_verification_collateral->qe_identity_size;
    remaining_size -= (uint32_t)quote_verification_collateral->qe_identity_size;

    // Copy QE ID Issue Chain
    OE_CHECK(oe_memcpy_s(
        buffer,
        remaining_size,
        quote_verification_collateral->qe_identity_issuer_chain,
        quote_verification_collateral->qe_identity_issuer_chain_size));
    buffer += quote_verification_collateral->qe_identity_issuer_chain_size;
    remaining_size -=
        (uint32_t)quote_verification_collateral->qe_identity_issuer_chain_size;

    // Copy creation datetime
    OE_CHECK(oe_memcpy_s(
        buffer, remaining_size, creation_datetime, CREATION_DATETIME_SIZE));
    buffer += CREATION_DATETIME_SIZE;

    // Sanity check
    if (buffer != (endorsements->buffer + endorsements->buffer_size))
        OE_RAISE_MSG(
            OE_FAILURE,
            "Encountered size mismatch when creating SGX endorsements. "
            "end of data section: 0x%x bytes, expected: 0x%x",
            buffer,
            (endorsements->buffer + endorsements->buffer_size));

    *endorsements_buffer = endorsements;
    *endorsements_buffer_size = size;

    result = OE_OK;

done:
    if ((result != OE_OK) && endorsements)
        oe_free(endorsements);

    if (root_ca_crl_issuer_chain)
    {
        oe_free(root_ca_crl_issuer_chain);
    }

    OE_TRACE_INFO(
        "Exit call %s: %d(%s)\n", __FUNCTION__, result, oe_result_str(result));

    return result;
}

/**
 * Converts an oe_endorsement_t structure to a SGX endorsement structure
 * (oe_sgx_endorsements_t).
 *
 * @param[in] endorsements The endorsements in raw format (oe_endorsements_t)
 * @param[out] sgx_endorsements The parsed SGX endorsements.
 */
oe_result_t oe_parse_sgx_endorsements(
    const oe_endorsements_t* endorsements,
    const size_t endorsements_size,
    oe_sgx_endorsements_t* sgx_endorsements)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t* offsets = NULL;
    uint32_t offsets_size = 0;
    uint8_t* data_ptr_start = NULL;
    uint32_t data_size;
    uint32_t version = 0;

    if (endorsements == NULL || sgx_endorsements == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Verify version and enclave type
    if ((endorsements->version != OE_ATTESTATION_ENDORSEMENT_VERSION) ||
        (endorsements->enclave_type != OE_ENCLAVE_TYPE_SGX))
        OE_RAISE_MSG(
            OE_INVALID_PARAMETER,
            "Failed to parse SGX endorsement. "
            "Invalid version=%d or enclave type=%d",
            endorsements->version,
            endorsements->enclave_type);

    if (endorsements->num_elements != OE_SGX_ENDORSEMENT_COUNT)
        OE_RAISE_MSG(
            OE_INVALID_PARAMETER,
            "Failed to parse SGX endorsement. Exepected %d items, but got %d.",
            OE_SGX_ENDORSEMENT_COUNT,
            endorsements->num_elements);

    offsets_size = endorsements->num_elements * (uint32_t)sizeof(uint32_t);
    if (endorsements_size > OE_ATTESTATION_ENDORSEMENT_MAX_SIZE ||
        endorsements->buffer_size > endorsements_size ||
        endorsements->buffer_size <= offsets_size)
        OE_RAISE_MSG(
            OE_INVALID_PARAMETER, "Endorsement buffer size is invalid.", NULL);

    data_size = endorsements->buffer_size - offsets_size;
    offsets = (uint32_t*)endorsements->buffer;
    data_ptr_start = (uint8_t*)(endorsements->buffer + offsets_size);

    memset(sgx_endorsements, 0, sizeof(oe_sgx_endorsements_t));

    version = *((uint32_t*)data_ptr_start);
    if (version != OE_SGX_ENDORSEMENTS_VERSION)
        OE_RAISE_MSG(
            OE_INVALID_PARAMETER,
            "Unexpected SGX endorsement version %d, expected %d",
            version,
            OE_SGX_ENDORSEMENTS_VERSION);

    OE_TRACE_INFO("SGX Version: %d", version);
    for (int i = 0; i < OE_SGX_ENDORSEMENT_COUNT; i++)
    {
        uint8_t* item_ptr = data_ptr_start + offsets[i];
        uint32_t item_size;

        if (offsets[i] >= endorsements->buffer_size)
            OE_RAISE_MSG(
                OE_INVALID_PARAMETER,
                "Offset value when creating SGX endorsement is incorrect.",
                NULL);

        if (i < OE_SGX_ENDORSEMENT_COUNT - 1)
            item_size = offsets[i + 1] - offsets[i];
        else
            item_size = data_size - offsets[i];

        sgx_endorsements->items[i].data = item_ptr;
        sgx_endorsements->items[i].size = item_size;

        OE_TRACE_VERBOSE(
            "SGX endorsement %d, size(%d): %s\n", i, item_size, item_ptr);
    }

    result = OE_OK;
done:

    return result;
}

oe_result_t oe_get_sgx_endorsements(
    const uint8_t* remote_report,
    size_t remote_report_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_sgx_quote_verification_collateral_args_t
        quote_verification_collateral = {0};

    const uint8_t* pem_pck_certificate = NULL;
    size_t pem_pck_certificate_size = 0;
    oe_cert_chain_t pck_cert_chain = {0};
    oe_cert_t leaf_cert = {0};
    oe_cert_t intermediate_cert = {0};

    OE_TRACE_INFO("Enter call %s\n", __FUNCTION__);

    if ((endorsements_buffer == NULL) || (endorsements_buffer_size == NULL))
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    *endorsements_buffer = NULL;
    *endorsements_buffer_size = 0;

    // Get PCK cert chain from the quote.
    OE_CHECK_MSG(
        oe_get_quote_cert_chain_internal(
            remote_report,
            remote_report_size,
            &pem_pck_certificate,
            &pem_pck_certificate_size,
            &pck_cert_chain),
        "Failed to get certificate chain from quote. %s",
        oe_result_str(result));

    // Fetch leaf and intermediate certificates.
    OE_CHECK_MSG(
        oe_cert_chain_get_leaf_cert(&pck_cert_chain, &leaf_cert),
        "Failed to get leaf certificate. %s",
        oe_result_str(result));
    OE_CHECK_MSG(
        oe_cert_chain_get_cert(&pck_cert_chain, 1, &intermediate_cert),
        "Failed to get intermediate certificate. %s",
        oe_result_str(result));

    // Get quote verification collateral
    OE_CHECK_MSG(
        oe_get_sgx_quote_verification_collateral_from_certs(
            &leaf_cert, &quote_verification_collateral),
        "Failed to get certificate quote verification collateral information. "
        "%s",
        oe_result_str(result));

    OE_CHECK_MSG(
        oe_create_sgx_endorsements(
            &quote_verification_collateral,
            (oe_endorsements_t**)endorsements_buffer,
            endorsements_buffer_size),
        "Failed to create SGX endorsements.",
        oe_result_str(result));

    result = OE_OK;

done:
    oe_cert_free(&leaf_cert);
    oe_cert_free(&intermediate_cert);
    oe_cert_chain_free(&pck_cert_chain);
    oe_free_sgx_quote_verification_collateral_args(
        &quote_verification_collateral);

    OE_TRACE_INFO(
        "Exit call %s: %d(%s)\n", __FUNCTION__, result, oe_result_str(result));

    return result;
}

/**
 * Free up any resources allocated by oe_get_sgx_endorsements()
 *
 * @param endorsements_buffer The buffer containing the endorsements.
 */
void oe_free_sgx_endorsements(uint8_t* endorsements_buffer)
{
    if (endorsements_buffer)
    {
        oe_free(endorsements_buffer);
    }
}
