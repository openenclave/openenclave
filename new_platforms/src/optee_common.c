/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>

#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

#include <RiotStatus.h>
#include <RiotEcc.h>
#include <RiotCrypt.h>
#include <TcpsId.h>

#if !defined(_MSC_VER) || defined(OE_NO_SAL)
#include "sal_unsup.h"
#endif

// based on mbedtls x509_get_crt_ext
static int mbedtls_x509_get_oid_value(
    uint8_t* der_extension_buffer,
    size_t der_extension_buffer_len,
    uint8_t* oid,
    size_t oid_size,
    uint8_t** oid_data,
    size_t* oid_data_size)
{
    int ret;
    size_t len;
    unsigned char** p = &der_extension_buffer;
    const unsigned char* end = der_extension_buffer + der_extension_buffer_len;
    unsigned char *end_ext_data, *end_ext_octet;

    *oid_data = NULL;

    if ((ret = mbedtls_asn1_get_tag(
             p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) !=
        0)
        return (MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);

    while (*p < end)
    {
        /*
         * Extension  ::=  SEQUENCE  {
         *      extnID      OBJECT IDENTIFIER,
         *      critical    BOOLEAN DEFAULT FALSE,
         *      extnValue   OCTET STRING  }
         */
        mbedtls_x509_buf extn_oid = {0, 0, NULL};
        int is_critical = 0; /* DEFAULT FALSE */
        int ext_type = 0;

        if ((ret = mbedtls_asn1_get_tag(
                 p,
                 end,
                 &len,
                 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
            return (MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);

        end_ext_data = *p + len;

        /* Get extension ID */
        if ((ret = mbedtls_asn1_get_tag(
                 p, end_ext_data, &extn_oid.len, MBEDTLS_ASN1_OID)) != 0)
            return (MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);

        extn_oid.tag = MBEDTLS_ASN1_OID;
        extn_oid.p = *p;
        *p += extn_oid.len;

        /* Get optional critical */
        if ((ret = mbedtls_asn1_get_bool(p, end_ext_data, &is_critical)) != 0 &&
            (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG))
            return (MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);

        /* Data should be octet string type */
        if ((ret = mbedtls_asn1_get_tag(
                 p, end_ext_data, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0)
            return (MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);

        end_ext_octet = *p + len;

        if (end_ext_octet != end_ext_data)
            return (
                MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);

        if (extn_oid.len != oid_size || memcmp(extn_oid.p, oid, oid_size))
        {
            *p = end_ext_octet;
            continue;
        }

        if ((ret = mbedtls_asn1_get_tag(
                 p, end_ext_data, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0)
            return (MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);

        if (end_ext_octet != *p + len)
            return (
                MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);

        *oid_data = *p;
        *oid_data_size = len;
        break;
    }

    return 0;
}

static oe_result_t get_claim_oid_data(
    uint8_t* der_extension_buffer,
    size_t der_extension_buffer_len,
    uint8_t** claim_oid_data,
    size_t* claim_oid_data_len)
{
    int result = mbedtls_x509_get_oid_value(
        der_extension_buffer,
        der_extension_buffer_len,
        cyres_claims_oid,
        cyres_claims_oid_size,
        claim_oid_data,
        claim_oid_data_len);
    return result ? OE_FAILURE : OE_OK;
}

static int mbedtls_sha256_hash(
    unsigned char* output,
    const unsigned char* input,
    const size_t input_size)
{
    int ret = 0;
    mbedtls_sha256_context sha256;

    mbedtls_sha256_init(&sha256);

    mbedtls_sha256_update(&sha256, input, input_size);

    mbedtls_sha256_finish(&sha256, output);

    mbedtls_sha256_free(&sha256);

    return ret;
}

static oe_result_t get_claims(
    mbedtls_x509_crt* cert,
    uint8_t* signer_id_buffer,
    size_t signed_id_buffer_size,
    uint8_t* unique_id_buffer,
    size_t unique_id_buffer_size,
    uint8_t* public_key_buffer,
    size_t public_key_buffer_size)
{
    uint8_t* claim_oid_data;
    size_t claim_oid_data_len;
    oe_result_t result = get_claim_oid_data(
        cert->v3_ext.p, cert->v3_ext.len, &claim_oid_data, &claim_oid_data_len);
    if (result != OE_OK || claim_oid_data == NULL)
    {
        goto Cleanup;
    }

    const uint8_t* value_buffer;
    size_t value_buffer_len;

    // CYRES_IDENTITY_MAP_AUTH

    RIOT_STATUS status = GetClaim(
        claim_oid_data,
        claim_oid_data_len,
        CYRES_IDENTITY_MAP_AUTH,
        &value_buffer,
        &value_buffer_len);
    if (status != RIOT_SUCCESS)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    int ret =
        mbedtls_sha256_hash(signer_id_buffer, value_buffer, value_buffer_len);
    if (ret)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    // CYRES_IDENTITY_MAP_FWID

    status = GetClaim(
        claim_oid_data,
        claim_oid_data_len,
        CYRES_IDENTITY_MAP_FWID,
        &value_buffer,
        &value_buffer_len);
    if (status != RIOT_SUCCESS)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    if (value_buffer_len != unique_id_buffer_size)
    {
        // TODO consider to disallow this branch
        int ret =
            mbedtls_sha256_hash(unique_id_buffer, value_buffer, value_buffer_len);
        if (ret)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }
    }
    else
    {
        memcpy(unique_id_buffer, value_buffer, value_buffer_len);
    }

    // CYRES_IDENTITY_MAP_PUBKEY

    if (public_key_buffer != NULL)
    {
        status = GetClaim(
            claim_oid_data,
            claim_oid_data_len,
            CYRES_IDENTITY_MAP_PUBKEY,
            &value_buffer,
            &value_buffer_len);
        if (status != RIOT_SUCCESS || value_buffer_len != public_key_buffer_size)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }

        memcpy(public_key_buffer, value_buffer, value_buffer_len);
    }

Cleanup:
    return result;
}

oe_result_t oe_parse_report_internal(
    mbedtls_x509_crt* chain,
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_OK;

    if (chain == NULL || 
        chain->next == NULL)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    oe_identity_t identity_local;
    oe_identity_t* pidentity = parsed_report ? 
        &parsed_report->identity : 
        &identity_local;

    result = get_claims(
        chain,
        pidentity->signer_id,
        sizeof(pidentity->signer_id),
        pidentity->unique_id,
        sizeof(pidentity->unique_id),
        NULL,
        0);
    if (result != OE_OK)
    {
        goto Cleanup;
    }

    result = OE_FAILURE;
    while (chain->next != NULL)
    {
        chain = chain->next;
        result = get_claims(
            chain,
            pidentity->device_signer_id,
            sizeof(pidentity->device_signer_id),
            pidentity->device_unique_id,
            sizeof(pidentity->device_unique_id),
            pidentity->device_public_key,
            sizeof(pidentity->device_public_key));
        if (result == OE_OK)
        {
            break;
        }
    }

    if (result != OE_OK)
    {
        goto Cleanup;
    }

    if (parsed_report)
    {
        parsed_report->size = sizeof(*parsed_report);
        parsed_report->type = OE_ENCLAVE_TYPE_TRUSTZONE;

        parsed_report->enclave_report_size = report_size;
        parsed_report->enclave_report = (uint8_t*)report;

        parsed_report->report_data_size = 0;
        parsed_report->report_data = NULL;

        parsed_report->identity.id_version = 0;
        parsed_report->identity.security_version = 0;

        parsed_report->identity.attributes = 0;
        // TODO: add support for OE_REPORT_ATTRIBUTES_*

        memset(
            parsed_report->identity.product_id,
            0,
            sizeof(parsed_report->identity.product_id));
    }

Cleanup:
    return result;
}

oe_result_t oe_parse_report(
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Out_ oe_report_t* parsed_report)
{
    oe_result_t result = OE_OK;

    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    int res = mbedtls_x509_crt_parse(&chain, report, report_size);
    if (res != 0)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    result = oe_parse_report_internal(
        &chain, report, report_size, parsed_report);
    if (result != OE_OK)
    {
        goto Cleanup;
    }

Cleanup:

    mbedtls_x509_crt_free(&chain);

    return result;
}

oe_result_t oe_get_target_info_v2(
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Outptr_ void** target_info_buffer,
    _Out_ size_t* target_info_size)
{
    /* Not yet supported */
    return OE_UNSUPPORTED;
}

oe_result_t oe_get_target_info_v1(
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Out_writes_bytes_(*target_info_size) void* target_info_buffer,
    _Inout_ size_t* target_info_size)
{
    return OE_UNSUPPORTED;
}

void oe_free_target_info(_In_ void* target_info_buffer)
{
    return;
}
