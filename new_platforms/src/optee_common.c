/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>

#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/asn1.h>
#include <mbedtls/oid.h>

#include <RiotStatus.h>
#include <RiotEcc.h>
#include <RiotCrypt.h>
#include <TcpsId.h>

#if !defined(_MSC_VER) || defined(OE_NO_SAL)
#include "sal_unsup.h"
#endif

// based on mbedtls x509_get_crt_ext
static int mbedtls_x509_get_oid_value(
    _In_reads_(der_extension_buffer_len) uint8_t* der_extension_buffer,
    _In_ size_t der_extension_buffer_len,
    _In_reads_(oid_size) const uint8_t* oid,
    _In_ size_t oid_size,
    _Outptr_ uint8_t** oid_data,
    _Out_ size_t* oid_data_size)
{
    int ret;
    size_t len;
    unsigned char** p = &der_extension_buffer;
    const unsigned char* end = der_extension_buffer + der_extension_buffer_len;
    const unsigned char *end_ext_data;
    unsigned char *end_ext_octet;

    *oid_data = NULL;
    *oid_data_size = 0;

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
        mbedtls_x509_buf extn_oid = { 0, 0, NULL };
        int is_critical = 0; /* DEFAULT FALSE */

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
    _In_reads_(der_extension_buffer_len) uint8_t* der_extension_buffer,
    _In_ size_t der_extension_buffer_len,
    _Outptr_ uint8_t** claim_oid_data,
    _Out_ size_t* claim_oid_data_len)
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
    _Out_ unsigned char output[32],
    _In_reads_(input_size) const unsigned char* input,
    _In_ const size_t input_size)
{
    int ret = 0;
    mbedtls_sha256_context sha256;

    mbedtls_sha256_init(&sha256);

    mbedtls_sha256_update(&sha256, input, input_size);

    mbedtls_sha256_finish(&sha256, output);

    mbedtls_sha256_free(&sha256);

    return ret;
}

// copy from mbedtls due to static linking
static int pk_get_pk_alg(
    unsigned char** p,
    const unsigned char* end,
    mbedtls_pk_type_t* pk_alg,
    mbedtls_asn1_buf* params)
{
    int ret;
    mbedtls_asn1_buf alg_oid;

    memset(params, 0, sizeof(mbedtls_asn1_buf));

    if ((ret = mbedtls_asn1_get_alg(p, end, &alg_oid, params)) != 0)
        return (MBEDTLS_ERR_PK_INVALID_ALG + ret);

    if (mbedtls_oid_get_pk_alg(&alg_oid, pk_alg) != 0)
        return (MBEDTLS_ERR_PK_UNKNOWN_PK_ALG);

    /*
     * No parameters with RSA (only for EC)
     */
    if (*pk_alg == MBEDTLS_PK_RSA &&
        ((params->tag != MBEDTLS_ASN1_NULL && params->tag != 0) ||
            params->len != 0))
    {
        return (MBEDTLS_ERR_PK_INVALID_ALG);
    }

    return (0);
}

static oe_result_t get_public_key_buffer(
    uint8_t* wrapper,
    size_t wrapperSize,
    uint8_t* public_key_buffer,
    size_t public_key_buffer_size)
{
    size_t len;
    int ret;
    oe_result_t result = OE_OK;
    const uint8_t* end = wrapper + wrapperSize;
    uint8_t* p = wrapper;
    if ((ret = mbedtls_asn1_get_tag(
        &p,
        end,
        &len,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }
    end = p + len;
    mbedtls_pk_type_t pk_alg;
    mbedtls_asn1_buf alg_params;

    if ((ret = pk_get_pk_alg(&p, end, &pk_alg, &alg_params)) != 0)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    if ((ret = mbedtls_asn1_get_bitstring_null(&p, end, &len)) != 0)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    if (len != public_key_buffer_size)
    {
        result = OE_FAILURE;
    }
    else
    {
        memcpy(public_key_buffer, p, len);
    }

Cleanup:
    return result;
}

static oe_result_t get_public_key(
    _Inout_ mbedtls_x509_crt* cert,
    _Out_writes_(public_key_buffer_size) uint8_t* public_key_buffer,
    _In_ size_t public_key_buffer_size)
{
    uint8_t* start = cert->subject_raw.p + cert->subject_raw.len;
    return get_public_key_buffer(
        start,
        cert->tbs.p + cert->tbs.len - start,
        public_key_buffer,
        public_key_buffer_size);
}

static oe_result_t get_claims(
    _Inout_ mbedtls_x509_crt* cert,
    _Out_writes_(signer_id_buffer_size) uint8_t* signer_id_buffer,
    _In_ size_t signer_id_buffer_size,
    _Out_writes_(unique_id_buffer_size) uint8_t* unique_id_buffer,
    _In_ size_t unique_id_buffer_size,
    _Out_writes_(product_id_buffer_size) uint8_t* product_id_buffer,
    _In_ size_t product_id_buffer_size,
    _Out_writes_(public_key_buffer_size) uint8_t* public_key_buffer,
    _In_ size_t public_key_buffer_size)
{
    uint8_t* claim_oid_data;
    size_t claim_oid_data_len;
    oe_result_t result;

    // Derive GUID based on subject common name for product_id
    {
        mbedtls_asn1_named_data* data = &cert->subject;
        while (data != NULL &&
            MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &data->oid) != 0)
        {
            data = data->next;
        }
        if (data == NULL)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }
        unsigned char guid[32];
        int ret = mbedtls_sha256_hash(
            guid, cert->subject.val.p, cert->subject.val.len);
        if (ret)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }

        // TODO assert
        if (product_id_buffer_size * 2 != sizeof(guid))
        {
            result = OE_FAILURE;
            goto Cleanup;
        }
        for (size_t i = 0; i < product_id_buffer_size; i++)
        {
            product_id_buffer[i] = guid[2 * i] ^ guid[2 * i + 1];
        }
    }

    result = get_claim_oid_data(
        cert->v3_ext.p, cert->v3_ext.len, &claim_oid_data, &claim_oid_data_len);
    if (result != OE_OK)
    {
        goto Cleanup;
    }

    if (claim_oid_data == NULL)
    {
        result =
            get_public_key(cert, public_key_buffer, public_key_buffer_size);
        if (result == OE_OK)
        {
            memset(signer_id_buffer, 0, signer_id_buffer_size);
            memset(unique_id_buffer, 0, unique_id_buffer_size);
        }
        goto Cleanup;
    }

    const uint8_t* value_buffer;
    size_t value_buffer_len;

    if (claim_oid_data_len > UINT32_MAX)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    // CYRES_IDENTITY_MAP_AUTH

    RIOT_STATUS status = GetClaim(
        claim_oid_data,
        (uint32_t)claim_oid_data_len,
        CYRES_IDENTITY_MAP_AUTH,
        &value_buffer,
        &value_buffer_len);
    if (status != RIOT_SUCCESS || value_buffer == NULL)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    // TODO assert
    if (signer_id_buffer_size != 32)
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
        (uint32_t)claim_oid_data_len,
        CYRES_IDENTITY_MAP_FWID,
        &value_buffer,
        &value_buffer_len);
    if (status != RIOT_SUCCESS || value_buffer == NULL)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    if (value_buffer_len != unique_id_buffer_size)
    {
        // TODO consider to disallow this branch
        ret = mbedtls_sha256_hash(
            unique_id_buffer, value_buffer, value_buffer_len);
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

    status = GetClaim(
        claim_oid_data,
        (uint32_t)claim_oid_data_len,
        CYRES_IDENTITY_MAP_PUBKEY,
        &value_buffer,
        &value_buffer_len);
    if (status == RIOT_SUCCESS && value_buffer != NULL) // TODO should we enforce presence of this claim?
    {
        if (value_buffer_len != public_key_buffer_size)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }
        else
        {
            memcpy(public_key_buffer, value_buffer, value_buffer_len);
        }
    }

Cleanup:
    return result;
}

oe_result_t oe_parse_report_internal(
    _Inout_ mbedtls_x509_crt* chain,
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Out_ oe_report_t* parsed_report)
{
    oe_result_t result = OE_OK;
    mbedtls_x509_crt localChain;

    oe_identity_t identity_local = { 0 };
    oe_identity_t* pidentity =
        parsed_report ? &parsed_report->identity : &identity_local;
    pidentity->caller = NULL;

    // Parse the CyRes X.509 certificate chain
    mbedtls_x509_crt_init(&localChain);
    int res = mbedtls_x509_crt_parse(&localChain, report, report_size);
    if (res != 0)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    // Count the identities
    size_t cert_count = 0;
    {
        mbedtls_x509_crt* cert = &localChain;
        while (cert)
        {
            cert_count++;
            cert = cert->next;
        }
    }

    if (cert_count == 0)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    // Allocate buffer for additional identities
    if (cert_count > 1)
    {
        oe_identity_t* additionalIdentities =
            (oe_identity_t*)malloc((cert_count - 1) * sizeof(oe_identity_t));
        if (additionalIdentities == NULL)
        {
            result = OE_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Construct the identity chain
        {
            oe_identity_t* identity = pidentity;
            oe_identity_t* next = additionalIdentities;

            for (size_t i = 0; i < cert_count - 1; i++)
            {
                identity->caller = next;
                identity = next;
                next++;
            }
            identity->caller = NULL;
        }
    }

    // Extract the claims
    {
        mbedtls_x509_crt* cert = &localChain;
        oe_identity_t* identity = pidentity;
        while (cert != NULL)
        {
            result = get_claims(
                cert,
                identity->signer_id,
                sizeof(identity->signer_id),
                identity->unique_id,
                sizeof(identity->unique_id),
                identity->product_id,
                sizeof(identity->product_id),
                identity->public_key,
                sizeof(identity->public_key));
            if (result != OE_OK)
            {
                goto Cleanup;
            }

            identity->id_version = 0;
            identity->security_version = 0;

            identity->attributes = 0;
            // TODO: add support for OE_REPORT_ATTRIBUTES_*

            if (cert->next == NULL)
            {
                identity->caller = NULL;
            }
            identity = identity->caller;
            cert = cert->next;
        }
    }

    if (parsed_report)
    {
        parsed_report->size = sizeof(*parsed_report);
        parsed_report->type = OE_ENCLAVE_TYPE_TRUSTZONE;

        parsed_report->enclave_report_size = report_size;
        parsed_report->enclave_report = (uint8_t*)report;

        parsed_report->report_data_size = 0;
        parsed_report->report_data = NULL;
    }

    if (chain != NULL)
    {
        memcpy(chain, &localChain, sizeof(mbedtls_x509_crt));
    }

    if (parsed_report != NULL)
    {
        pidentity = NULL;
    }

Cleanup:

    if (!(result == OE_OK && chain != NULL))
    {
        mbedtls_x509_crt_free(&localChain);
    }

    if (pidentity != NULL && pidentity->caller != NULL)
    {
        free(pidentity->caller);
    }

    return result;
}

oe_result_t oe_parse_report(
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Out_ oe_report_t* parsed_report)
{
    oe_result_t result = OE_OK;

    result = oe_parse_report_internal(NULL, report, report_size, parsed_report);
    if (result != OE_OK)
    {
        goto Cleanup;
    }

Cleanup:

    return result;
}

void oe_free_parsed_report(_In_ oe_report_t* parsed_report)
{
    if (parsed_report != NULL)
    {
        if (parsed_report->identity.caller != NULL)
        {
            free(parsed_report->identity.caller);
            parsed_report->identity.caller = NULL;
        }
    }
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
