// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "quote.h"
#include <openenclave/internal/cert.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/sha.h>
#include <openenclave/internal/utils.h>
#include "common.h"
#include "revocation.h"
<<<<<<< HEAD
#include "qeidentity.h"

=======
#define  OE_USE_LIBSGX 1
>>>>>>> b7ab80e... added QE ID support
#ifdef OE_USE_LIBSGX

// Public key of Intel's root certificate.
static const char* g_expected_root_certificate_key =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiO\n"
    "SLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlA==\n"
    "-----END PUBLIC KEY-----\n";

// The mrsigner value of Intel's Production quoting enclave.
static const uint8_t g_qe_mrsigner[32] = {
    0x8c, 0x4f, 0x57, 0x75, 0xd7, 0x96, 0x50, 0x3e, 0x96, 0x13, 0x7f,
    0x77, 0xc6, 0x8a, 0x82, 0x9a, 0x00, 0x56, 0xac, 0x8d, 0xed, 0x70,
    0x14, 0x0b, 0x08, 0x1b, 0x09, 0x44, 0x90, 0xc5, 0x7b, 0xff};

// The isvprodid value of Intel's Production quoting enclave.
static const uint32_t g_qe_isvprodid = 1;

// The isvsvn value of Intel's Production quoting enclave.
static const uint32_t g_qeisvsvn = 1;

OE_INLINE uint16_t ReadUint16(const uint8_t* p)
{
    return p[0] | (p[1] << 8);
}

OE_INLINE uint32_t ReadUint32(const uint8_t* p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static oe_result_t _parse_quote(
    const uint8_t* quote,
    size_t quote_size,
    sgx_quote_t** sgx_quote,
    sgx_quote_auth_data_t** quote_auth_data,
    sgx_qe_auth_data_t* qe_auth_data,
    sgx_qe_cert_data_t* qe_cert_data)
{
    oe_result_t result = OE_UNEXPECTED;

    const uint8_t* p = quote;
    const uint8_t* const quote_end = quote + quote_size;

    if (quote_end < p)
    {
        // Pointer wrapped around.
        OE_RAISE(OE_REPORT_PARSE_ERROR);
    }

    *sgx_quote = NULL;

    *sgx_quote = (sgx_quote_t*)p;
    p += sizeof(sgx_quote_t);
    if (p > quote_end)
        OE_RAISE(OE_REPORT_PARSE_ERROR);

    if (p + (*sgx_quote)->signature_len != quote_end)
        OE_RAISE(OE_REPORT_PARSE_ERROR);

    *quote_auth_data = (sgx_quote_auth_data_t*)(*sgx_quote)->signature;
    p += sizeof(sgx_quote_auth_data_t);

    qe_auth_data->size = ReadUint16(p);
    p += 2;
    qe_auth_data->data = (uint8_t*)p;
    p += qe_auth_data->size;

    if (p > quote_end)
        OE_RAISE(OE_REPORT_PARSE_ERROR);

    qe_cert_data->type = ReadUint16(p);
    p += 2;
    qe_cert_data->size = ReadUint32(p);
    p += 4;
    qe_cert_data->data = (uint8_t*)p;
    p += qe_cert_data->size;

    if (p != quote_end)
        OE_RAISE(OE_REPORT_PARSE_ERROR);

    result = OE_OK;
done:
    return result;
}

static oe_result_t _read_public_key(
    sgx_ecdsa256_key_t* key,
    oe_ec_public_key_t* public_key)
{
    return oe_ec_public_key_from_coordinates(
        public_key,
        OE_EC_TYPE_SECP256R1,
        key->x,
        sizeof(key->x),
        key->y,
        sizeof(key->y));
}

typedef struct _oe_parsed_qe_identity_info
{
    uint32_t version;
    oe_datetime_t issue_date;
    oe_datetime_t next_update;

    uint32_t miscselect;        // The MISCSELECT that must be set
    uint32_t miscselectMask;    // Mask of MISCSELECT to enforce

    // TODO: find out what attributes are!

    sgx_attributes_t attributes; // ATTRIBUTES Flags Field 
    uint32_t         attributesMask; // string

    uint8_t mrsigner[OE_SHA256_SIZE]; // MRSIGNER of the enclave

    uint16_t isvprodid; // ISV assigned Product ID
    uint16_t isvsvn; // ISV assigned SVN

    uint8_t signature[64];
} oe_parsed_qe_identity_info_t;


oe_result_t oe_parse_qe_identity_info_json(
    const uint8_t* info_json,
    size_t info_json_size,
    oe_parsed_qe_identity_info_t* parsed_info)
{
    oe_result_t result = OE_OK;
    return result;
}

// uint32_t qe_id_info_size;   // size of qe identity
// char* qe_id_info;           // qe identity info structure (JSON)
// uint32_t issuer_chain_size; // size of issuer chain for qe identity info
// char* issuer_chain;     

oe_result_t oe_enforce_qe_identity()
{
    oe_result_t result = OE_FAILURE;
    sgx_qe_identity_info_t *identity = NULL;
    oe_parsed_qe_identity_info_t parsed_info = {0};
    oe_cert_chain_t pck_cert_chain = {0};
    const uint8_t* pem_pck_certificate = NULL;
    size_t pem_pck_certificate_size = 0;

    printf("===========qe_identity ========\n");
    OE_TRACE_INFO("Calling %s\n", __PRETTY_FUNCTION__);

    // fetch qe identity information
    _get_qe_identity_info(&identity);

    pem_pck_certificate = identity.issuer_chain;
    pem_pck_certificate_size = identity.issuer_chain_size;


    // validate the cert chain.
    OE_CHECK(
            oe_cert_chain_read_pem(
                &pck_cert_chain,
                pem_pck_certificate,
                pem_pck_certificate_size));

    // verify qe identity signature
    printf("qe_identity.issuer_chain:[%s]\n", test->issuer_chain);
    OE_CHECK(oe_verify_tcb_signature(
                identity.qe_id_info,
                identity.qe_id_info_size,
                (sgx_ecdsa256_signature_t*)identity.signature,
                &tcb_issuer_chain));

    // parse identity info json blob
    printf("qe_identity.qe_id_info:[%s]\n", test->qe_id_info);
    OE_CHECK(oe_parse_qe_identity_info_json(
                                    identity->qe_id_info,
                                    identity->qe_id_info_size,
                                    &parsed_info));    

    // check identity

    _free_qe_identity_info(identity);
    printf("===========qe_identity ========\n");

    result = OE_OK;
    return result;
}


static oe_result_t _ecdsa_verify(
    oe_ec_public_key_t* public_key,
    void* data,
    size_t data_size,
    sgx_ecdsa256_signature_t* signature)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sha256_context_t sha256_ctx = {0};
    OE_SHA256 sha256 = {0};
    uint8_t asn1_signature[256];
    size_t asn1_signature_size = sizeof(asn1_signature);

    OE_CHECK(oe_sha256_init(&sha256_ctx));
    OE_CHECK(oe_sha256_update(&sha256_ctx, data, data_size));
    OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

    OE_CHECK(
        oe_ecdsa_signature_write_der(
            asn1_signature,
            &asn1_signature_size,
            signature->r,
            sizeof(signature->r),
            signature->s,
            sizeof(signature->s)));

    OE_CHECK(
        oe_ec_public_key_verify(
            public_key,
            OE_HASH_TYPE_SHA256,
            (uint8_t*)&sha256,
            sizeof(sha256),
            asn1_signature,
            asn1_signature_size));

    result = OE_OK;
done:
    return result;
}

oe_result_t VerifyQuoteImpl(
    const uint8_t* quote,
    size_t quote_size,
    const uint8_t* pem_pck_certificate,
    size_t pem_pck_certificate_size,
    const uint8_t* pck_crl,
    size_t pck_crl_size,
    const uint8_t* tcb_info_json,
    size_t tcb_info_json_size)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_quote_t* sgx_quote = NULL;
    sgx_quote_auth_data_t* quote_auth_data = NULL;
    sgx_qe_auth_data_t qe_auth_data = {0};
    sgx_qe_cert_data_t qe_cert_data = {0};
    oe_cert_chain_t pck_cert_chain = {0};
    oe_sha256_context_t sha256_ctx = {0};
    OE_SHA256 sha256 = {0};
    oe_ec_public_key_t attestation_key = {0};
    oe_cert_t leaf_cert = {0};
    oe_cert_t root_cert = {0};
    oe_cert_t intermediate_cert = {0};
    oe_ec_public_key_t leaf_public_key = {0};
    oe_ec_public_key_t root_public_key = {0};
    oe_ec_public_key_t expected_root_public_key = {0};
    bool key_equal = false;

    OE_CHECK(
        _parse_quote(
            quote,
            quote_size,
            &sgx_quote,
            &quote_auth_data,
            &qe_auth_data,
            &qe_cert_data));

    if (sgx_quote->version != OE_SGX_QUOTE_VERSION)
    {
        OE_RAISE(OE_VERIFY_FAILED);
    }

    // The certificate provided in the quote is preferred.
    if (qe_cert_data.type == OE_SGX_PCK_ID_PCK_CERT_CHAIN)
    {
        if (qe_cert_data.size == 0)
            OE_RAISE(OE_FAILURE);
        pem_pck_certificate = qe_cert_data.data;
        pem_pck_certificate_size = qe_cert_data.size;
    }
    else
    {
        OE_RAISE(OE_MISSING_CERTIFICATE_CHAIN);
    }

    if (pem_pck_certificate == NULL)
        OE_RAISE(OE_MISSING_CERTIFICATE_CHAIN);

    // PckCertificate Chain validations.
    {
        // Read and validate the chain.
        OE_CHECK(
            oe_cert_chain_read_pem(
                &pck_cert_chain,
                pem_pck_certificate,
                pem_pck_certificate_size));

        // Fetch leaf and root certificates.
        OE_CHECK(oe_cert_chain_get_leaf_cert(&pck_cert_chain, &leaf_cert));
        OE_CHECK(oe_cert_chain_get_root_cert(&pck_cert_chain, &root_cert));
        OE_CHECK(
            oe_cert_chain_get_cert(&pck_cert_chain, 1, &intermediate_cert));

        OE_CHECK(oe_cert_get_ec_public_key(&leaf_cert, &leaf_public_key));
        OE_CHECK(oe_cert_get_ec_public_key(&root_cert, &root_public_key));

        // Ensure that the root certificate matches root of trust.
        OE_CHECK(
            oe_ec_public_key_read_pem(
                &expected_root_public_key,
                (const uint8_t*)g_expected_root_certificate_key,
                strlen(g_expected_root_certificate_key) + 1));

        OE_CHECK(
            oe_ec_public_key_equal(
                &root_public_key, &expected_root_public_key, &key_equal));
        if (!key_equal)
            OE_RAISE(OE_VERIFY_FAILED);

        OE_CHECK(
            oe_enforce_revocation(
                &leaf_cert, &intermediate_cert, &pck_cert_chain));
    }

    // Quote validations.
    {
        // Verify SHA256 ECDSA (qe_report_body_signature, qe_report_body,
        // PckCertificate.pub_key)
        OE_CHECK(
            _ecdsa_verify(
                &leaf_public_key,
                &quote_auth_data->qe_report_body,
                sizeof(quote_auth_data->qe_report_body),
                &quote_auth_data->qe_report_body_signature));

        // Assert SHA256 (attestation_key + qe_auth_data.data) ==
        // qe_report_body.report_data[0..32]
        OE_CHECK(oe_sha256_init(&sha256_ctx));
        OE_CHECK(
            oe_sha256_update(
                &sha256_ctx,
                (const uint8_t*)&quote_auth_data->attestation_key,
                sizeof(quote_auth_data->attestation_key)));
        if (qe_auth_data.size > 0)
        {
            OE_CHECK(
                oe_sha256_update(
                    &sha256_ctx, qe_auth_data.data, qe_auth_data.size));
        }
        OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

        if (!oe_constant_time_mem_equal(
                &sha256,
                &quote_auth_data->qe_report_body.report_data,
                sizeof(sha256)))
            OE_RAISE(OE_VERIFY_FAILED);

        // Verify SHA256 ECDSA (attestation_key, SGX_QUOTE_SIGNED_DATA,
        // signature)
        OE_CHECK(
            _read_public_key(
                &quote_auth_data->attestation_key, &attestation_key));

        OE_CHECK(
            _ecdsa_verify(
                &attestation_key,
                sgx_quote,
                SGX_QUOTE_SIGNED_DATA_SIZE,
                &quote_auth_data->signature));
    }

    // Quoting Enclave validations.
    {
        // Assert that the qe report's MRSIGNER matches Intel's quoting
        // enclave's mrsigner.
        if (!oe_constant_time_mem_equal(
                quote_auth_data->qe_report_body.mrsigner,
                g_qe_mrsigner,
                sizeof(g_qe_mrsigner)))
            OE_RAISE(OE_VERIFY_FAILED);

        if (quote_auth_data->qe_report_body.isvprodid != g_qe_isvprodid)
            OE_RAISE(OE_VERIFY_FAILED);

        if (quote_auth_data->qe_report_body.isvsvn != g_qeisvsvn)
            OE_RAISE(OE_VERIFY_FAILED);

        // Ensure that the QE is not a debug supporting enclave.
        if (quote_auth_data->qe_report_body.attributes.flags & SGX_FLAGS_DEBUG)
            OE_RAISE(OE_VERIFY_FAILED);

<<<<<<< HEAD
=======
        // enforce the QE revocation certificate
        OE_CHECK(
            oe_enforce_qe_revocation(
                &leaf_cert, &intermediate_cert, &pck_cert_chain));

>>>>>>> b7ab80e... added QE ID support
        // check QE Identify
        OE_CHECK(oe_enforce_qe_identity());

            // version
            // issueDate
            //nextUpdate
            //miscselect
            //attributes
            //attributesMask
            //mrsigner
            //isvprodif
            //isvsvn
            //signature validation
    }
    result = OE_OK;

done:
    oe_ec_public_key_free(&leaf_public_key);
    oe_ec_public_key_free(&root_public_key);
    oe_ec_public_key_free(&expected_root_public_key);
    oe_ec_public_key_free(&attestation_key);
    oe_cert_free(&leaf_cert);
    oe_cert_free(&root_cert);
    oe_cert_free(&intermediate_cert);
    oe_cert_chain_free(&pck_cert_chain);
    return result;
}

#else

oe_result_t VerifyQuoteImpl(
    const uint8_t* enc_quote,
    size_t quote_size,
    const uint8_t* enc_pem_pck_certificate,
    size_t pem_pck_certificate_size,
    const uint8_t* enc_pck_crl,
    size_t enc_pck_crl_size,
    const uint8_t* enc_tcb_info_json,
    size_t enc_tcb_info_json_size)
{
    OE_UNUSED(enc_quote);
    OE_UNUSED(quote_size);
    OE_UNUSED(enc_pem_pck_certificate);
    OE_UNUSED(pem_pck_certificate_size);
    OE_UNUSED(enc_pck_crl);
    OE_UNUSED(enc_pck_crl_size);
    OE_UNUSED(enc_tcb_info_json);
    OE_UNUSED(enc_tcb_info_json_size);

    return OE_UNSUPPORTED;
}



/**
 * type = tcbInfo
 * Schema:
 * {
 *    "version" : integer,
 *    "issueDate" : string,
 *    "fmspc" : "hex string"
 *    "tcbLevels" : [ objects of type tcbLevel ]
 * }
 */
/*
static oe_result_t _read_qe_identity_info(
    const uint8_t** itr,
    const uint8_t* end,
    oe_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_info)
{
    oe_result_t result = OE_TCB_INFO_PARSE_ERROR;
    uint64_t value = 0;
    const uint8_t* date_str = NULL;
    size_t date_size = 0;

    parsed_info->tcb_info_start = *itr;
    OE_CHECK(_read('{', itr, end));

    OE_TRACE_INFO("Reading version\n");
    OE_CHECK(_read_property_name_and_colon("version", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    parsed_info->version = (uint32_t)value;
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading issueDate\n");
    OE_CHECK(_read_property_name_and_colon("issueDate", itr, end));
    OE_CHECK(_read_string(itr, end, &date_str, &date_size));
    if (oe_datetime_from_string(
            (const char*)date_str, date_size, &parsed_info->issue_date) !=
        OE_OK)
        OE_RAISE(OE_TCB_INFO_PARSE_ERROR);
    OE_CHECK(_read(',', itr, end));

    // nextUpdate is treated as an optional property.
    OE_TRACE_INFO("Reading nextUpdate\n");
    if (_read_property_name_and_colon("nextUpdate", itr, end) == OE_OK)
    {
        OE_CHECK(_read_string(itr, end, &date_str, &date_size));
        if (oe_datetime_from_string(
                (const char*)date_str, date_size, &parsed_info->next_update) !=
            OE_OK)
            OE_RAISE(OE_TCB_INFO_PARSE_ERROR);
        OE_CHECK(_read(',', itr, end));
    }
    else
    {
        memset(&parsed_info->next_update, 0, sizeof(parsed_info->next_update));
    }

    OE_TRACE_INFO("Reading fmspc\n");
    OE_CHECK(_read_property_name_and_colon("fmspc", itr, end));
    OE_CHECK(
        _read_hex_string(
            itr, end, parsed_info->fmspc, sizeof(parsed_info->fmspc)));
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading tcbLevels\n");
    OE_CHECK(_read_property_name_and_colon("tcbLevels", itr, end));
    OE_CHECK(_read('[', itr, end));
    while (*itr < end)
    {
        OE_CHECK(_read_tcb_level(itr, end, platform_tcb_level, parsed_info));
        // Read end of array or comma separator.
        if (*itr < end && **itr == ']')
            break;

        OE_CHECK(_read(',', itr, end));
    }
    OE_CHECK(_read(']', itr, end));

    // itr is expected to point to the '}' that denotes the end of the tcb
    // object. The signature is generated over the entire object including the
    // '}'.
    parsed_info->tcb_info_size = *itr - parsed_info->tcb_info_start + 1;
    OE_CHECK(_read('}', itr, end));

    result = OE_OK;
done:
    return result;
}
*/

#endif
