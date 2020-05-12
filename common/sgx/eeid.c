// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openenclave/bits/eeid.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/types.h>
#include <openenclave/internal/utils.h>

#include "sgxmeasure.h"

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#include "../../enclave/crypto/key.h"
#include "../../enclave/crypto/rsa.h"
#else
#include <openenclave/host.h>
#include <openssl/opensslv.h>
#include <openssl/rsa.h>
#include "../../host/crypto/openssl/key.h"
#include "../../host/crypto/openssl/rsa.h"
#endif

static oe_result_t serialize_element(
    const char* name,
    char** position,
    size_t* remaining,
    const uint8_t* element,
    size_t element_size)
{
    size_t name_sz = strlen(name);

    if (*remaining < 2 * element_size + 1 + name_sz + 1)
        return OE_BUFFER_TOO_SMALL;

    snprintf(*position, *remaining, "%s=", name);
    *position += name_sz + 1;
    *remaining -= name_sz + 1;

    oe_hex_string(*position, *remaining, element, element_size);
    *position += 2 * element_size;
    **position = '\n';
    *position += 1;
    *remaining -= 2 * element_size + 1;

    return OE_OK;
}

static oe_result_t deserialize_element(
    const char** position,
    size_t* remaining,
    uint8_t* element,
    size_t element_size)
{
    // Skip name
    while (**position != ' ')
    {
        *position += 1;
        *remaining -= 1;
    }
    *position += 1;
    *remaining -= 1;

    if (*remaining < 2 * element_size + 2)
        return OE_OUT_OF_BOUNDS;

    for (size_t i = 0; i < element_size; i++)
    {
        unsigned digit;
        if (sscanf(*position, "%02x", &digit) != 1)
            return OE_INVALID_PARAMETER;
        element[i] = (uint8_t)digit;
        *position += 2;
        *remaining -= 2;
    }

    if (**position != '\n')
        return OE_INVALID_PARAMETER;

    *position += 1;
    *remaining -= 1;

    return OE_OK;
}

// Note: this needs to be updated when oe_eeid_t changes.
oe_result_t oe_serialize_eeid(const oe_eeid_t* eeid, char* buf, size_t buf_size)
{
    oe_result_t result;

    if (!eeid || !buf || !buf_size)
        return OE_INVALID_PARAMETER;

    char** position = &buf;
    size_t remaining = buf_size;

    OE_CHECK(serialize_element(
        "H",
        position,
        &remaining,
        (uint8_t*)eeid->hash_state.H,
        sizeof(eeid->hash_state.H)));
    OE_CHECK(serialize_element(
        "N",
        position,
        &remaining,
        (uint8_t*)eeid->hash_state.N,
        sizeof(eeid->hash_state.N)));
    OE_CHECK(serialize_element(
        "signature_size",
        position,
        &remaining,
        (uint8_t*)&eeid->signature_size,
        sizeof(eeid->signature_size)));
    OE_CHECK(serialize_element(
        "signature",
        position,
        &remaining,
        eeid->signature,
        eeid->signature_size));
    OE_CHECK(serialize_element(
        "size_settings",
        position,
        &remaining,
        (uint8_t*)&eeid->size_settings,
        sizeof(eeid->size_settings)));
    OE_CHECK(serialize_element(
        "data_size",
        position,
        &remaining,
        (uint8_t*)&eeid->data_size,
        sizeof(eeid->data_size)));
    OE_CHECK(serialize_element(
        "vaddr",
        position,
        &remaining,
        (uint8_t*)&eeid->vaddr,
        sizeof(eeid->vaddr)));
    OE_CHECK(serialize_element(
        "entry_point",
        position,
        &remaining,
        (uint8_t*)&eeid->entry_point,
        sizeof(eeid->entry_point)));
    OE_CHECK(serialize_element(
        "data", position, &remaining, (uint8_t*)eeid->data, eeid->data_size));

    **position = '\0';

done:
    return OE_OK;
}

// Note: this needs to be updated when oe_eeid_t changes.
oe_result_t oe_deserialize_eeid(
    const char* buf,
    size_t buf_size,
    oe_eeid_t* eeid)
{
    oe_result_t result;

    if (!buf || !buf_size || !eeid)
        return OE_INVALID_PARAMETER;

    const char** position = &buf;
    size_t remaining = buf_size;

    memset(eeid, 0, sizeof(oe_eeid_t));

    OE_CHECK(deserialize_element(
        position,
        &remaining,
        (uint8_t*)eeid->hash_state.H,
        sizeof(eeid->hash_state.H)));
    OE_CHECK(deserialize_element(
        position,
        &remaining,
        (uint8_t*)eeid->hash_state.N,
        sizeof(eeid->hash_state.N)));
    OE_CHECK(deserialize_element(
        position,
        &remaining,
        (uint8_t*)&eeid->signature_size,
        sizeof(eeid->signature_size)));
    OE_CHECK(deserialize_element(
        position, &remaining, eeid->signature, eeid->signature_size));
    OE_CHECK(deserialize_element(
        position,
        &remaining,
        (uint8_t*)&eeid->size_settings,
        sizeof(eeid->size_settings)));
    OE_CHECK(deserialize_element(
        position,
        &remaining,
        (uint8_t*)&eeid->data_size,
        sizeof(eeid->data_size)));
    OE_CHECK(deserialize_element(
        position, &remaining, (uint8_t*)&eeid->vaddr, sizeof(eeid->vaddr)));
    OE_CHECK(deserialize_element(
        position,
        &remaining,
        (uint8_t*)&eeid->entry_point,
        sizeof(eeid->entry_point)));
    OE_CHECK(deserialize_element(
        position, &remaining, (uint8_t*)eeid->data, eeid->data_size));

done:
    return OE_OK;
}

oe_result_t oe_remeasure_memory_pages(
    const oe_eeid_t* eeid,
    struct _OE_SHA256* computed_enclave_hash,
    bool with_eeid_pages)
{
    oe_result_t result;
    oe_sha256_context_t hctx;
    oe_sha256_restore(&hctx, eeid->hash_state.H, eeid->hash_state.N);

    uint64_t base = 0x0ab0c0d0e0f;
    oe_page_t blank_pg, stack_pg, tcs_pg;
    memset(&blank_pg, 0, sizeof(blank_pg));
    memset(&stack_pg, 0xcc, sizeof(stack_pg));

#define ADD_PAGE(PG, T)                                      \
    {                                                        \
        OE_CHECK(oe_sgx_measure_load_enclave_data(           \
            &hctx,                                           \
            base,                                            \
            base + vaddr,                                    \
            (uint64_t)&PG,                                   \
            SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W, \
            T));                                             \
        vaddr += OE_PAGE_SIZE;                               \
    }

    uint64_t vaddr = eeid->vaddr;

    // This is where we replay the addition of memory pages, both, for
    // verification of the extended image hash (with_eeid_pages=true) and the
    // base image hash, for which there are no EEID pages, but one TCS page (or
    // more if we decide to support arbitrary base image properties).
    if (with_eeid_pages)
    {
        oe_page_t fst_page;
        *((uint64_t*)fst_page.data) = OE_EEID_MAGIC;
        // A non-eeid enclave would either segfault (if there are no heap pages)
        // or see a 0 (the default heap page content).
        size_t num_bytes = sizeof(oe_eeid_t) + eeid->data_size;
        size_t num_pages =
            num_bytes / OE_PAGE_SIZE + (num_bytes % OE_PAGE_SIZE) ? 1 : 0;
        memcpy(fst_page.data + sizeof(uint64_t), eeid, num_bytes);
        for (size_t i = 0; i < num_pages; i++)
            ADD_PAGE(fst_page + i * OE_PAGE_SIZE, false);
    }

    for (size_t i = 0; i < eeid->size_settings.num_heap_pages; i++)
        ADD_PAGE(blank_pg, false);

    for (size_t i = 0; i < eeid->size_settings.num_tcs; i++)
    {
        vaddr += OE_PAGE_SIZE; /* guard page */

        for (size_t i = 0; i < eeid->size_settings.num_stack_pages; i++)
            ADD_PAGE(stack_pg, true);

        vaddr += OE_PAGE_SIZE; /* guard page */

        sgx_tcs_t* tcs;
        memset(&tcs_pg, 0, sizeof(tcs_pg));
        tcs = (sgx_tcs_t*)&tcs_pg;
        tcs->flags = 0;
        tcs->ossa = vaddr + OE_PAGE_SIZE;
        tcs->cssa = 0;
        tcs->nssa = 2;
        tcs->oentry = eeid->entry_point;
        tcs->fsbase = vaddr + (5 * OE_PAGE_SIZE);
        tcs->gsbase = tcs->fsbase;
        tcs->fslimit = 0xFFFFFFFF;
        tcs->gslimit = 0xFFFFFFFF;

        OE_CHECK(oe_sgx_measure_load_enclave_data(
            &hctx,
            base,
            base + vaddr,
            (uint64_t)&tcs_pg,
            SGX_SECINFO_TCS,
            true));

        vaddr += OE_PAGE_SIZE;

        for (size_t i = 0; i < 2; i++)
            ADD_PAGE(blank_pg, true);
        vaddr += OE_PAGE_SIZE; // guard
        for (size_t i = 0; i < 2; i++)
            ADD_PAGE(blank_pg, true);
    }

    oe_sha256_final(&hctx, computed_enclave_hash);

done:
    return OE_OK;
}

static bool is_zero(const uint8_t* buf, size_t sz)
{
    while (sz != 0)
        if (buf[--sz] != 0)
            return false;
    return true;
}

static size_t _serialized_eeid_size(const oe_eeid_t* eeid)
{
    return 2 * (sizeof(oe_eeid_t) + eeid->data_size) + 8 + 1;
}

static oe_result_t verify_base_image_signature(const sgx_sigstruct_t* sigstruct)
{
    oe_result_t result = OE_UNEXPECTED;
    unsigned char buf[sizeof(sgx_sigstruct_t)];
    size_t n = 0;

    OE_CHECK(oe_memcpy_s(
        buf,
        sizeof(buf),
        sgx_sigstruct_header(sigstruct),
        sgx_sigstruct_header_size()));
    n += sgx_sigstruct_header_size();
    OE_CHECK(oe_memcpy_s(
        &buf[n],
        sizeof(buf) - n,
        sgx_sigstruct_body(sigstruct),
        sgx_sigstruct_body_size()));
    n += sgx_sigstruct_body_size();

    OE_SHA256 msg_hsh;
    oe_sha256_context_t context;

    oe_sha256_init(&context);
    oe_sha256_update(&context, buf, n);
    oe_sha256_final(&context, &msg_hsh);

    uint8_t reversed_modulus[OE_KEY_SIZE];
    for (size_t i = 0; i < OE_KEY_SIZE; i++)
        reversed_modulus[i] = sigstruct->modulus[OE_KEY_SIZE - 1 - i];

    uint8_t reversed_exponent[OE_KEY_SIZE];
    for (size_t i = 0; i < OE_EXPONENT_SIZE; i++)
        reversed_exponent[i] = sigstruct->exponent[OE_EXPONENT_SIZE - 1 - i];

    uint8_t reversed_signature[OE_KEY_SIZE];
    for (size_t i = 0; i < OE_KEY_SIZE; i++)
        reversed_signature[i] = sigstruct->signature[OE_KEY_SIZE - 1 - i];

    oe_rsa_public_key_t pk;
#ifdef OE_BUILD_ENCLAVE
    mbedtls_pk_context pkctx;
    mbedtls_pk_init(&pkctx);
    const mbedtls_pk_info_t* info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
    mbedtls_pk_setup(&pkctx, info);

    mbedtls_rsa_context* rsa_ctx = mbedtls_pk_rsa(pkctx);
    mbedtls_rsa_init(rsa_ctx, 0, 0);
    mbedtls_rsa_import_raw(
        rsa_ctx,
        reversed_modulus,
        OE_KEY_SIZE, // N
        NULL,
        0,
        NULL,
        0,
        NULL,
        0, // P Q D
        reversed_exponent,
        OE_EXPONENT_SIZE);
    if (mbedtls_rsa_check_pubkey(rsa_ctx) != 0)
        OE_RAISE(OE_INVALID_PARAMETER);
    mbedtls_pk_context* ikey = &pkctx;
#else
#if OPENSSL_VERSION_NUMBER < 0x1010100fL
#error OpenSSL 1.0.2 not supported
#endif
    BIGNUM* rm = BN_bin2bn(reversed_modulus, OE_KEY_SIZE, 0);
    BIGNUM* re = BN_bin2bn(reversed_exponent, OE_EXPONENT_SIZE, 0);
    RSA* rsa = RSA_new();
    RSA_set0_key(rsa, rm, re, NULL);
    EVP_PKEY* ikey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(ikey, rsa);
#endif
    oe_rsa_public_key_init(&pk, ikey);

    OE_CHECK(oe_rsa_public_key_verify(
        &pk,
        OE_HASH_TYPE_SHA256,
        msg_hsh.buf,
        sizeof(msg_hsh.buf),
        reversed_signature,
        OE_KEY_SIZE));

    oe_rsa_public_key_free(&pk);

#ifdef OE_BUILD_ENCLAVE
    mbedtls_pk_free(ikey);
#else
    EVP_PKEY_free(ikey);
#endif

    result = OE_OK;

done:
    return result;
}

oe_result_t verify_eeid(
    const uint8_t* reported_enclave_hash,
    const uint8_t* reported_enclave_signer,
    uint16_t reported_product_id,
    uint32_t reported_security_version,
    uint64_t reported_attributes,
    const oe_eeid_t* eeid)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!eeid)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (eeid->signature_size != 1808) // We only support SGX sigstructs for now.
        OE_RAISE(OE_VERIFY_FAILED);

    if (oe_get_current_logging_level() >= OE_LOG_LEVEL_VERBOSE)
    {
        char buf[_serialized_eeid_size(eeid)];
        OE_CHECK(oe_serialize_eeid(eeid, buf, sizeof(buf)));
        printf("EEID:\n%s", buf);
    }

    // Compute expected enclave hash
    OE_SHA256 computed_enclave_hash;
    oe_remeasure_memory_pages(eeid, &computed_enclave_hash, true);

    // Check recomputed enclave hash against reported enclave hash
    if (memcmp(
            computed_enclave_hash.buf, reported_enclave_hash, OE_SHA256_SIZE) !=
        0)
        OE_RAISE(OE_VERIFY_FAILED);

    if (memcmp(
            OE_DEBUG_PUBLIC_KEY, reported_enclave_signer, OE_SIGNER_ID_SIZE) !=
        0)
        OE_RAISE(OE_VERIFY_FAILED);

    const sgx_sigstruct_t* sigstruct = (const sgx_sigstruct_t*)&eeid->signature;

    // Compute and check base image hash
    const uint8_t* reported_base_enclave_hash = sigstruct->enclavehash;
    OE_SHA256 computed_base_enclave_hash;
    oe_eeid_t tmp_eeid = *eeid;
    // If we saved non-zero heap/stack sizes for the base image, we could add
    // them here.
    tmp_eeid.size_settings.num_heap_pages = 0;
    tmp_eeid.size_settings.num_stack_pages = 0;
    tmp_eeid.size_settings.num_tcs = 1;
    oe_remeasure_memory_pages(&tmp_eeid, &computed_base_enclave_hash, false);

    if (memcmp(
            computed_base_enclave_hash.buf,
            reported_base_enclave_hash,
            OE_SHA256_SIZE) != 0)
        OE_RAISE(OE_VERIFY_FAILED);

    // Check other image properties have not changed
    bool base_debug = sigstruct->attributes.flags & SGX_FLAGS_DEBUG;
    bool extended_debug = reported_attributes & OE_REPORT_ATTRIBUTES_DEBUG;

    if (base_debug != extended_debug ||
        sigstruct->isvprodid != reported_product_id ||
        sigstruct->isvsvn != reported_security_version)
        OE_RAISE(OE_VERIFY_FAILED);

    // Check old signature (new signature has been checked above)
    if (base_debug && is_zero(sigstruct->signature, OE_KEY_SIZE))
        return OE_OK; // Unsigned debug image is ok.
    else
        OE_CHECK(verify_base_image_signature(sigstruct));

    result = OE_OK;

done:
    return result;
}