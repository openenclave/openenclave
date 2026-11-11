// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/crypto/gcm.h>
#include <openenclave/internal/tests.h>
#include <openenclave/sgx/seal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// The GCM-AES wire format is needed to construct authenticated unsafe blobs
// independently of the seal path, which must reject these key requests.
struct SealedBlobHeader
{
    sgx_key_request_t keyrequest;
    uint32_t ciphertext_size;
    uint8_t reserved[12];
    uint32_t total_size;
    uint8_t iv[12];
    uint8_t tag[OE_GCM_TAG_SIZE];
};

static const uint8_t _plaintext[] = "authenticated sealing policy regression";
static const uint8_t _aad[] = "sealing policy additional data";
static const oe_seal_setting_t _default_setting =
    OE_SEAL_SET_SGX_KEYNAME(SGX_KEYSELECT_SEAL);

static uint8_t* _seal(
    const oe_seal_setting_t* settings,
    size_t settings_count,
    const uint8_t* aad,
    size_t aad_size,
    size_t* blob_size)
{
    uint8_t* blob = NULL;
    OE_TEST_CODE(
        oe_seal(
            NULL,
            settings,
            settings_count,
            _plaintext,
            sizeof(_plaintext),
            aad,
            aad_size,
            &blob,
            blob_size),
        OE_OK);
    OE_TEST(*blob_size == sizeof(SealedBlobHeader) + sizeof(_plaintext));
    return blob;
}

static void _check_plaintext(
    oe_result_t result,
    const uint8_t* plaintext,
    size_t plaintext_size)
{
    if (result == OE_OK)
    {
        OE_TEST(plaintext != NULL);
        OE_TEST(plaintext_size == sizeof(_plaintext));
        OE_TEST(memcmp(plaintext, _plaintext, sizeof(_plaintext)) == 0);
    }
    else
    {
        OE_TEST(plaintext == NULL);
    }
}

static void _unseal(
    const uint8_t* blob,
    size_t blob_size,
    const uint8_t* aad,
    size_t aad_size,
    oe_result_t expected)
{
    uint8_t* plaintext = NULL;
    size_t plaintext_size = 0;
    uint8_t* host_blob = (uint8_t*)oe_host_malloc(blob_size);
    OE_TEST(host_blob != NULL);
    memcpy(host_blob, blob, blob_size);

    oe_result_t result = oe_unseal(
        host_blob, blob_size, aad, aad_size, &plaintext, &plaintext_size);
    oe_host_free(host_blob);
    _check_plaintext(result, plaintext, plaintext_size);
    free(plaintext);
    oe_result_t public_expected = expected == OE_OK ? OE_OK : OE_UNSUPPORTED;
    printf(
        "oe_unseal returned %s (expected %s)\n",
        oe_result_str(result),
        oe_result_str(public_expected));
    OE_TEST(result == public_expected);

    plaintext = NULL;
    plaintext_size = 0;
    result = oe_seal_plugin_gcm_aes.unseal(
        blob, blob_size, aad, aad_size, &plaintext, &plaintext_size);
    _check_plaintext(result, plaintext, plaintext_size);
    free(plaintext);
    OE_TEST(result == expected);
}

static void _test_forged_key_request(
    uint16_t key_name,
    uint16_t key_policy,
    uint64_t flags_mask,
    oe_result_t expected)
{
    size_t blob_size = 0;
    uint8_t* blob = _seal(&_default_setting, 1, _aad, sizeof(_aad), &blob_size);
    SealedBlobHeader header;
    memcpy(&header, blob, sizeof(header));
    header.keyrequest.key_name = key_name;
    header.keyrequest.key_policy = key_policy;
    header.keyrequest.attribute_mask.flags = flags_mask;

    uint8_t* key = NULL;
    size_t key_size = 0;
    OE_TEST_CODE(
        oe_get_seal_key(
            (const uint8_t*)&header.keyrequest,
            sizeof(header.keyrequest),
            &key,
            &key_size),
        OE_OK);
    OE_TEST_CODE(
        oe_aes_gcm_encrypt(
            key,
            key_size,
            header.iv,
            sizeof(header.iv),
            _aad,
            sizeof(_aad),
            _plaintext,
            sizeof(_plaintext),
            blob + sizeof(header),
            sizeof(_plaintext),
            header.tag),
        OE_OK);

    // Prove this is authenticated ciphertext, not a header mutation that the
    // old unseal implementation would already reject during GCM verification.
    uint8_t decrypted[sizeof(_plaintext)];
    OE_TEST_CODE(
        oe_aes_gcm_decrypt(
            key,
            key_size,
            header.iv,
            sizeof(header.iv),
            _aad,
            sizeof(_aad),
            blob + sizeof(header),
            sizeof(_plaintext),
            decrypted,
            sizeof(decrypted),
            header.tag),
        OE_OK);
    OE_TEST(memcmp(decrypted, _plaintext, sizeof(_plaintext)) == 0);
    oe_free_seal_key(key, NULL);
    memcpy(blob, &header, sizeof(header));

    printf(
        "Authenticated blob: key_name=%u, key_policy=%u, DEBUG mask=%u\n",
        (unsigned)key_name,
        (unsigned)key_policy,
        (unsigned)((flags_mask & SGX_FLAGS_DEBUG) != 0));
    _unseal(blob, blob_size, _aad, sizeof(_aad), expected);
    free(blob);
}

static void _test_rejected_setting(const oe_seal_setting_t* setting)
{
    uint8_t* blob = NULL;
    size_t blob_size = 0;
    OE_TEST_CODE(
        oe_seal(
            NULL,
            setting,
            1,
            _plaintext,
            sizeof(_plaintext),
            NULL,
            0,
            &blob,
            &blob_size),
        OE_INVALID_PARAMETER);
    OE_TEST(blob == NULL);
}

void TestSealPolicy()
{
    printf("=== Testing SGX sealing key policy validation\n");
    _test_forged_key_request(
        SGX_KEYSELECT_SEAL,
        0,
        OE_SEALKEY_DEFAULT_FLAGSMASK,
        OE_INVALID_PARAMETER);
    _test_forged_key_request(
        SGX_KEYSELECT_REPORT,
        SGX_KEYPOLICY_MRSIGNER,
        OE_SEALKEY_DEFAULT_FLAGSMASK,
        OE_INVALID_PARAMETER);
    _test_forged_key_request(
        SGX_KEYSELECT_SEAL,
        SGX_KEYPOLICY_MRSIGNER,
        OE_SEALKEY_DEFAULT_FLAGSMASK & ~SGX_FLAGS_DEBUG,
        OE_INVALID_PARAMETER);
    _test_forged_key_request(
        SGX_KEYSELECT_SEAL,
        SGX_KEYPOLICY_ALL,
        OE_SEALKEY_DEFAULT_FLAGSMASK,
        OE_OK);

    for (uint16_t name = SGX_KEYSELECT_EINITTOKEN; name < SGX_KEYSELECT_SEAL;
         ++name)
    {
        const oe_seal_setting_t setting = OE_SEAL_SET_SGX_KEYNAME(name);
        _test_rejected_setting(&setting);
    }
    const oe_seal_setting_t unsafe_mask = OE_SEAL_SET_SGX_FLAGSMASK(
        OE_SEALKEY_DEFAULT_FLAGSMASK & ~SGX_FLAGS_DEBUG);
    _test_rejected_setting(&unsafe_mask);

    size_t blob_size = 0;
    uint8_t* blob = _seal(&_default_setting, 1, NULL, 0, &blob_size);
    _unseal(blob, blob_size, NULL, 0, OE_OK);
    free(blob);

    for (uint16_t policy = OE_SEAL_POLICY_UNIQUE;
         policy <= OE_SEAL_POLICY_PRODUCT;
         ++policy)
    {
        const oe_seal_setting_t setting = OE_SEAL_SET_POLICY(policy);
        blob = _seal(&setting, 1, _aad, sizeof(_aad), &blob_size);
        _unseal(blob, blob_size, _aad, sizeof(_aad), OE_OK);
        uint8_t wrong_aad[sizeof(_aad)];
        memcpy(wrong_aad, _aad, sizeof(_aad));
        wrong_aad[0] ^= 1;
        _unseal(blob, blob_size, wrong_aad, sizeof(wrong_aad), OE_CRYPTO_ERROR);
        free(blob);

        const uint8_t older_cpu_svn[SGX_CPUSVN_SIZE] = {0};
        const oe_seal_setting_t older_svn[] = {
            OE_SEAL_SET_POLICY(policy),
            OE_SEAL_SET_SGX_ISVSVN(0),
            OE_SEAL_SET_SGX_CPUSVN(older_cpu_svn)};
        blob = _seal(
            older_svn, OE_COUNTOF(older_svn), _aad, sizeof(_aad), &blob_size);
        _unseal(blob, blob_size, _aad, sizeof(_aad), OE_OK);
        free(blob);
    }
}
