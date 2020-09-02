// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/crypto/ec.h>
#include <openenclave/internal/kdf.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>
#include <stdlib.h>

static inline oe_result_t _check_asymmetric_key_params(
    const oe_asymmetric_key_params_t* key_params)
{
    if (key_params == NULL)
        return OE_INVALID_PARAMETER;

    if (key_params->type != OE_ASYMMETRIC_KEY_EC_SECP256P1)
        return OE_INVALID_PARAMETER;

    if (key_params->format != OE_ASYMMETRIC_KEY_PEM)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}

static oe_result_t _load_seal_key_by_policy(
    oe_seal_policy_t policy,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* key_buffer_local = NULL;
    size_t key_buffer_size_local = 0;
    uint8_t* key_info_local = NULL;
    size_t key_info_size_local = 0;

    if (!key_buffer || !key_buffer_size || (key_info && !key_info_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Now, get the key buffers. */
    result = oe_get_seal_key_by_policy(
        policy,
        &key_buffer_local,
        &key_buffer_size_local,
        &key_info_local,
        &key_info_size_local);

    if (result != OE_OK)
        OE_RAISE(result);

    result = OE_OK;
    *key_buffer = key_buffer_local;
    *key_buffer_size = key_buffer_size_local;
    if (key_info)
    {
        *key_info = key_info_local;
        *key_info_size = key_info_size_local;
    }
    else
    {
        oe_free_seal_key(NULL, key_info_local);
    }
    key_buffer_local = NULL;
    key_info_local = NULL;

done:

    return result;
}

static oe_result_t _load_seal_key(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* key_buffer_local = NULL;
    size_t key_buffer_size_local = 0;

    if (!key_info || !key_buffer || !key_buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    result = oe_get_seal_key(
        key_info, key_info_size, &key_buffer_local, &key_buffer_size_local);

    if (result != OE_OK)
        OE_RAISE(result);

    result = OE_OK;
    *key_buffer = key_buffer_local;
    *key_buffer_size = key_buffer_size_local;
    key_buffer_local = NULL;

done:
    return result;
}

static oe_result_t _create_asymmetric_keypair(
    const oe_asymmetric_key_params_t* key_params,
    const uint8_t* master_key,
    size_t master_key_size,
    oe_ec_private_key_t* private_key,
    oe_ec_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t key[OE_SHA256_SIZE];
    uint8_t key_prev[sizeof(key)];
    oe_ec_type_t type;

    if (!key_params || !master_key || !private_key || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    switch (key_params->type)
    {
        case OE_ASYMMETRIC_KEY_EC_SECP256P1:
            type = OE_EC_TYPE_SECP256R1;
            break;
        default:
            OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* First, derive a key from the given key. */
    OE_CHECK(oe_kdf_derive_key(
        OE_KDF_HMAC_SHA256_CTR,
        master_key,
        master_key_size,
        key_params->user_data,
        key_params->user_data_size,
        key,
        sizeof(key)));

    /*
     * If the derived key is not a valid ECC private key, then we use the
     * derived key to derive another candidate key. The main requirement
     * for the derived key is to be between [1, N-1], where N is the order
     * (number of points) on the elliptic curve. For most curves, it's
     * very likely that derived key is already within that range.
     */
    while (!oe_ec_valid_raw_private_key(type, key, sizeof(key)))
    {
        /* Copy to a temporary buffer before doing the key derivation. */
        OE_CHECK(oe_memcpy_s(key_prev, sizeof(key_prev), key, sizeof(key)));

        /* Derive a new key. */
        OE_CHECK(oe_kdf_derive_key(
            OE_KDF_HMAC_SHA256_CTR,
            key_prev,
            sizeof(key_prev),
            key_params->user_data,
            key_params->user_data_size,
            key,
            sizeof(key)));
    }

    /* Derive both public and private keys. */
    OE_CHECK(oe_ec_generate_key_pair_from_private(
        type, key, sizeof(key), private_key, public_key));

    result = OE_OK;

done:
    oe_secure_zero_fill(key, sizeof(key));
    oe_secure_zero_fill(key_prev, sizeof(key_prev));
    return result;
}

static oe_result_t _export_keypair(
    const oe_asymmetric_key_params_t* key_params,
    bool is_public,
    const oe_ec_private_key_t* private_key,
    const oe_ec_public_key_t* public_key,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* key = NULL;
    size_t key_size = 0;

    if (!key_params || !private_key || !public_key || !key_buffer ||
        !key_buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Call once to get the size. */
    if (is_public)
        result = oe_ec_public_key_write_pem(public_key, key, &key_size);
    else
        result = oe_ec_private_key_write_pem(private_key, key, &key_size);

    if (result == OE_OK)
        OE_RAISE(OE_UNEXPECTED);

    if (result != OE_BUFFER_TOO_SMALL)
        OE_RAISE(result);

    /* Call again with the allocated memory. */
    key = (uint8_t*)oe_malloc(key_size);
    if (key == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    if (is_public)
        result = oe_ec_public_key_write_pem(public_key, key, &key_size);
    else
        result = oe_ec_private_key_write_pem(private_key, key, &key_size);

    if (result != OE_OK)
        OE_RAISE(result);

    result = OE_OK;
    *key_buffer = key;
    *key_buffer_size = key_size;
    key = NULL;

done:
    if (key != NULL)
    {
        oe_secure_zero_fill(key, key_size);
        oe_free(key);
    }

    return result;
}

static oe_result_t _derive_asymmetric_key(
    const oe_asymmetric_key_params_t* key_params,
    bool is_public,
    const uint8_t* master_key,
    size_t master_key_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_ec_public_key_t public_key;
    oe_ec_private_key_t private_key;
    bool keypair_created = false;

    /* Check invalid arguments. */
    if (!master_key || !key_buffer || !key_buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_check_asymmetric_key_params(key_params));

    /* Derive the public/private key from the master key. */
    OE_CHECK(_create_asymmetric_keypair(
        key_params, master_key, master_key_size, &private_key, &public_key));

    keypair_created = true;

    /* Export the key depending on what was requested. */
    OE_CHECK(_export_keypair(
        key_params,
        is_public,
        &private_key,
        &public_key,
        key_buffer,
        key_buffer_size));

    result = OE_OK;

done:
    if (keypair_created)
    {
        oe_ec_private_key_free(&private_key);
        oe_ec_public_key_free(&public_key);
    }

    return result;
}

static oe_result_t _load_asymmetric_key_by_policy(
    oe_seal_policy_t policy,
    const oe_asymmetric_key_params_t* key_params,
    bool is_public,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* key = NULL;
    size_t key_size = 0;
    uint8_t* key_buffer_local = NULL;
    size_t key_buffer_size_local = 0;
    uint8_t* key_info_local = NULL;
    size_t key_info_size_local = 0;

    /* Check invalid params. */
    if (!key_buffer || !key_buffer_size || (key_info && !key_info_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_check_asymmetric_key_params(key_params));

    /* Load seal key. */
    OE_CHECK(_load_seal_key_by_policy(
        policy,
        &key,
        &key_size,
        key_info ? &key_info_local : NULL,
        key_info ? &key_info_size_local : NULL));

    /* Derive the asymmetric key. */
    OE_CHECK(_derive_asymmetric_key(
        key_params,
        is_public,
        key,
        key_size,
        &key_buffer_local,
        &key_buffer_size_local));

    result = OE_OK;
    *key_buffer = key_buffer_local;
    *key_buffer_size = key_buffer_size_local;
    if (key_info)
    {
        *key_info = key_info_local;
        *key_info_size = key_info_size_local;
    }
    key_buffer_local = NULL;
    key_info_local = NULL;

done:
    if (key_buffer_local != NULL)
    {
        oe_secure_zero_fill(key_buffer_local, key_buffer_size_local);
        oe_free(key_buffer_local);
    }

    if (key_info_local != NULL)
    {
        oe_secure_zero_fill(key_info_local, key_info_size_local);
        oe_free(key_info_local);
    }

    if (key != NULL)
    {
        oe_secure_zero_fill(key, key_size);
        oe_free(key);
    }

    return result;
}

static oe_result_t _load_asymmetric_key(
    const oe_asymmetric_key_params_t* key_params,
    bool is_public,
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* key = NULL;
    size_t key_size = 0;
    uint8_t* key_buffer_local = NULL;
    size_t key_buffer_size_local = 0;

    /* Check invalid params. */
    if (!key_info || !key_buffer || !key_buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_check_asymmetric_key_params(key_params));

    /* Load seal key. */
    OE_CHECK(_load_seal_key(key_info, key_info_size, &key, &key_size));

    /* Derive the asymmetric key. */
    OE_CHECK(_derive_asymmetric_key(
        key_params,
        is_public,
        key,
        key_size,
        &key_buffer_local,
        &key_buffer_size_local));

    result = OE_OK;
    *key_buffer = key_buffer_local;
    *key_buffer_size = key_buffer_size_local;
    key_buffer_local = NULL;

done:
    if (key_buffer_local != NULL)
    {
        oe_secure_zero_fill(key_buffer_local, key_buffer_size_local);
        oe_free(key_buffer_local);
    }

    if (key != NULL)
    {
        oe_secure_zero_fill(key, key_size);
        oe_free(key);
    }

    return result;
}

oe_result_t oe_get_public_key_by_policy(
    oe_seal_policy_t policy,
    const oe_asymmetric_key_params_t* key_params,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    return _load_asymmetric_key_by_policy(
        policy,
        key_params,
        true,
        key_buffer,
        key_buffer_size,
        key_info,
        key_info_size);
}

oe_result_t oe_get_public_key(
    const oe_asymmetric_key_params_t* key_params,
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    return _load_asymmetric_key(
        key_params, true, key_info, key_info_size, key_buffer, key_buffer_size);
}

oe_result_t oe_get_private_key_by_policy(
    oe_seal_policy_t policy,
    const oe_asymmetric_key_params_t* key_params,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    return _load_asymmetric_key_by_policy(
        policy,
        key_params,
        false,
        key_buffer,
        key_buffer_size,
        key_info,
        key_info_size);
}

oe_result_t oe_get_private_key(
    const oe_asymmetric_key_params_t* key_params,
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    return _load_asymmetric_key(
        key_params,
        false,
        key_info,
        key_info_size,
        key_buffer,
        key_buffer_size);
}

void oe_free_key(
    uint8_t* key_buffer,
    size_t key_buffer_size,
    uint8_t* key_info,
    size_t key_info_size)
{
    if (key_buffer)
    {
        oe_secure_zero_fill(key_buffer, key_buffer_size);
        oe_free(key_buffer);
    }

    if (key_info)
    {
        oe_secure_zero_fill(key_info, key_info_size);
        oe_free(key_info);
    }
}

/* If this function is modified to produce larger keys, please increase the
 * DEFAULT_KEY_BUFFER_SIZE definition on the host side accordingly.
 */
oe_result_t oe_get_public_key_by_policy_ecall(
    uint32_t seal_policy,
    const oe_asymmetric_key_params_t* key_params,
    void* key_buffer,
    size_t key_buffer_size,
    size_t* key_buffer_size_out,
    void* key_info,
    size_t key_info_size,
    size_t* key_info_size_out)
{
    oe_result_t result = OE_UNEXPECTED;
    struct
    {
        uint8_t* key_buffer;
        size_t key_buffer_size;
        uint8_t* key_info;
        size_t key_info_size;
    } arg = {NULL};

    if (key_buffer_size_out)
        *key_info_size_out = 0;

    if (key_info_size_out)
        *key_info_size_out = 0;

    if (!key_buffer_size_out || !key_info_size_out)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the key. */
    OE_CHECK(oe_get_public_key_by_policy(
        (oe_seal_policy_t)seal_policy,
        key_params,
        &arg.key_buffer,
        &arg.key_buffer_size,
        &arg.key_info,
        &arg.key_info_size));

    *key_buffer_size_out = arg.key_buffer_size;
    *key_info_size_out = arg.key_info_size;

    if (key_buffer_size < arg.key_buffer_size)
        OE_RAISE(OE_BUFFER_TOO_SMALL);

    if (key_info_size < arg.key_info_size)
        OE_RAISE(OE_BUFFER_TOO_SMALL);

    memcpy(key_buffer, arg.key_buffer, arg.key_buffer_size);
    memcpy(key_info, arg.key_info, arg.key_info_size);

    result = OE_OK;

done:

    oe_free(arg.key_buffer);
    oe_free(arg.key_info);

    return result;
}

/* If this function is modified to produce larger keys, please increase the
 * DEFAULT_KEY_BUFFER_SIZE definition on the host side accordingly.
 */
oe_result_t oe_get_public_key_ecall(
    const oe_asymmetric_key_params_t* key_params,
    const void* key_info,
    size_t key_info_size,
    void* key_buffer,
    size_t key_buffer_size,
    size_t* key_buffer_size_out)
{
    oe_result_t result = OE_UNEXPECTED;
    struct
    {
        uint8_t* key_buffer;
        size_t key_buffer_size;
    } arg = {NULL};

    if (key_buffer_size_out)
        *key_buffer_size_out = 0;

    if (!key_buffer_size_out)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the key. */
    OE_CHECK(oe_get_public_key(
        key_params,
        key_info,
        key_info_size,
        &arg.key_buffer,
        &arg.key_buffer_size));

    *key_buffer_size_out = arg.key_buffer_size;

    if (key_buffer_size < arg.key_buffer_size)
        OE_RAISE(OE_BUFFER_TOO_SMALL);

    memcpy(key_buffer, arg.key_buffer, arg.key_buffer_size);

    result = OE_OK;

done:

    oe_free(arg.key_buffer);

    return result;
}
