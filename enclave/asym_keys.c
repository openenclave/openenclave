// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "asym_keys.h"
#include <openenclave/bits/safecrt.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/asym_keys.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/kdf.h>
#include <openenclave/internal/raise.h>
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
    key = (uint8_t*)malloc(key_size);
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
        free(key);
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
        free(key_buffer_local);
    }

    if (key_info_local != NULL)
    {
        oe_secure_zero_fill(key_info_local, key_info_size_local);
        free(key_info_local);
    }

    if (key != NULL)
    {
        oe_secure_zero_fill(key, key_size);
        free(key);
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
        free(key_buffer_local);
    }

    if (key != NULL)
    {
        oe_secure_zero_fill(key, key_size);
        free(key);
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
        free(key_buffer);
    }

    if (key_info)
    {
        oe_secure_zero_fill(key_info, key_info_size);
        free(key_info);
    }
}

static oe_result_t _copy_to_from_host(
    bool to_host,
    const void* data,
    size_t data_size,
    uint8_t** out)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* out_local = NULL;

    if (data == NULL)
    {
        *out = NULL;
        result = OE_OK;
        goto done;
    }

    if (to_host)
    {
        /* Copy enclave -> host. */
        if (!oe_is_within_enclave(data, data_size))
            OE_RAISE(OE_INVALID_PARAMETER);
        out_local = (uint8_t*)oe_host_malloc(data_size);
    }
    else
    {
        /* Copy host -> enclave. */
        if (!oe_is_outside_enclave(data, data_size))
            OE_RAISE(OE_INVALID_PARAMETER);
        out_local = (uint8_t*)malloc(data_size);
    }

    if (out_local == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(oe_memcpy_s(out_local, data_size, data, data_size));

    *out = out_local;
    out_local = NULL;
    result = OE_OK;

done:
    if (out_local != NULL)
    {
        if (to_host)
            oe_host_free(out_local);
        else
            free(out_local);
    }
    return result;
}

void oe_handle_get_public_key_by_policy(uint64_t arg_in)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_public_key_by_policy_args_t* uarg =
        (oe_get_public_key_by_policy_args_t*)arg_in;
    oe_get_public_key_by_policy_args_t arg;
    uint8_t* enclave_user_data = NULL;
    uint8_t* host_key_info = NULL;
    uint8_t* host_key_buffer = NULL;

    /* Copy arguments to avoid time of use / time of check. */
    if (!uarg || !oe_is_outside_enclave(uarg, sizeof(uarg)))
        return;

    arg = *uarg;
    arg.key_buffer = NULL;
    arg.key_buffer_size = 0;
    arg.key_info = NULL;
    arg.key_info_size = 0;

    OE_CHECK(_copy_to_from_host(
        false,
        arg.key_params.user_data,
        arg.key_params.user_data_size,
        &enclave_user_data));

    arg.key_params.user_data = enclave_user_data;

    /* Get the key. */
    OE_CHECK(oe_get_public_key_by_policy(
        arg.seal_policy,
        &arg.key_params,
        &arg.key_buffer,
        &arg.key_buffer_size,
        &arg.key_info,
        &arg.key_info_size));

    /* Copy to host memory. */
    OE_CHECK(_copy_to_from_host(
        true, arg.key_info, arg.key_info_size, &host_key_info));

    OE_CHECK(_copy_to_from_host(
        true, arg.key_buffer, arg.key_buffer_size, &host_key_buffer));

    /* Success. Just copy to unsafe struct now. */
    uarg->key_info = host_key_info;
    uarg->key_info_size = arg.key_info_size;
    uarg->key_buffer = host_key_buffer;
    uarg->key_buffer_size = arg.key_buffer_size;
    host_key_info = NULL;
    host_key_buffer = NULL;
    result = OE_OK;

done:
    uarg->result = result;

    if (enclave_user_data != NULL)
        free(enclave_user_data);

    if (arg.key_buffer != NULL)
        free(arg.key_buffer);

    if (arg.key_info != NULL)
        free(arg.key_info);

    if (host_key_info != NULL)
        oe_host_free(host_key_info);

    if (host_key_buffer != NULL)
        oe_host_free(host_key_buffer);
}

void oe_handle_get_public_key(uint64_t arg_in)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_public_key_args_t* uarg = (oe_get_public_key_args_t*)arg_in;
    oe_get_public_key_args_t arg;
    uint8_t* enclave_user_data = NULL;
    uint8_t* enclave_key_info = NULL;
    uint8_t* host_key_buffer = NULL;

    /* Copy arguments to avoid time of use / time of check. */
    if (!uarg || !oe_is_outside_enclave(uarg, sizeof(uarg)))
        return;

    arg = *uarg;
    arg.key_buffer = NULL;
    arg.key_buffer_size = 0;

    OE_CHECK(_copy_to_from_host(
        false,
        arg.key_params.user_data,
        arg.key_params.user_data_size,
        &enclave_user_data));

    OE_CHECK(_copy_to_from_host(
        false, arg.key_info, arg.key_info_size, &enclave_key_info));

    arg.key_params.user_data = enclave_user_data;
    arg.key_info = enclave_key_info;

    /* Get the key. */
    OE_CHECK(oe_get_public_key(
        &arg.key_params,
        arg.key_info,
        arg.key_info_size,
        &arg.key_buffer,
        &arg.key_buffer_size));

    /* Copy to host memory. */
    OE_CHECK(_copy_to_from_host(
        true, arg.key_buffer, arg.key_buffer_size, &host_key_buffer));

    /* Success. Just copy to unsafe struct now. */
    uarg->key_buffer = host_key_buffer;
    uarg->key_buffer_size = arg.key_buffer_size;
    host_key_buffer = NULL;
    result = OE_OK;

done:
    uarg->result = result;

    if (enclave_user_data != NULL)
        free(enclave_user_data);

    if (enclave_key_info != NULL)
        free(enclave_key_info);

    if (arg.key_buffer != NULL)
        free(arg.key_buffer);

    if (host_key_buffer != NULL)
        oe_host_free(host_key_buffer);
}
