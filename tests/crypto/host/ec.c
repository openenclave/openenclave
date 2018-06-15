// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../ec.h"
#include <openenclave/internal/raise.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <string.h>
#include "../../../host/crypto/key.h"

oe_result_t oe_ecdsa_signature_read_der(
    const uint8_t* signature,
    size_t signature_size,
    uint8_t* r_data,
    size_t* r_size,
    uint8_t* s_data,
    size_t* s_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const uint8_t* p = (const uint8_t*)signature;
    ECDSA_SIG* sig = NULL;
    int rn;
    int sn;

    if (!signature || !signature_size || !r_size || !s_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(sig = d2_i_ecdsa_sig(NULL, &p, signature_size)))
        OE_RAISE(OE_FAILURE);

    if (!sig->r || !sig->s)
        OE_RAISE(OE_FAILURE);

    /* Convert R to binary */
    {
        rn = BN_num_bytes(sig->r);
        uint8_t buf[rn];

        if (!BN_bn2bin(sig->r, buf))
            OE_RAISE(OE_FAILURE);

        if (rn <= *r_size && r_data)
            memcpy(r_data, buf, rn);
    }

    /* Convert S to binary */
    {
        sn = BN_num_bytes(sig->s);
        uint8_t buf[sn];

        if (!BN_bn2bin(sig->s, buf))
            OE_RAISE(OE_FAILURE);

        if (sn <= *s_size && s_data)
            memcpy(s_data, buf, sn);
    }

    /* If buffers are too small */
    if (rn > *r_size || sn > *s_size)
    {
        *r_size = rn;
        *s_size = sn;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Set output-buffer sizes */
    *r_size = rn;
    *s_size = sn;

    result = OE_OK;

done:

    if (sig)
        ECDSA_SIG_free(sig);

    return result;
}

oe_result_t oe_ec_public_key_to_coordinates(
    const oe_ec_public_key_t* public_key,
    uint8_t* x_data,
    size_t* x_size,
    uint8_t* y_data,
    size_t* y_size)
{
    const oe_public_key_t* impl = (const oe_public_key_t*)public_key;
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* data = NULL;
    EC_KEY* ec = NULL;
    int required_size;
    const EC_GROUP* group;
    const EC_POINT* point;
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;

    /* Check for invalid parameters */
    if (!public_key || !x_size || !y_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If x_data is null, then x_size should be zero */
    if (!x_data && *x_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If y_data is null, then y_size should be zero */
    if (!y_data && *y_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the EC public key */
    if (!(ec = EVP_PKEY_get1_EC_KEY(impl->pkey)))
        OE_RAISE(OE_FAILURE);

    /* Set the required buffer size */
    if ((required_size = i2_o_ec_public_key(ec, NULL)) == 0)
        OE_RAISE(OE_FAILURE);

    /* Get the group */
    if (!(group = EC_KEY_get0_group(ec)))
        OE_RAISE(OE_FAILURE);

    /* Get public key point */
    if (!(point = EC_KEY_get0_public_key(ec)))
        OE_RAISE(OE_FAILURE);

    if (!(x = BN_new()) || !(y = BN_new()))
        OE_RAISE(OE_FAILURE);

    /* Get the coordinates */
    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, NULL))
        OE_RAISE(OE_FAILURE);

    /* Check whether data buffers are too small */
    {
        size_t xn = BN_num_bytes(x);
        size_t yn = BN_num_bytes(y);

        bool buffer_too_small = (xn > *x_size || yn > *y_size);
        *x_size = xn;
        *y_size = yn;

        if (buffer_too_small)
            OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Convert X to big number object */
    if (x_data && !(BN_bn2bin(x, x_data)))
        OE_RAISE(OE_FAILURE);

    /* Convert Y to big number object */
    if (y_data && !(BN_bn2bin(y, y_data)))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (ec)
        EC_KEY_free(ec);

    if (data)
        free(data);

    if (x)
        BN_free(x);

    if (y)
        BN_free(y);

    return result;
}
