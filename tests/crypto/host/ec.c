// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../ec.h"
#include <openenclave/bits/raise.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <string.h>
#include "../../../host/crypto/key.h"

OE_Result OE_ECDSASignatureReadDER(
    const uint8_t* signature,
    size_t signatureSize,
    uint8_t* rData,
    size_t* rSize,
    uint8_t* sData,
    size_t* sSize)
{
    OE_Result result = OE_UNEXPECTED;
    const uint8_t* p = (const uint8_t*)signature;
    ECDSA_SIG* sig = NULL;
    int rn;
    int sn;

    if (!signature || !signatureSize || !rSize || !sSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(sig = d2i_ECDSA_SIG(NULL, &p, signatureSize)))
        OE_RAISE(OE_FAILURE);

    if (!sig->r || !sig->s)
        OE_RAISE(OE_FAILURE);

    /* Convert R to binary */
    {
        rn = BN_num_bytes(sig->r);
        uint8_t buf[rn];

        if (!BN_bn2bin(sig->r, buf))
            OE_RAISE(OE_FAILURE);

        if (rn <= *rSize && rData)
            memcpy(rData, buf, rn);
    }

    /* Convert S to binary */
    {
        sn = BN_num_bytes(sig->s);
        uint8_t buf[sn];

        if (!BN_bn2bin(sig->s, buf))
            OE_RAISE(OE_FAILURE);

        if (sn <= *sSize && sData)
            memcpy(sData, buf, sn);
    }

    /* If buffers are too small */
    if (rn > *rSize || sn > *sSize)
    {
        *rSize = rn;
        *sSize = sn;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Set output-buffer sizes */
    *rSize = rn;
    *sSize = sn;

    result = OE_OK;

done:

    if (sig)
        ECDSA_SIG_free(sig);

    return result;
}

OE_Result OE_ECPublicKeyToCoordinates(
    const OE_ECPublicKey* publicKey,
    uint8_t* xData,
    size_t* xSize,
    uint8_t* yData,
    size_t* ySize)
{
    const OE_PublicKey* impl = (const OE_PublicKey*)publicKey;
    OE_Result result = OE_UNEXPECTED;
    uint8_t* data = NULL;
    EC_KEY* ec = NULL;
    int requiredSize;
    const EC_GROUP* group;
    const EC_POINT* point;
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;

    /* Check for invalid parameters */
    if (!publicKey || !xSize || !ySize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If xData is null, then xDataSize should be zero */
    if (!xData && *xSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If yData is null, then yDataSize should be zero */
    if (!yData && *ySize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the EC public key */
    if (!(ec = EVP_PKEY_get1_EC_KEY(impl->pkey)))
        OE_RAISE(OE_FAILURE);

    /* Set the required buffer size */
    if ((requiredSize = i2o_ECPublicKey(ec, NULL)) == 0)
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

        if (xn > *xSize || yn > *ySize)
        {
            *xSize = xn;
            *ySize = yn;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        *xSize = xn;
        *ySize = yn;
    }

    /* Convert X to big number object */
    if (xData && !(BN_bn2bin(x, xData)))
        OE_RAISE(OE_FAILURE);

    /* Convert Y to big number object */
    if (yData && !(BN_bn2bin(y, yData)))
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
