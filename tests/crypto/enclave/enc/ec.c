// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../../ec.h"
#include <mbedtls/asn1write.h>
#include <openenclave/bits/raise.h>
#include "../../../../enclave/key.h"

oe_result_t oe_ec_public_key_to_coordinates(
    const oe_ec_public_key_t* publicKey,
    uint8_t* xData,
    size_t* xSize,
    uint8_t* yData,
    size_t* ySize)
{
    oe_public_key_t* impl = (oe_public_key_t*)publicKey;
    oe_result_t result = OE_UNEXPECTED;

    /* Check for invalid parameters */
    if (!impl || !xSize || !ySize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If xData is null, then xDataSize should be zero */
    if (!xData && *xSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If yData is null, then yDataSize should be zero */
    if (!yData && *ySize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Convert public EC key to binary */
    {
        const mbedtls_ecp_keypair* ec;
        size_t size;

        if (!(ec = mbedtls_pk_ec(impl->pk)))
            OE_RAISE(OE_FAILURE);

        size = mbedtls_mpi_size(&ec->grp.P);

        if (size > *xSize || size > *ySize)
        {
            *xSize = size;
            *ySize = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        *xSize = size;
        *ySize = size;

        /* Write the X coordinate */
        if (mbedtls_mpi_write_binary(&ec->Q.X, xData, *xSize) != 0)
            OE_RAISE(OE_FAILURE);

        /* Write the Y coordinate */
        if (mbedtls_mpi_write_binary(&ec->Q.Y, yData, *ySize) != 0)
            OE_RAISE(OE_FAILURE);
    }

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_ecdsa__signature_read_der(
    const uint8_t* signature,
    size_t signatureSize,
    uint8_t* rData,
    size_t* rSize,
    uint8_t* sData,
    size_t* sSize)
{
    oe_result_t result = OE_UNEXPECTED;
    mbedtls_mpi r;
    mbedtls_mpi s;
    uint8_t* p = (uint8_t*)signature;
    const uint8_t* end = signature + signatureSize;
    size_t len;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (!signature || !signatureSize || !rSize || !sSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Parse the tag */
    {
        unsigned char tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;

        if (mbedtls_asn1_get_tag(&p, end, &len, tag) != 0)
            OE_RAISE(OE_FAILURE);

        if (p + len != end)
            OE_RAISE(OE_FAILURE);
    }

    /* Parse R */
    if (mbedtls_asn1_get_mpi(&p, end, &r) != 0)
        OE_RAISE(OE_FAILURE);

    /* Parse S */
    if (mbedtls_asn1_get_mpi(&p, end, &s) != 0)
        OE_RAISE(OE_FAILURE);

    /* Check that output buffers are big enough */
    {
        const size_t rBytes = mbedtls_mpi_size(&r);
        const size_t sBytes = mbedtls_mpi_size(&s);

        bool bufferToSmall = (rBytes > *rSize || sBytes > *sSize);
        *rSize = rBytes;
        *sSize = sBytes;

        if (bufferToSmall)
            OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Fail if buffers are null */
    if (!rData || !rSize)
        OE_RAISE(OE_FAILURE);

    /* Convert R to binary */
    if (mbedtls_mpi_write_binary(&r, rData, *rSize) != 0)
        OE_RAISE(OE_FAILURE);

    /* Convert S to binary */
    if (mbedtls_mpi_write_binary(&s, sData, *sSize) != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return result;
}
