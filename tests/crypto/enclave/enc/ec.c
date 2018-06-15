// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../../ec.h"
#include <mbedtls/asn1write.h>
#include <openenclave/internal/raise.h>
#include "../../../../enclave/key.h"

oe_result_t oe_ec_public_key_to_coordinates(
    const oe_ec_public_key_t* public_key,
    uint8_t* x_data,
    size_t* x_size,
    uint8_t* y_data,
    size_t* y_size)
{
    oe_public_key_t* impl = (oe_public_key_t*)public_key;
    oe_result_t result = OE_UNEXPECTED;

    /* Check for invalid parameters */
    if (!impl || !x_size || !y_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If x_data is null, then x_size should be zero */
    if (!x_data && *x_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If y_data is null, then y_size should be zero */
    if (!y_data && *y_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Convert public EC key to binary */
    {
        const mbedtls_ecp_keypair* ec;
        size_t size;

        if (!(ec = mbedtls_pk_ec(impl->pk)))
            OE_RAISE(OE_FAILURE);

        size = mbedtls_mpi_size(&ec->grp.P);

        if (size > *x_size || size > *y_size)
        {
            *x_size = size;
            *y_size = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        *x_size = size;
        *y_size = size;

        /* Write the X coordinate */
        if (mbedtls_mpi_write_binary(&ec->Q.X, x_data, *x_size) != 0)
            OE_RAISE(OE_FAILURE);

        /* Write the Y coordinate */
        if (mbedtls_mpi_write_binary(&ec->Q.Y, y_data, *y_size) != 0)
            OE_RAISE(OE_FAILURE);
    }

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_ecdsa_signature_read_der(
    const uint8_t* signature,
    size_t signature_size,
    uint8_t* r_data,
    size_t* r_size,
    uint8_t* s_data,
    size_t* s_size)
{
    oe_result_t result = OE_UNEXPECTED;
    mbedtls_mpi r;
    mbedtls_mpi s;
    uint8_t* p = (uint8_t*)signature;
    const uint8_t* end = signature + signature_size;
    size_t len;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (!signature || !signature_size || !r_size || !s_size)
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
        const size_t r_bytes = mbedtls_mpi_size(&r);
        const size_t s_bytes = mbedtls_mpi_size(&s);

        bool buffer_to_small = (r_bytes > *r_size || s_bytes > *s_size);
        *r_size = r_bytes;
        *s_size = s_bytes;

        if (buffer_to_small)
            OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Fail if buffers are null */
    if (!r_data || !r_size)
        OE_RAISE(OE_FAILURE);

    /* Convert R to binary */
    if (mbedtls_mpi_write_binary(&r, r_data, *r_size) != 0)
        OE_RAISE(OE_FAILURE);

    /* Convert S to binary */
    if (mbedtls_mpi_write_binary(&s, s_data, *s_size) != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return result;
}
