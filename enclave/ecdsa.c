// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/config.h>
#include <mbedtls/ecdsa.h>

#include <openenclave/enclave.h>

#include <openenclave/bits/ecdsa.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/sha.h>
#include <openenclave/bits/utils.h>

OE_Result OE_ECDSA256_SHA_Verify(
    const OE_ECDSA256Key* key,
    const void* data,
    uint32_t size,
    const OE_ECDSA256Signature* signature)
{
    OE_Result result = OE_UNEXPECTED;
    OE_SHA256 sha256 = {0};
    int res = 0;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;

    // mbedtls setup
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    res =
        mbedtls_mpi_read_binary(&r, signature->r, sizeof(signature->r)) || res;
    res =
        mbedtls_mpi_read_binary(&s, signature->s, sizeof(signature->s)) || res;
    res = mbedtls_mpi_read_binary(&Q.X, key->x, sizeof(key->x)) || res;
    res = mbedtls_mpi_read_binary(&Q.Y, key->y, sizeof(key->y)) || res;
    res = mbedtls_mpi_lset(&Q.Z, 1) || res;
    res = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) || res;

    // Check if any of the mbedtls setup failed.
    if (res != 0)
        goto done;

    OE_CHECK(OE_ComputeSHA256(data, size, &sha256));

    if (mbedtls_ecdsa_verify(
            &grp, (const uint8_t*)&sha256, sizeof(sha256), &Q, &r, &s) != 0)
        OE_RAISE(OE_VERIFY_FAILED);

    result = OE_OK;
done:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return result;
}