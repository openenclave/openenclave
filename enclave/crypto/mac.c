// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/cmac.h>
#include <mbedtls/config.h>
#include <openenclave/enclave.h>

#include <openenclave/bits/mac.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/sgxtypes.h>

OE_STATIC_ASSERT(sizeof(OE_MAC) * 8 == 128);

OE_Result OE_GetMAC(
    const uint8_t* key,
    uint32_t keySize,
    const uint8_t* src,
    uint32_t len,
    OE_MAC* mac)
{
    OE_Result result = OE_OK;
    //mbedtls_cipher_context_t ctx;
    const mbedtls_cipher_info_t* info = NULL;
    //uint64_t outlen = 0;

    //mbedtls_cipher_init( &ctx );

    if (mac == NULL)
        OE_RAISE(OE_BUFFER_TOO_SMALL);

    if (keySize != sizeof(SGX_Key))
        OE_RAISE(OE_INVALID_PARAMETER);
    
    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (info == NULL)
        OE_RAISE(OE_CRYPTO_ERROR);


    /*OE_CHECK( mbedtls_cipher_setup(&ctx, info) ? OE_CRYPTO_ERROR : OE_OK );
    OE_CHECK( mbedtls_cipher_setkey(&ctx, key, sizeof(SGX_Key)*8, MBEDTLS_ENCRYPT ) ? OE_CRYPTO_ERROR : OE_OK );
    
    OE_CHECK( mbedtls_cipher_update(&ctx, src, len, mac->bytes, &outlen) ? OE_CRYPTO_ERROR : OE_OK);
    OE_CHECK( mbedtls_cipher_finish(&ctx, mac->bytes+outlen, &outlen) ? OE_CRYPTO_ERROR : OE_OK);
    OE_CHECK( outlen != sizeof(SGX_Key)*8 ? OE_CRYPTO_ERROR : OE_OK);*/
    mbedtls_cipher_cmac(info, key, keySize*8, src, len, mac->bytes);


done:
    //mbedtls_cipher_free(&ctx);

    return result;
}

// void dec_empty_buf()
// {
//     unsigned char key[32];
//     unsigned char iv[16];

//     mbedtls_cipher_context_t ctx_dec;
//     const mbedtls_cipher_info_t *cipher_info;

//     unsigned char encbuf[64];
//     unsigned char decbuf[64];

//     size_t outlen = 0;

//     memset( key, 0, 32 );
//     memset( iv , 0, 16 );

//     mbedtls_cipher_init( &ctx_dec );

//     memset( encbuf, 0, 64 );
//     memset( decbuf, 0, 64 );

//     /* Initialise context */
//     cipher_info = mbedtls_cipher_info_from_type( MBEDTLS_CIPHER_AES_128_CBC );
//     TEST_ASSERT( NULL != cipher_info);

//     TEST_ASSERT( 0 == mbedtls_cipher_setup( &ctx_dec, cipher_info ) );

//     TEST_ASSERT( 0 == mbedtls_cipher_setkey( &ctx_dec, key, 128, MBEDTLS_DECRYPT ) );

//     TEST_ASSERT( 0 == mbedtls_cipher_set_iv( &ctx_dec, iv, 16 ) );

//     TEST_ASSERT( 0 == mbedtls_cipher_reset( &ctx_dec ) );

// #if defined(MBEDTLS_GCM_C)
//     TEST_ASSERT( 0 == mbedtls_cipher_update_ad( &ctx_dec, NULL, 0 ) );
// #endif

//     /* decode 0-byte string */
//     TEST_ASSERT( 0 == mbedtls_cipher_update( &ctx_dec, encbuf, 0, decbuf, &outlen ) );
//     TEST_ASSERT( 0 == outlen );
//     TEST_ASSERT( MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED == mbedtls_cipher_finish(
//                  &ctx_dec, decbuf + outlen, &outlen ) );
//     TEST_ASSERT( 0 == outlen );

// exit:
//     mbedtls_cipher_free( &ctx_dec );
// }