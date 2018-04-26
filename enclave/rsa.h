#ifndef _OE_ENCLAVE_RSA_H
#define _OE_ENCLAVE_RSA_H

#include <mbedtls/pk.h>
#include <openenclave/bits/rsa.h>
#include <openenclave/types.h>

/* Randomly generated magic number */
#define OE_RSA_PUBLIC_KEY_MAGIC 0x713600af058c447a

typedef struct _OE_RSAPublicKeyImpl
{
    uint64_t magic;
    mbedtls_pk_context pk;
} OE_RSAPublicKeyImpl;

OE_STATIC_ASSERT(sizeof(OE_RSAPublicKeyImpl) <= sizeof(OE_RSAPublicKey));

int OE_RSACopyKey(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool clearPrivateFields);

#endif /* _OE_ENCLAVE_RSA_H */
