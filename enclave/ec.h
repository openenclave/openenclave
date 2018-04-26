#ifndef _OE_ENCLAVE_EC_H
#define _OE_ENCLAVE_EC_H

#include <mbedtls/pk.h>
#include <openenclave/bits/ec.h>
#include <openenclave/types.h>

/* Randomly generated magic number */
#define OE_EC_PUBLIC_KEY_MAGIC 0xd7490a56f6504ee6

typedef struct _OE_ECPublicKeyImpl
{
    uint64_t magic;
    mbedtls_pk_context pk;
} OE_ECPublicKeyImpl;

OE_STATIC_ASSERT(sizeof(OE_ECPublicKeyImpl) <= sizeof(OE_ECPublicKey));

int OE_ECCopyKey(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool clearPrivateFields);

#endif /* _OE_ENCLAVE_EC_H */
