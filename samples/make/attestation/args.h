#ifndef OE_SAMPLES_ATTESTATION_ARGS_H
#define OE_SAMPLES_ATTESTATION_ARGS_H

#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>

struct QuotedPublicKey
{
    uint8_t pemKey[512];
    uint8_t* quote;
    uint32_t quoteSize;
};

struct GetPublicKeyArgs
{
    QuotedPublicKey* quotedPublicKey; /* out */
    bool success;                     /* out */
};

struct StorePublicKeyArgs
{
    QuotedPublicKey* quotedPublicKey; /* in */
    bool success;                     /* out */
};

struct GenerateEncryptedDataArgs
{
    uint8_t* data; /* out */
    uint32_t size; /* out */
    bool success;  /* out */
};

struct ProcessEncryptedDataArgs
{
    const uint8_t* data; /* in */
    uint32_t size;       /* in */
    bool success;        /* out */
};

#endif // OE_SAMPLES_ATTESTATION_ARGS_H
